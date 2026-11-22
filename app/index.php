<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-API-KEY");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

function envVal($key, $default = '') {
    $val = getenv($key);
    if ($val !== false && trim($val) !== '') return trim($val);
    $alt = $_ENV[$key] ?? ($_SERVER[$key] ?? $default);
    return is_string($alt) ? trim($alt) : $default;
}

// 1. App Security Check
$expectedKey = envVal('API_SECRET', 'zihad-secret-key-2026');
$clientKey = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['key'] ?? '');

if ($clientKey !== $expectedKey) {
    http_response_code(401);
    header("Content-Type: application/json");
    echo json_encode(["status" => "error", "message" => "Unauthorized! Invalid API Key."]);
    exit;
}

// 2. Tigris S3 Credentials (Wasmer Environment Variables theke asbe)
$tigrisBucket = envVal('TIGRIS_BUCKET');
$tigrisKey    = envVal('TIGRIS_ACCESS_KEY');
$tigrisSecret = envVal('TIGRIS_SECRET_KEY');
$tigrisRegion = 'auto';
$tigrisHost   = $tigrisBucket ? "$tigrisBucket.t3.storage.dev" : '';

// ==================================================
// PURE PHP AWS SIGV4 SIGNER FOR TIGRIS S3
// ==================================================
function s3SigningKey($secret, $dateStamp, $region, $service) {
    $kDate    = hash_hmac('sha256', $dateStamp, 'AWS4' . $secret, true);
    $kRegion  = hash_hmac('sha256', $region, $kDate, true);
    $kService = hash_hmac('sha256', $service, $kRegion, true);
    return hash_hmac('sha256', 'aws4_request', $kService, true);
}

function s3EncodePath($objectKey) {
    $key = ltrim($objectKey, '/');
    if ($key === '') return '/';
    return '/' . implode('/', array_map('rawurlencode', explode('/', $key)));
}

function tigrisRequest($method, $objectKey, $query = [], $body = '', $contentType = '') {
    global $tigrisHost, $tigrisKey, $tigrisSecret, $tigrisRegion;
    if (!$tigrisHost || !$tigrisKey || !$tigrisSecret) {
        return [500, '{"error":"Tigris credentials missing in Wasmer Environment Variables"}', ''];
    }

    $amzDate      = gmdate('Ymd\THis\Z');
    $dateStamp    = gmdate('Ymd');
    $payloadHash  = hash('sha256', $body);
    $canonicalUri = s3EncodePath($objectKey);

    ksort($query);
    $canonicalQuery = http_build_query($query, '', '&', PHP_QUERY_RFC3986);

    $canonicalHeaders = "host:$tigrisHost\nx-amz-content-sha256:$payloadHash\nx-amz-date:$amzDate\n";
    $signedHeaders    = "host;x-amz-content-sha256;x-amz-date";

    $canonicalRequest = "$method\n$canonicalUri\n$canonicalQuery\n$canonicalHeaders\n$signedHeaders\n$payloadHash";
    $scope        = "$dateStamp/$tigrisRegion/s3/aws4_request";
    $stringToSign = "AWS4-HMAC-SHA256\n$amzDate\n$scope\n" . hash('sha256', $canonicalRequest);

    $signingKey = s3SigningKey($tigrisSecret, $dateStamp, $tigrisRegion, 's3');
    $signature  = hash_hmac('sha256', $stringToSign, $signingKey);

    $authHeader = "AWS4-HMAC-SHA256 Credential=$tigrisKey/$scope, SignedHeaders=$signedHeaders, Signature=$signature";
    $url = "https://$tigrisHost$canonicalUri" . ($canonicalQuery ? "?$canonicalQuery" : "");

    $headers = [
        "Host: $tigrisHost",
        "X-Amz-Content-Sha256: $payloadHash",
        "X-Amz-Date: $amzDate",
        "Authorization: $authHeader"
    ];
    if ($contentType !== '') $headers[] = "Content-Type: $contentType";

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    if ($method === 'PUT') {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }

    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    return [$code, $resp, $err];
}

function tigrisPresignedUrl($method, $objectKey, $expires = 300) {
    global $tigrisHost, $tigrisKey, $tigrisSecret, $tigrisRegion;
    $amzDate      = gmdate('Ymd\THis\Z');
    $dateStamp    = gmdate('Ymd');
    $scope        = "$dateStamp/$tigrisRegion/s3/aws4_request";
    $canonicalUri = s3EncodePath($objectKey);

    $query = [
        'X-Amz-Algorithm'     => 'AWS4-HMAC-SHA256',
        'X-Amz-Credential'    => "$tigrisKey/$scope",
        'X-Amz-Date'          => $amzDate,
        'X-Amz-Expires'       => (string)$expires,
        'X-Amz-SignedHeaders' => 'host'
    ];
    ksort($query);
    $canonicalQuery = http_build_query($query, '', '&', PHP_QUERY_RFC3986);

    $canonicalRequest = "$method\n$canonicalUri\nhost:$tigrisHost\n\nhost\nUNSIGNED-PAYLOAD";
    $stringToSign = "AWS4-HMAC-SHA256\n$amzDate\n$scope\n" . hash('sha256', $canonicalRequest);
    $signingKey = s3SigningKey($tigrisSecret, $dateStamp, $tigrisRegion, 's3');
    $signature  = hash_hmac('sha256', $stringToSign, $signingKey);

    return "https://$tigrisHost$canonicalUri?$canonicalQuery&X-Amz-Signature=$signature";
}

function getPdo() {
    $pdo = new PDO(
        "mysql:host=" . envVal('DB_HOST') . ";port=" . envVal('DB_PORT', '3306') . ";dbname=" . envVal('DB_NAME') . ";charset=utf8mb4",
        envVal('DB_USERNAME'),
        envVal('DB_PASSWORD'),
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    $pdo->exec("CREATE TABLE IF NOT EXISTS app_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        collection VARCHAR(100) NOT NULL,
        item_key VARCHAR(150) NOT NULL,
        data_json LONGTEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_item (collection, item_key)
    )");
    return $pdo;
}

function cleanPath($p) {
    $p = preg_replace('/[^a-zA-Z0-9_\-\.\/]/', '', $p);
    return ltrim(str_replace('..', '', $p), '/');
}

$action = $_GET['action'] ?? 'ping';

// --- 1. HEALTH CHECK ---
if ($action === 'ping') {
    header("Content-Type: application/json");
    echo json_encode([
        "status" => "success",
        "message" => "Wasmer + Tigris S3 + MySQL Bridge Ready!",
        "tigris_configured" => ($tigrisBucket !== '' && $tigrisKey !== '' && $tigrisSecret !== '')
    ]);
    exit;
}

// ==================================================
// PART A: TIGRIS 5GB FILE STORAGE
// ==================================================

// Zero-CPU Presigned Upload URL
if ($action === 'get_upload_url') {
    header("Content-Type: application/json");
    if (!$tigrisHost) {
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Tigris not configured."]);
        exit;
    }
    $folder = cleanPath($_GET['folder'] ?? 'general') ?: 'general';
    $name   = cleanPath(basename($_GET['filename'] ?? 'file.bin')) ?: 'file.bin';
    $key    = "uploads/$folder/" . time() . "_$name";
    echo json_encode([
        "status" => "success",
        "object_key" => $key,
        "upload_url" => tigrisPresignedUrl('PUT', $key, 300),
        "method" => "PUT",
        "expires_in_seconds" => 300
    ]);
    exit;
}

// Zero-CPU Presigned Download URL
if ($action === 'get_download_url' && isset($_GET['path'])) {
    header("Content-Type: application/json");
    if (!$tigrisHost) {
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Tigris not configured."]);
        exit;
    }
    $key = cleanPath($_GET['path']);
    echo json_encode([
        "status" => "success",
        "download_url" => tigrisPresignedUrl('GET', $key, 3600),
        "expires_in_seconds" => 3600
    ]);
    exit;
}

// Direct Upload via Wasmer (POST multipart: file)
if ($action === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header("Content-Type: application/json");
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "No valid file uploaded."]);
        exit;
    }
    $file   = $_FILES['file'];
    $folder = cleanPath($_POST['folder'] ?? 'general') ?: 'general';
    $name   = cleanPath(basename($file['name']));
    $key    = "uploads/$folder/" . time() . "_$name";
    $bytes  = file_get_contents($file['tmp_name']);
    $mime   = $file['type'] ?: 'application/octet-stream';

    list($code, $resp, $err) = tigrisRequest('PUT', $key, [], $bytes, $mime);
    if ($code === 200) {
        echo json_encode(["status" => "success", "path" => $key, "size" => $file['size']]);
    } else {
        http_response_code($code ?: 500);
        echo json_encode(["status" => "error", "tigris_code" => $code, "details" => $resp ?: $err]);
    }
    exit;
}

// List Files from Tigris
if ($action === 'list') {
    header("Content-Type: application/json");
    $folder = cleanPath($_GET['folder'] ?? '');
    $prefix = $folder ? "uploads/$folder/" : "uploads/";
    list($code, $xmlStr, $err) = tigrisRequest('GET', '', ['list-type' => '2', 'prefix' => $prefix]);

    if ($code !== 200) {
        http_response_code($code ?: 500);
        echo json_encode(["status" => "error", "tigris_code" => $code, "details" => $xmlStr ?: $err]);
        exit;
    }
    $xml = @simplexml_load_string($xmlStr);
    $files = [];
    if ($xml && isset($xml->Contents)) {
        foreach ($xml->Contents as $item) {
            $files[] = [
                "path" => (string)$item->Key,
                "name" => basename((string)$item->Key),
                "size" => (int)$item->Size,
                "last_modified" => (string)$item->LastModified
            ];
        }
    }
    echo json_encode(["status" => "success", "files" => $files]);
    exit;
}

// Direct Download via Wasmer
if ($action === 'download' && isset($_GET['path'])) {
    $key = cleanPath($_GET['path']);
    list($code, $bytes) = tigrisRequest('GET', $key);
    if ($code !== 200) {
        http_response_code(404);
        header("Content-Type: application/json");
        echo json_encode(["status" => "error", "message" => "File not found in Tigris."]);
        exit;
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($key) . '"');
    header('Content-Length: ' . strlen($bytes));
    echo $bytes;
    exit;
}

// Delete File from Tigris
if ($action === 'delete' && isset($_GET['path'])) {
    header("Content-Type: application/json");
    $key = cleanPath($_GET['path']);
    list($code) = tigrisRequest('DELETE', $key);
    echo json_encode(["status" => ($code === 204 || $code === 200) ? "success" : "error", "tigris_code" => $code]);
    exit;
}

// ==================================================
// PART B: MYSQL DATABASE MANAGEMENT
// ==================================================
if ($action === 'db_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header("Content-Type: application/json");
    $input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $col = trim($input['collection'] ?? '');
    $key = trim($input['item_key'] ?? '');
    $data = $input['data'] ?? null;
    if (!$col || !$key || $data === null) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "collection, item_key, and data required."]);
        exit;
    }
    $pdo = getPdo();
    $jsonStr = is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE);
    $stmt = $pdo->prepare("INSERT INTO app_data (collection, item_key, data_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE data_json = VALUES(data_json)");
    $stmt->execute([$col, $key, $jsonStr]);
    echo json_encode(["status" => "success", "collection" => $col, "item_key" => $key]);
    exit;
}

if ($action === 'db_get') {
    header("Content-Type: application/json");
    $col = trim($_GET['collection'] ?? '');
    $key = trim($_GET['item_key'] ?? '');
    if (!$col) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "collection required."]);
        exit;
    }
    $pdo = getPdo();
    if ($key) {
        $stmt = $pdo->prepare("SELECT item_key, data_json, updated_at FROM app_data WHERE collection = ? AND item_key = ?");
        $stmt->execute([$col, $key]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Not found."]);
            exit;
        }
        $row['data'] = json_decode($row['data_json'], true) ?? $row['data_json'];
        unset($row['data_json']);
        echo json_encode(["status" => "success", "item" => $row]);
    } else {
        $stmt = $pdo->prepare("SELECT item_key, data_json, updated_at FROM app_data WHERE collection = ? ORDER BY id DESC");
        $stmt->execute([$col]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            $r['data'] = json_decode($r['data_json'], true) ?? $r['data_json'];
            unset($r['data_json']);
        }
        echo json_encode(["status" => "success", "items" => $rows]);
    }
    exit;
}

if ($action === 'db_delete') {
    header("Content-Type: application/json");
    $col = trim($_GET['collection'] ?? '');
    $key = trim($_GET['item_key'] ?? '');
    $pdo = getPdo();
    $stmt = $pdo->prepare("DELETE FROM app_data WHERE collection = ? AND item_key = ?");
    $stmt->execute([$col, $key]);
    echo json_encode(["status" => "success", "deleted" => $stmt->rowCount()]);
    exit;
}

http_response_code(404);
header("Content-Type: application/json");
echo json_encode(["status" => "error", "message" => "Unknown action."]);
