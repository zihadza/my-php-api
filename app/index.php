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
    if ($val !== false && $val !== '') return $val;
    return $_ENV[$key] ?? ($_SERVER[$key] ?? $default);
}

// 1. Security Check (Header: X-API-KEY athoba URL: ?key=...)
$expectedKey = envVal('API_SECRET', 'zihad-secret-key-2026');
$clientKey = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['key'] ?? '');

if ($clientKey !== $expectedKey) {
    http_response_code(401);
    header("Content-Type: application/json");
    echo json_encode(["status" => "error", "message" => "Unauthorized! Invalid API Key."]);
    exit;
}

// 2. MySQL Database Connection
$dbHost = envVal('DB_HOST');
$dbPort = envVal('DB_PORT', '3306');
$dbName = envVal('DB_NAME');
$dbUser = envVal('DB_USERNAME');
$dbPass = envVal('DB_PASSWORD');

try {
    $pdo = new PDO(
        "mysql:host=$dbHost;port=$dbPort;dbname=$dbName;charset=utf8mb4",
        $dbUser,
        $dbPass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    // Table 1: File Management
    $pdo->exec("CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        original_name VARCHAR(255) NOT NULL,
        saved_name VARCHAR(255) NOT NULL,
        file_size BIGINT NOT NULL,
        mime_type VARCHAR(100),
        folder VARCHAR(100) DEFAULT 'general',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");

    // Table 2: App Database Records (JSON data save/read korar jonno)
    $pdo->exec("CREATE TABLE IF NOT EXISTS app_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        collection VARCHAR(100) NOT NULL,
        item_key VARCHAR(150) NOT NULL,
        data_json LONGTEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_item (collection, item_key)
    )");
} catch (Exception $e) {
    http_response_code(500);
    header("Content-Type: application/json");
    echo json_encode(["status" => "error", "message" => "DB Connection Error: " . $e->getMessage()]);
    exit;
}

// 3. Persistent File Folder (/data volume)
$uploadDir = '/data/uploads';
if (!is_dir($uploadDir)) {
    @mkdir($uploadDir, 0777, true);
}

$action = $_GET['action'] ?? 'ping';

// --- HEALTH CHECK ---
if ($action === 'ping') {
    header("Content-Type: application/json");
    echo json_encode([
        "status" => "success",
        "message" => "Wasmer PHP API & MySQL Database Ready!",
        "storage_ready" => is_dir($uploadDir) && is_writable($uploadDir)
    ]);
    exit;
}

// ==========================================
// PART A: FILE MANAGEMENT SYSTEM
// ==========================================

// 1. Upload File (POST multipart/form-data: file, optional folder)
if ($action === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header("Content-Type: application/json");
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "No valid file uploaded."]);
        exit;
    }

    $file = $_FILES['file'];
    $originalName = basename($file['name']);
    $folder = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['folder'] ?? 'general') ?: 'general';
    $ext = pathinfo($originalName, PATHINFO_EXTENSION);
    $savedName = uniqid('file_', true) . ($ext ? '.' . $ext : '');
    $targetPath = $uploadDir . '/' . $savedName;

    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        $stmt = $pdo->prepare("INSERT INTO files (original_name, saved_name, file_size, mime_type, folder) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$originalName, $savedName, $file['size'], $file['type'], $folder]);
        $id = $pdo->lastInsertId();

        echo json_encode([
            "status" => "success",
            "id" => (int)$id,
            "name" => $originalName,
            "folder" => $folder,
            "size" => (int)$file['size']
        ]);
    } else {
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Failed to move uploaded file."]);
    }
    exit;
}

// 2. List Files (GET, optional &folder=...)
if ($action === 'list') {
    header("Content-Type: application/json");
    $folder = $_GET['folder'] ?? '';
    if ($folder !== '') {
        $stmt = $pdo->prepare("SELECT id, original_name, file_size, mime_type, folder, created_at FROM files WHERE folder = ? ORDER BY id DESC");
        $stmt->execute([$folder]);
    } else {
        $stmt = $pdo->query("SELECT id, original_name, file_size, mime_type, folder, created_at FROM files ORDER BY id DESC");
    }
    echo json_encode(["status" => "success", "files" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    exit;
}

// 3. Download File (GET &id=1)
if ($action === 'download' && isset($_GET['id'])) {
    $stmt = $pdo->prepare("SELECT * FROM files WHERE id = ?");
    $stmt->execute([(int)$_GET['id']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    $filePath = $row ? ($uploadDir . '/' . $row['saved_name']) : '';
    if (!$row || !file_exists($filePath)) {
        http_response_code(404);
        header("Content-Type: application/json");
        echo json_encode(["status" => "error", "message" => "File not found."]);
        exit;
    }

    if (ob_get_level()) ob_end_clean();
    header('Content-Type: ' . ($row['mime_type'] ?: 'application/octet-stream'));
    header('Content-Disposition: attachment; filename="' . $row['original_name'] . '"');
    header('Content-Length: ' . filesize($filePath));
    readfile($filePath);
    exit;
}

// 4. Delete File (GET/POST/DELETE &id=1)
if ($action === 'delete' && isset($_GET['id'])) {
    header("Content-Type: application/json");
    $stmt = $pdo->prepare("SELECT saved_name FROM files WHERE id = ?");
    $stmt->execute([(int)$_GET['id']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        $filePath = $uploadDir . '/' . $row['saved_name'];
        if (file_exists($filePath)) @unlink($filePath);
        $pdo->prepare("DELETE FROM files WHERE id = ?")->execute([(int)$_GET['id']]);
        echo json_encode(["status" => "success", "message" => "File deleted."]);
    } else {
        http_response_code(404);
        echo json_encode(["status" => "error", "message" => "File not found."]);
    }
    exit;
}

// ==========================================
// PART B: DATABASE JSON DATA MANAGEMENT
// ==========================================

// 5. Save or Update Data (POST JSON body: {"collection":"users","item_key":"u1","data":{"name":"Zihad"}})
if ($action === 'db_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header("Content-Type: application/json");
    $raw = file_get_contents('php://input');
    $input = json_decode($raw, true) ?: $_POST;

    $collection = trim($input['collection'] ?? '');
    $itemKey = trim($input['item_key'] ?? '');
    $data = $input['data'] ?? null;

    if ($collection === '' || $itemKey === '' || $data === null) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "collection, item_key, and data are required."]);
        exit;
    }

    $jsonStr = is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE);
    $stmt = $pdo->prepare("INSERT INTO app_data (collection, item_key, data_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE data_json = VALUES(data_json)");
    $stmt->execute([$collection, $itemKey, $jsonStr]);

    echo json_encode(["status" => "success", "collection" => $collection, "item_key" => $itemKey]);
    exit;
}

// 6. Get Data (GET ?action=db_get&collection=users&item_key=u1)
if ($action === 'db_get') {
    header("Content-Type: application/json");
    $collection = trim($_GET['collection'] ?? '');
    $itemKey = trim($_GET['item_key'] ?? '');

    if ($collection === '') {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "collection parameter is required."]);
        exit;
    }

    if ($itemKey !== '') {
        $stmt = $pdo->prepare("SELECT item_key, data_json, updated_at FROM app_data WHERE collection = ? AND item_key = ?");
        $stmt->execute([$collection, $itemKey]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Record not found."]);
            exit;
        }
        $row['data'] = json_decode($row['data_json'], true) ?? $row['data_json'];
        unset($row['data_json']);
        echo json_encode(["status" => "success", "item" => $row]);
    } else {
        $stmt = $pdo->prepare("SELECT item_key, data_json, updated_at FROM app_data WHERE collection = ? ORDER BY id DESC");
        $stmt->execute([$collection]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            $r['data'] = json_decode($r['data_json'], true) ?? $r['data_json'];
            unset($r['data_json']);
        }
        echo json_encode(["status" => "success", "items" => $rows]);
    }
    exit;
}

// 7. Delete Data (GET/POST ?action=db_delete&collection=users&item_key=u1)
if ($action === 'db_delete') {
    header("Content-Type: application/json");
    $collection = trim($_GET['collection'] ?? '');
    $itemKey = trim($_GET['item_key'] ?? '');
    if ($collection === '' || $itemKey === '') {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "collection and item_key are required."]);
        exit;
    }
    $stmt = $pdo->prepare("DELETE FROM app_data WHERE collection = ? AND item_key = ?");
    $stmt->execute([$collection, $itemKey]);
    echo json_encode(["status" => "success", "deleted" => $stmt->rowCount()]);
    exit;
}

http_response_code(404);
header("Content-Type: application/json");
echo json_encode(["status" => "error", "message" => "Unknown action."]);
