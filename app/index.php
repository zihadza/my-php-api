<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, X-API-KEY");

// 1. API Key Check
$expectedKey = getenv('API_SECRET') ?: 'amar-secret-key-12345';
$clientKey = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['key'] ?? '');

if ($clientKey !== $expectedKey) {
    http_response_code(401);
    header("Content-Type: application/json");
    echo json_encode(["status" => "error", "message" => "Unauthorized!"]);
    exit;
}

// 2. MySQL Database Connection (Wasmer automatic inject kore dey)
$dbHost = getenv('DB_HOST');
$dbPort = getenv('DB_PORT') ?: '3306';
$dbName = getenv('DB_NAME');
$dbUser = getenv('DB_USERNAME');
$dbPass = getenv('DB_PASSWORD');

try {
    $pdo = new PDO(
        "mysql:host=$dbHost;port=$dbPort;dbname=$dbName;charset=utf8mb4",
        $dbUser,
        $dbPass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    $pdo->exec("CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        original_name VARCHAR(255) NOT NULL,
        saved_name VARCHAR(255) NOT NULL,
        file_size BIGINT NOT NULL,
        mime_type VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
} catch (Exception $e) {
    http_response_code(500);
    header("Content-Type: application/json");
    echo json_encode(["status" => "error", "message" => "DB Error: " . $e->getMessage()]);
    exit;
}

$uploadDir = '/data/uploads';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

$action = $_GET['action'] ?? 'list';

// UPLOAD (POST)
if ($action === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header("Content-Type: application/json");
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "No valid file uploaded."]);
        exit;
    }
    $file = $_FILES['file'];
    $originalName = basename($file['name']);
    $ext = pathinfo($originalName, PATHINFO_EXTENSION);
    $savedName = uniqid('file_', true) . ($ext ? '.' . $ext : '');
    $targetPath = $uploadDir . '/' . $savedName;

    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        $stmt = $pdo->prepare("INSERT INTO files (original_name, saved_name, file_size, mime_type) VALUES (?, ?, ?, ?)");
        $stmt->execute([$originalName, $savedName, $file['size'], $file['type']]);
        echo json_encode(["status" => "success", "id" => $pdo->lastInsertId(), "name" => $originalName]);
    } else {
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Failed to save file."]);
    }
    exit;
}

// LIST (GET)
if ($action === 'list') {
    header("Content-Type: application/json");
    $stmt = $pdo->query("SELECT id, original_name, file_size, mime_type, created_at FROM files ORDER BY id DESC");
    echo json_encode(["status" => "success", "files" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    exit;
}

// DOWNLOAD (GET)
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
    header('Content-Type: ' . ($row['mime_type'] ?: 'application/octet-stream'));
    header('Content-Disposition: attachment; filename="' . $row['original_name'] . '"');
    header('Content-Length: ' . filesize($filePath));
    readfile($filePath);
    exit;
}

// DELETE (GET/POST)
if ($action === 'delete' && isset($_GET['id'])) {
    header("Content-Type: application/json");
    $stmt = $pdo->prepare("SELECT saved_name FROM files WHERE id = ?");
    $stmt->execute([(int)$_GET['id']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        $filePath = $uploadDir . '/' . $row['saved_name'];
        if (file_exists($filePath)) unlink($filePath);
        $pdo->prepare("DELETE FROM files WHERE id = ?")->execute([(int)$_GET['id']]);
        echo json_encode(["status" => "success", "message" => "File deleted."]);
    } else {
        http_response_code(404);
        echo json_encode(["status" => "error", "message" => "File not found."]);
    }
    exit;
}
