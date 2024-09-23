<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: text/plain');
require_once '../config.php';

session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    echo "ERROR: 未授权访问";
    exit;
}

if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
    echo "ERROR: CSRF 令牌无效";
    exit;
}

try {
    $activation_code = bin2hex(random_bytes(32));
    $expiration_date = date('Y-m-d H:i:s', strtotime('+30 days'));

    $stmt = $pdo->prepare("INSERT INTO activation_codes (code, expiration_date) VALUES (?, ?)");
    $result = $stmt->execute([$activation_code, $expiration_date]);

    if ($result) {
        $new_id = $pdo->lastInsertId();
        echo "SUCCESS: $activation_code|$new_id";
    } else {
        $errorInfo = $stmt->errorInfo();
        error_log("SQL错误: " . $errorInfo[2]);
        echo "ERROR: 生成激活码时发生数据库错误";
    }
} catch (PDOException $e) {
    error_log("PDO异常: " . $e->getMessage());
    echo "ERROR: 生成激活码时发生数据库错误: " . $e->getMessage();
} catch (Exception $e) {
    error_log("生成激活码时发生错误: " . $e->getMessage());
    echo "ERROR: 生成激活码时发生错误: " . $e->getMessage();
}