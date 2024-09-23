<?php
// 错误报告（在生产环境中禁用）
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/path/to/error.log');

// 数据库配置
$db_host = 'localhost';
$db_name = 'jh';
$db_user = 'root';
$db_pass = 'd1c788e851afd5bc';

// 建立数据库连接
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
} catch (PDOException $e) {
    error_log("数据库连接失败: " . $e->getMessage());
    die("发生数据库错误。请稍后再试。");
}

// 使用数据库进行速率限制的函数
function rateLimitCheck($ip, $limit = 10, $period = 60) {
    global $pdo;
    $now = time();
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM rate_limits WHERE ip = ? AND timestamp > ?");
    $stmt->execute([$ip, $now - $period]);
    $count = $stmt->fetchColumn();

    if ($count >= $limit) {
        return false;
    }

    $stmt = $pdo->prepare("INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)");
    $stmt->execute([$ip, $now]);
    return true;
}

// 使用预处理语句的日志记录函数
function logActivationAttempt($code, $ip, $code_id, $success) {
    global $pdo;
    $stmt = $pdo->prepare("INSERT INTO activation_logs (activation_code, ip_address, code_id, success) VALUES (?, ?, ?, ?)");
    $stmt->execute([$code, $ip, $code_id, $success]);
}

// 设置初始管理员账户的函数
function setupAdminAccount($username, $password) {
    global $pdo;
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM admins");
    $stmt->execute();
    $count = $stmt->fetchColumn();

    if ($count == 0) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)");
        $stmt->execute([$username, $password_hash]);
        echo "管理员账户创建成功。\n";
    } else {
        echo "管理员账户已存在。此函数仅用于初始设置。\n";
    }
}

// 取消注释并运行一次以设置管理员账户，然后再次注释掉
// setupAdminAccount('admin', 'your_secure_password');

// CSRF 令牌生成和验证
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}