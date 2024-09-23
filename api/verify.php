<?php
header('Content-Type: application/json');
require_once '../config.php';

// 速率限制
if (!rateLimitCheck($_SERVER['REMOTE_ADDR'])) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => '请求过于频繁，请稍后再试。']);
    exit;
}

$activation_code = $_POST['activation_code'] ?? '';
$ip_address = $_SERVER['REMOTE_ADDR'];

if (empty($activation_code) || strlen($activation_code) !== 64) {
    logActivationAttempt($activation_code, $ip_address, null, false);
    echo json_encode(['success' => false, 'message' => '无效的激活码格式']);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT * FROM activation_codes WHERE code = ? AND expiration_date > CURRENT_TIMESTAMP");
    $stmt->execute([$activation_code]);
    $code = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$code) {
        logActivationAttempt($activation_code, $ip_address, null, false);
        echo json_encode(['success' => false, 'message' => '无效或已过期的激活码']);
        exit;
    }

    if ($code['is_used']) {
        if ($code['bound_ip'] === $ip_address) {
            logActivationAttempt($activation_code, $ip_address, $code['id'], true);
            echo json_encode(['success' => true, 'message' => '激活码对此IP有效']);
        } else {
            logActivationAttempt($activation_code, $ip_address, $code['id'], false);
            echo json_encode(['success' => false, 'message' => '激活码已被其他IP使用']);
        }
    } else {
        $stmt = $pdo->prepare("UPDATE activation_codes SET is_used = TRUE, bound_ip = ?, activated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$ip_address, $code['id']]);
        logActivationAttempt($activation_code, $ip_address, $code['id'], true);
        echo json_encode(['success' => true, 'message' => '激活成功']);
    }
} catch (PDOException $e) {
    error_log("验证过程中发生数据库错误: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => '发生错误，请稍后再试']);
}