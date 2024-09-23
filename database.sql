-- 创建激活码表
CREATE TABLE IF NOT EXISTS activation_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) UNIQUE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    bound_ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP NULL,
    expiration_date TIMESTAMP NULL
);

-- 创建管理员表
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    last_login TIMESTAMP NULL
);

-- 创建激活日志表
CREATE TABLE IF NOT EXISTS activation_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    activation_code VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    code_id INT,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL
);

-- 创建速率限制表
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    timestamp INT NOT NULL
);

-- 创建索引
CREATE INDEX idx_activation_code ON activation_codes(code);
CREATE INDEX idx_activation_logs_code ON activation_logs(activation_code);
CREATE INDEX idx_activation_logs_ip ON activation_logs(ip_address);
CREATE INDEX idx_rate_limits_ip_timestamp ON rate_limits(ip, timestamp);