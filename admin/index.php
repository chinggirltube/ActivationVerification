<?php
require_once '../config.php';
session_start();

if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

$csrf_token = generateCSRFToken();

// 处理POST请求
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => '无效的CSRF令牌']);
        exit;
    }

    $action = $_POST['action'] ?? '';
    $code_id = $_POST['code_id'] ?? '';

    switch ($action) {
        case 'generate_code':
            try {
                $activation_code = bin2hex(random_bytes(32));
                $expiration_date = date('Y-m-d H:i:s', strtotime('+30 days'));

                $stmt = $pdo->prepare("INSERT INTO activation_codes (code, expiration_date) VALUES (?, ?)");
                $result = $stmt->execute([$activation_code, $expiration_date]);

                if ($result) {
                    $new_id = $pdo->lastInsertId();
                    echo json_encode(['success' => true, 'message' => '激活码生成成功', 'activation_code' => $activation_code, 'id' => $new_id]);
                } else {
                    echo json_encode(['success' => false, 'message' => '生成激活码时发生数据库错误']);
                }
            } catch (Exception $e) {
                error_log("生成激活码时发生错误: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => '生成激活码时发生错误']);
            }
            break;

        case 'update_expiration':
            if (empty($code_id) || empty($_POST['new_expiration'])) {
                echo json_encode(['success' => false, 'message' => '无效的请求']);
                exit;
            }
            try {
                $stmt = $pdo->prepare("UPDATE activation_codes SET expiration_date = ? WHERE id = ?");
                $result = $stmt->execute([$_POST['new_expiration'], $code_id]);
                echo json_encode(['success' => $result, 'message' => $result ? '过期时间已成功更新' : '更新过期时间失败']);
            } catch (Exception $e) {
                error_log("更新过期时间时发生错误: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => '更新过期时间时发生错误']);
            }
            break;

        case 'unbind':
            if (empty($code_id)) {
                echo json_encode(['success' => false, 'message' => '无效的请求']);
                exit;
            }
            try {
                $stmt = $pdo->prepare("UPDATE activation_codes SET is_used = FALSE, bound_ip = NULL, activated_at = NULL WHERE id = ?");
                $result = $stmt->execute([$code_id]);
                echo json_encode(['success' => $result, 'message' => $result ? '激活码已成功解绑' : '解绑激活码失败']);
            } catch (Exception $e) {
                error_log("解绑激活码时发生错误: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => '解绑激活码时发生错误']);
            }
            break;

        case 'delete':
            if (empty($code_id)) {
                echo json_encode(['success' => false, 'message' => '无效的请求']);
                exit;
            }
            try {
                $stmt = $pdo->prepare("DELETE FROM activation_codes WHERE id = ?");
                $result = $stmt->execute([$code_id]);
                echo json_encode(['success' => $result, 'message' => $result ? '激活码已成功删除' : '删除激活码失败']);
            } catch (Exception $e) {
                error_log("删除激活码时发生错误: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => '删除激活码时发生错误']);
            }
            break;

        default:
            echo json_encode(['success' => false, 'message' => '无效的操作']);
            break;
    }
    exit;
}

// 获取激活码列表
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$per_page = 20;
$offset = ($page - 1) * $per_page;

try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM activation_codes");
    $stmt->execute();
    $total_codes = $stmt->fetchColumn();

    $total_pages = ceil($total_codes / $per_page);

    $stmt = $pdo->prepare("SELECT * FROM activation_codes ORDER BY created_at DESC LIMIT ? OFFSET ?");
    $stmt->execute([$per_page, $offset]);
    $codes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("获取激活码列表时发生错误: " . $e->getMessage());
    $error_message = "获取激活码时发生错误";
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>激活码管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/boxicons@2.0.7/css/boxicons.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .navbar { background-color: #343a40; }
        .card { box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .table { background-color: #fff; }
        .btn-icon { padding: 0.25rem 0.5rem; font-size: 1.25rem; line-height: 1; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="#">激活码管理系统</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="logout.php">退出登录</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container">
        <div id="message"></div>

        <div class="card mb-4">
            <div class="card-body">
                <h5 class="card-title">生成新激活码</h5>
                <button id="generateCodeBtn" class="btn btn-primary">生成激活码</button>
            </div>
        </div>
        
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">现有激活码</h5>
                <div class="table-responsive">
                    <table id="activation-codes-table" class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>激活码</th>
                                <th>已使用</th>
                                <th>绑定IP</th>
                                <th>创建时间</th>
                                <th>激活时间</th>
                                <th>过期时间</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($codes as $code): ?>
                            <tr>
                                <td><?= htmlspecialchars($code['code']) ?></td>
                                <td><?= $code['is_used'] ? '是' : '否' ?></td>
                                <td><?= htmlspecialchars($code['bound_ip'] ?? '未绑定') ?></td>
                                <td><?= htmlspecialchars($code['created_at']) ?></td>
                                <td><?= htmlspecialchars($code['activated_at'] ?? '未激活') ?></td>
                                <td><?= htmlspecialchars($code['expiration_date']) ?></td>
                                <td>
                                    <div class="btn-group" role="group">
                                        <button type="button" class="btn btn-warning btn-sm btn-icon updateExpirationBtn" data-bs-toggle="modal" data-bs-target="#updateModal<?= $code['id'] ?>">
                                            <i class='bx bx-calendar'></i>
                                        </button>
                                        <?php if ($code['is_used']): ?>
                                        <button type="button" class="btn btn-info btn-sm btn-icon unbindBtn" data-code-id="<?= $code['id'] ?>">
                                            <i class='bx bx-unlink'></i>
                                        </button>
                                        <?php endif; ?>
                                        <button type="button" class="btn btn-danger btn-sm btn-icon deleteBtn" data-code-id="<?= $code['id'] ?>">
                                            <i class='bx bx-trash'></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <nav>
                    <ul class="pagination justify-content-center">
                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?>"><?= $i ?></a>
                            </li>
                        <?php endfor; ?>
                    </ul>
                </nav>
            </div>
        </div>
    </div>

    <?php foreach ($codes as $code): ?>
    <div class="modal fade" id="updateModal<?= $code['id'] ?>" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">更新过期时间</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="date" id="newExpirationDate<?= $code['id'] ?>" class="form-control" required>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary updateExpirationConfirmBtn" data-code-id="<?= $code['id'] ?>">更新</button>
                </div>
            </div>
        </div>
    </div>
    <?php endforeach; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const csrfToken = '<?= $csrf_token ?>';

        function showMessage(message, isError = false) {
            const messageDiv = document.getElementById('message');
            messageDiv.innerHTML = `<div class="alert alert-${isError ? 'danger' : 'success'} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>`;
        }

        async function sendRequest(action, data = {}) {
            const formData = new FormData();
            formData.append('csrf_token', csrfToken);
            formData.append('action', action);
            for (const [key, value] of Object.entries(data)) {
                formData.append(key, value);
            }

            try {
                const response = await fetch('index.php', {
                    method: 'POST',
                    body: formData
                });
                return await response.json();
            } catch (error) {
                console.error('Error:', error);
                showMessage('发生错误，请稍后再试', true);
            }
        }

        document.getElementById('generateCodeBtn').addEventListener('click', async () => {
            const result = await sendRequest('generate_code');
            if (result.success) {
                showMessage(result.message);
                location.reload();
            } else {
                showMessage(result.message, true);
            }
        });

        document.querySelectorAll('.updateExpirationConfirmBtn').forEach(button => {
            button.addEventListener('click', async function() {
                const codeId = this.dataset.codeId;
                const newExpirationDate = document.getElementById(`newExpirationDate${codeId}`).value;
                const result = await sendRequest('update_expiration', { code_id: codeId, new_expiration: newExpirationDate });
                if (result.success) {
                    showMessage(result.message);
                    location.reload();
                } else {
                    showMessage(result.message, true);
                }
            });
        });

        document.querySelectorAll('.unbindBtn').forEach(button => {
            button.addEventListener('click', async function() {
                if (confirm('确定要解绑此激活码吗？')) {
                    const result = await sendRequest('unbind', { code_id: this.dataset.codeId });
                    if (result.success) {
                        showMessage(result.message);
                        location.reload();
                    } else {
                        showMessage(result.message, true);
                    }
                }
            });
        });

        document.querySelectorAll('.deleteBtn').forEach(button => {
            button.addEventListener('click', async function() {
                if (confirm('确定要删除此激活码吗？')) {
                    const result = await sendRequest('delete', { code_id: this.dataset.codeId });
                    if (result.success) {
                        showMessage(result.message);
                        location.reload();
                    } else {
                        showMessage(result.message, true);
                    }
                }
            });
        });
    </script>
</body>
</html>