<?php
require_once '../config.php';
session_start();

if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

$csrf_token = generateCSRFToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "无效的请求";
    } else {
        $action = $_POST['action'] ?? '';

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
                        $errorInfo = $stmt->errorInfo();
                        error_log("SQL错误: " . $errorInfo[2]);
                        echo json_encode(['success' => false, 'message' => '生成激活码时发生数据库错误']);
                    }
                } catch (PDOException $e) {
                    error_log("PDO异常: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => '生成激活码时发生数据库错误: ' . $e->getMessage()]);
                } catch (Exception $e) {
                    error_log("生成激活码时发生错误: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => '生成激活码时发生错误: ' . $e->getMessage()]);
                }
                break;

            case 'update_expiration':
                $code_id = $_POST['code_id'] ?? '';
                $new_expiration_date = $_POST['new_expiration_date'] ?? '';

                if (empty($code_id) || empty($new_expiration_date)) {
                    echo json_encode(['success' => false, 'message' => '无效的请求']);
                } else {
                    try {
                        $stmt = $pdo->prepare("UPDATE activation_codes SET expiration_date = ? WHERE id = ?");
                        $result = $stmt->execute([$new_expiration_date, $code_id]);

                        if ($result) {
                            echo json_encode(['success' => true, 'message' => '过期时间更新成功']);
                        } else {
                            $errorInfo = $stmt->errorInfo();
                            error_log("SQL错误: " . $errorInfo[2]);
                            echo json_encode(['success' => false, 'message' => '更新过期时间时发生数据库错误']);
                        }
                    } catch (PDOException $e) {
                        error_log("PDO异常: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => '更新过期时间时发生数据库错误: ' . $e->getMessage()]);
                    } catch (Exception $e) {
                        error_log("更新过期时间时发生错误: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => '更新过期时间时发生错误: ' . $e->getMessage()]);
                    }
                }
                break;

            case 'unbind':
                $code_id = $_POST['code_id'] ?? '';

                if (empty($code_id)) {
                    echo json_encode(['success' => false, 'message' => '无效的请求']);
                } else {
                    try {
                        $stmt = $pdo->prepare("UPDATE activation_codes SET is_used = FALSE, bound_ip = NULL WHERE id = ?");
                        $result = $stmt->execute([$code_id]);

                        if ($result) {
                            echo json_encode(['success' => true, 'message' => '解绑成功']);
                        } else {
                            $errorInfo = $stmt->errorInfo();
                            error_log("SQL错误: " . $errorInfo[2]);
                            echo json_encode(['success' => false, 'message' => '解绑时发生数据库错误']);
                        }
                    } catch (PDOException $e) {
                        error_log("PDO异常: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => '解绑时发生数据库错误: ' . $e->getMessage()]);
                    } catch (Exception $e) {
                        error_log("解绑时发生错误: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => '解绑时发生错误: ' . $e->getMessage()]);
                    }
                }
                break;

            case 'delete':
                $code_id = $_POST['code_id'] ?? '';

                if (empty($code_id)) {
                    echo json_encode(['success' => false, 'message' => '无效的请求']);
                } else {
                    try {
                        $stmt = $pdo->prepare("DELETE FROM activation_codes WHERE id = ?");
                        $result = $stmt->execute([$code_id]);

                        if ($result) {
                            echo json_encode(['success' => true, 'message' => '删除成功']);
                        } else {
                            $errorInfo = $stmt->errorInfo();
                            error_log("SQL错误: " . $errorInfo[2]);
                            echo json_encode(['success' => false, 'message' => '删除时发生数据库错误']);
                        }
                    } catch (PDOException $e) {
                        error_log("PDO异常: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => '删除时发生数据库错误: ' . $e->getMessage()]);
                    } catch (Exception $e) {
                        error_log("删除时发生错误: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => '删除时发生错误: ' . $e->getMessage()]);
                    }
                }
                break;

            default:
                echo json_encode(['success' => false, 'message' => '无效的请求']);
                break;
        }
    }
    exit;
}

$page = isset($_GET['page']) ? intval($_GET['page']) : 1;
$limit = 10;
$offset = ($page - 1) * $limit;

$stmt = $pdo->prepare("SELECT * FROM activation_codes ORDER BY created_at DESC LIMIT ? OFFSET ?");
$stmt->execute([$limit, $offset]);
$activation_codes = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT COUNT(*) FROM activation_codes");
$stmt->execute();
$total_codes = $stmt->fetchColumn();
$total_pages = ceil($total_codes / $limit);
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理员后台</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/boxicons@2.1.4/css/boxicons.min.css" rel="stylesheet">
    <style>
        body {
            padding-top: 20px;
            padding-bottom: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 960px;
        }
        .card {
            margin-bottom: 20px;
        }
        .table {
            margin-bottom: 0;
        }
        .pagination {
            justify-content: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">管理员后台</h3>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <button type="button" class="btn btn-primary" id="generateCodeBtn">生成激活码</button>
                </div>
                <div id="message" class="mb-3"></div>
                <table class="table table-bordered table-striped">
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
                        <?php foreach ($activation_codes as $code): ?>
                            <tr>
                                <td><?= htmlspecialchars($code['code']) ?></td>
                                <td><?= $code['is_used'] ? '是' : '否' ?></td>
                                <td><?= htmlspecialchars($code['bound_ip'] ?? '未绑定') ?></td>
                                <td><?= htmlspecialchars($code['created_at']) ?></td>
                                <td><?= htmlspecialchars($code['activated_at'] ?? '未激活') ?></td>
                                <td><?= htmlspecialchars($code['expiration_date']) ?></td>
                                <td>
                                    <button type="button" class="btn btn-sm btn-secondary" data-bs-toggle="modal" data-bs-target="#expirationModal<?= $code['id'] ?>">
                                        <i class="bx bx-calendar"></i> 更新过期时间
                                    </button>
                                    <?php if ($code['is_used']): ?>
                                        <button type="button" class="btn btn-sm btn-warning unbindBtn" data-code-id="<?= $code['id'] ?>">
                                            <i class="bx bx-link-alt"></i> 解绑
                                        </button>
                                    <?php endif; ?>
                                    <button type="button" class="btn btn-sm btn-danger deleteBtn" data-code-id="<?= $code['id'] ?>">
                                        <i class="bx bx-trash"></i> 删除
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <div class="card-footer">
                <nav aria-label="Page navigation">
                    <ul class="pagination justify-content-center">
                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <li class="page-item <?= $i == $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?>"><?= $i ?></a>
                            </li>
                        <?php endfor; ?>
                    </ul>
                </nav>
            </div>
        </div>
    </div>

    <!-- Expiration Modal -->
    <?php foreach ($activation_codes as $code): ?>
        <div class="modal fade" id="expirationModal<?= $code['id'] ?>" tabindex="-1" aria-labelledby="expirationModalLabel<?= $code['id'] ?>" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="expirationModalLabel<?= $code['id'] ?>">更新过期时间</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <form id="expirationForm<?= $code['id'] ?>">
                            <div class="mb-3">
                                <label for="newExpirationDate<?= $code['id'] ?>" class="form-label">新的过期时间</label>
                                <input type="datetime-local" class="form-control" id="newExpirationDate<?= $code['id'] ?>" name="new_expiration_date" required>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                        <button type="button" class="btn btn-primary updateExpirationBtn" data-code-id="<?= $code['id'] ?>">保存</button>
                    </div>
                </div>
            </div>
        </div>
    <?php endforeach; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('generateCodeBtn').addEventListener('click', function() {
            const messageDiv = document.getElementById('message');
            messageDiv.innerHTML = '正在生成激活码...';

            fetch('index.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `csrf_token=<?= htmlspecialchars($csrf_token) ?>&action=generate_code`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    messageDiv.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
                    const newRow = document.createElement('tr');
                    newRow.innerHTML = `
                        <td>${data.activation_code}</td>
                        <td>否</td>
                        <td>未绑定</td>
                        <td>${new Date().toLocaleString()}</td>
                        <td>未激活</td>
                        <td>${new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toLocaleString()}</td>
                        <td>
                            <button type="button" class="btn btn-sm btn-secondary" data-bs-toggle="modal" data-bs-target="#expirationModal${data.id}">
                                <i class="bx bx-calendar"></i> 更新过期时间
                            </button>
                            <button type="button" class="btn btn-sm btn-danger deleteBtn" data-code-id="${data.id}">
                                <i class="bx bx-trash"></i> 删除
                            </button>
                        </td>
                    `;
                    document.querySelector('table tbody').prepend(newRow);

                    // Add expiration modal for the new code
                    const expirationModal = document.createElement('div');
                    expirationModal.className = 'modal fade';
                    expirationModal.id = `expirationModal${data.id}`;
                    expirationModal.tabIndex = '-1';
                    expirationModal.setAttribute('aria-labelledby', `expirationModalLabel${data.id}`);
                    expirationModal.setAttribute('aria-hidden', 'true');
                    expirationModal.innerHTML = `
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="expirationModalLabel${data.id}">更新过期时间</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <div class="modal-body">
                                    <form id="expirationForm${data.id}">
                                        <div class="mb-3">
                                            <label for="newExpirationDate${data.id}" class="form-label">新的过期时间</label>
                                            <input type="datetime-local" class="form-control" id="newExpirationDate${data.id}" name="new_expiration_date" required>
                                        </div>
                                    </form>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                                    <button type="button" class="btn btn-primary updateExpirationBtn" data-code-id="${data.id}">保存</button>
                                </div>
                            </div>
                        </div>
                    `;
                    document.body.appendChild(expirationModal);
                } else {
                    messageDiv.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                messageDiv.innerHTML = '<div class="alert alert-danger">生成激活码时发生错误</div>';
            });
        });

        document.querySelectorAll('.updateExpirationBtn').forEach(button => {
            button.addEventListener('click', function() {
                const codeId = this.dataset.codeId;
                const newExpirationDate = document.getElementById(`newExpirationDate${codeId}`).value;
                const messageDiv = document.getElementById('message');

                fetch('index.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `csrf_token=<?= htmlspecialchars($csrf_token) ?>&action=update_expiration&code_id=${codeId}&new_expiration_date=${newExpirationDate}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        messageDiv.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
                        location.reload();
                    } else {
                        messageDiv.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    messageDiv.innerHTML = '<div class="alert alert-danger">更新过期时间时发生错误</div>';
                });
            });
        });

        document.querySelectorAll('.unbindBtn').forEach(button => {
            button.addEventListener('click', function() {
                const codeId = this.dataset.codeId;
                const messageDiv = document.getElementById('message');

                fetch('index.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `csrf_token=<?= htmlspecialchars($csrf_token) ?>&action=unbind&code_id=${codeId}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        messageDiv.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
                        location.reload();
                    } else {
                        messageDiv.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    messageDiv.innerHTML = '<div class="alert alert-danger">解绑时发生错误</div>';
                });
            });
        });

        document.querySelectorAll('.deleteBtn').forEach(button => {
            button.addEventListener('click', function() {
                const codeId = this.dataset.codeId;
                const messageDiv = document.getElementById('message');

                if (confirm('确定要删除此激活码吗？')) {
                    fetch('index.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `csrf_token=<?= htmlspecialchars($csrf_token) ?>&action=delete&code_id=${codeId}`
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            messageDiv.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
                            location.reload();
                        } else {
                            messageDiv.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        messageDiv.innerHTML = '<div class="alert alert-danger">删除时发生错误</div>';
                    });
                }
            });
        });
    </script>
</body>
</html>