<?php

declare(strict_types=1);

session_start();

$config = require __DIR__ . '/config.php';
$lockFile = __DIR__ . '/.installed';

if (!isset($_SESSION['install_csrf'])) {
    $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
}

if (file_exists($lockFile) || !$config['install']['enabled']) {
    http_response_code(403);
    echo 'Installation is disabled.';
    exit;
}

function pdoFromConfig(array $config): PDO
{
    $db = $config['db'];
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $db['host'], $db['port'], $db['name'], $db['charset']);

    return new PDO($dsn, $db['user'], $db['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
}

$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $csrfToken = (string) ($_POST['csrf_token'] ?? '');
        if (!hash_equals((string) $_SESSION['install_csrf'], $csrfToken)) {
            throw new RuntimeException('Invalid CSRF token.');
        }

        $rawPassword = (string) ($_POST['app_password'] ?? '');
        if (mb_strlen($rawPassword) < 10) {
            throw new RuntimeException('Password must be at least 10 characters.');
        }

        $passwordHash = password_hash($rawPassword, PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            throw new RuntimeException('Could not generate password hash.');
        }

        $configPath = __DIR__ . '/config.php';
        $configContent = (string) file_get_contents($configPath);
        if ($configContent === '') {
            throw new RuntimeException('Could not read config.php');
        }
        $updatedConfig = str_replace('__SET_DURING_INSTALL__', $passwordHash, $configContent);
        if ($updatedConfig === $configContent) {
            throw new RuntimeException('Install placeholder not found in config.php');
        }
        if (file_put_contents($configPath, $updatedConfig, LOCK_EX) === false) {
            throw new RuntimeException('Could not write password hash to config.php');
        }

        $pdo = pdoFromConfig($config);
        $pdo->exec('SET NAMES utf8mb4');

        $pdo->exec(
            <<<'SQL'
            CREATE TABLE IF NOT EXISTS thesis_nodes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                parent_id INT NULL,
                level TINYINT NOT NULL,
                title VARCHAR(500) NOT NULL,
                order_index INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_thesis_parent FOREIGN KEY (parent_id)
                    REFERENCES thesis_nodes(id) ON DELETE CASCADE,
                INDEX idx_parent_order (parent_id, order_index)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            SQL
        );

        $pdo->exec(
            <<<'SQL'
            CREATE TABLE IF NOT EXISTS ideas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                node_id INT NOT NULL,
                idea_type ENUM('addition', 'review', 'article', 'reference', 'note') NOT NULL DEFAULT 'note',
                content TEXT NOT NULL,
                priority TINYINT DEFAULT 2,
                is_done BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_idea_node FOREIGN KEY (node_id)
                    REFERENCES thesis_nodes(id) ON DELETE CASCADE,
                INDEX idx_ideas_node (node_id),
                INDEX idx_ideas_type (idea_type),
                INDEX idx_ideas_priority (priority),
                INDEX idx_ideas_done (is_done)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            SQL
        );

        $count = (int) $pdo->query('SELECT COUNT(*) AS c FROM thesis_nodes WHERE level = 1')->fetch()['c'];
        if ($count === 0) {
            $stmt = $pdo->prepare('INSERT INTO thesis_nodes (parent_id, level, title, order_index) VALUES (NULL, 1, ?, 1)');
            $stmt->execute(['الفصل الأول']);
        }

        if (file_put_contents($lockFile, date(DATE_ATOM), LOCK_EX) === false) {
            throw new RuntimeException('Failed to create install lock file.');
        }

        $message = 'Installation complete. Please delete install.php after first use.';
        unset($_SESSION['install_csrf']);
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}
?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>تهيئة Thesis Tracker</title>
  <style>
    body {font-family: Tahoma, sans-serif; margin: 2rem; background: #f7f8ff; color: #1f2140;}
    .card {max-width: 650px; background: #fff; border-radius: 14px; padding: 1.5rem; margin: auto; box-shadow: 0 8px 25px rgba(0,0,0,0.08);}
    button {background: #4f46e5; color: white; border: 0; border-radius: 10px; padding: .7rem 1.2rem; cursor: pointer;}
    .ok {background: #ecfdf5; color: #065f46; padding: .6rem .9rem; border-radius: 8px; margin-bottom: 1rem;}
    .err {background: #fef2f2; color: #991b1b; padding: .6rem .9rem; border-radius: 8px; margin-bottom: 1rem; word-break: break-word;}
  </style>
</head>
<body>
  <div class="card">
    <h1>تهيئة قاعدة البيانات</h1>
    <p>اضغط الزر أدناه لإنشاء الجداول الافتراضية للتطبيق.</p>
    <?php if ($message): ?><div class="ok"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <?php if ($error): ?><div class="err"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars((string) $_SESSION['install_csrf'], ENT_QUOTES, 'UTF-8') ?>">
      <label for="app_password">كلمة مرور التطبيق</label>
      <input id="app_password" name="app_password" type="password" minlength="10" required style="margin:.4rem 0 1rem;">
      <button type="submit">تنفيذ التهيئة</button>
    </form>
  </div>
</body>
</html>
