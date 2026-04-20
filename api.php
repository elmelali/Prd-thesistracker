<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');

if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

session_set_cookie_params([
    'lifetime' => $config['auth']['session_lifetime_seconds'],
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function respond(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function db(array $config): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $db = $config['db'];
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $db['host'], $db['port'], $db['name'], $db['charset']);

    $pdo = new PDO($dsn, $db['user'], $db['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    return $pdo;
}

function isAuthenticated(): bool
{
    return !empty($_SESSION['authenticated']) && !empty($_SESSION['auth_expires']) && $_SESSION['auth_expires'] > time();
}

function refreshSession(array $config): void
{
    $_SESSION['authenticated'] = true;
    $_SESSION['auth_expires'] = time() + (int) $config['auth']['session_lifetime_seconds'];
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function invalidateSession(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
    }
    session_destroy();
}

function requestData(): array
{
    $raw = file_get_contents('php://input') ?: '';
    if ($raw !== '') {
        $json = json_decode($raw, true);
        if (is_array($json)) {
            return $json;
        }
    }
    return $_POST;
}

function getCsrfFromRequest(array $input): string
{
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $headerToken = $headers['X-CSRF-Token'] ?? $headers['x-csrf-token'] ?? '';
    return (string) ($headerToken ?: ($input['csrf_token'] ?? ''));
}

function requireAuth(array $config): void
{
    if (!isAuthenticated()) {
        respond(['ok' => false, 'error' => 'UNAUTHORIZED'], 401);
    }
    refreshSession($config);
}

function requireCsrf(array $input): void
{
    $token = getCsrfFromRequest($input);
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        respond(['ok' => false, 'error' => 'INVALID_CSRF'], 403);
    }
}

function getAllNodes(PDO $pdo): array
{
    return $pdo->query('SELECT id, parent_id, level, title, order_index, created_at FROM thesis_nodes ORDER BY level, order_index, id')->fetchAll();
}

function buildChildrenMap(array $nodes): array
{
    $map = [];
    foreach ($nodes as $node) {
        $parentId = $node['parent_id'] === null ? 0 : (int) $node['parent_id'];
        $map[$parentId][] = (int) $node['id'];
    }
    return $map;
}

function descendantsOf(int $rootId, array $childrenMap): array
{
    $result = [$rootId];
    $queue = [$rootId];
    while ($queue) {
        $current = array_shift($queue);
        foreach ($childrenMap[$current] ?? [] as $child) {
            $result[] = $child;
            $queue[] = $child;
        }
    }
    return $result;
}

function buildPathMap(array $nodes): array
{
    $byId = [];
    foreach ($nodes as $node) {
        $byId[(int) $node['id']] = $node;
    }

    $paths = [];

    $pathFor = function (int $id) use (&$pathFor, &$paths, $byId): string {
        if (isset($paths[$id])) {
            return $paths[$id];
        }
        if (!isset($byId[$id])) {
            return '';
        }

        $node = $byId[$id];
        $title = $node['title'];
        $parent = $node['parent_id'] !== null ? (int) $node['parent_id'] : null;

        if ($parent === null) {
            $paths[$id] = $title;
            return $paths[$id];
        }

        $parentPath = $pathFor($parent);
        $paths[$id] = $parentPath !== '' ? $parentPath . ' › ' . $title : $title;
        return $paths[$id];
    };

    foreach (array_keys($byId) as $id) {
        $pathFor($id);
    }

    return $paths;
}

function buildTree(array $nodes): array
{
    $items = [];
    foreach ($nodes as $node) {
        $node['children'] = [];
        $node['id'] = (int) $node['id'];
        $node['level'] = (int) $node['level'];
        $node['order_index'] = (int) $node['order_index'];
        $items[$node['id']] = $node;
    }

    $roots = [];
    foreach ($items as $id => &$item) {
        if ($item['parent_id'] === null) {
            $roots[] = &$item;
            continue;
        }

        $parentId = (int) $item['parent_id'];
        if (!isset($items[$parentId])) {
            $roots[] = &$item;
            continue;
        }

        $items[$parentId]['children'][] = &$item;
    }
    unset($item);

    $sortRecursive = function (&$branch) use (&$sortRecursive): void {
        usort($branch, static fn($a, $b) => [$a['order_index'], $a['id']] <=> [$b['order_index'], $b['id']]);
        foreach ($branch as &$child) {
            if (!empty($child['children'])) {
                $sortRecursive($child['children']);
            }
        }
        unset($child);
    };

    $sortRecursive($roots);

    return $roots;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$input = requestData();
$mutatingActions = ['add_node', 'edit_node', 'delete_node', 'reorder_node', 'add_idea', 'edit_idea', 'delete_idea', 'toggle_idea'];

try {
    if ($action === 'login') {
        $password = (string) ($input['password'] ?? '');
        if ($password === '' || !password_verify($password, $config['auth']['password_hash'])) {
            respond(['ok' => false, 'error' => 'INVALID_CREDENTIALS'], 401);
        }

        session_regenerate_id(true);
        refreshSession($config);
        respond(['ok' => true, 'csrf_token' => $_SESSION['csrf_token']]);
    }

    if ($action === 'logout') {
        invalidateSession();
        respond(['ok' => true]);
    }

    requireAuth($config);

    if (in_array($action, $mutatingActions, true)) {
        requireCsrf($input);
    }

    $pdo = db($config);

    switch ($action) {
        case 'get_tree': {
            $nodes = getAllNodes($pdo);
            $counts = $pdo->query(
                'SELECT n.id, COALESCE(SUM(CASE WHEN i.is_done = 0 THEN 1 ELSE 0 END), 0) AS pending_count
                 FROM thesis_nodes n
                 LEFT JOIN ideas i ON i.node_id = n.id
                 GROUP BY n.id'
            )->fetchAll();
            $countMap = [];
            foreach ($counts as $row) {
                $countMap[(int) $row['id']] = (int) $row['pending_count'];
            }

            foreach ($nodes as &$node) {
                $node['pending_count'] = $countMap[(int) $node['id']] ?? 0;
            }
            unset($node);

            $tree = buildTree($nodes);
            respond([
                'ok' => true,
                'csrf_token' => $_SESSION['csrf_token'],
                'nodes' => $nodes,
                'tree' => $tree,
            ]);
        }

        case 'add_node': {
            $title = trim((string) ($input['title'] ?? ''));
            $parentId = array_key_exists('parent_id', $input) && $input['parent_id'] !== '' ? (int) $input['parent_id'] : null;

            if ($title === '') {
                respond(['ok' => false, 'error' => 'TITLE_REQUIRED'], 422);
            }

            $level = 1;
            if ($parentId !== null) {
                $stmt = $pdo->prepare('SELECT level FROM thesis_nodes WHERE id = ?');
                $stmt->execute([$parentId]);
                $parent = $stmt->fetch();
                if (!$parent) {
                    respond(['ok' => false, 'error' => 'PARENT_NOT_FOUND'], 404);
                }
                $level = (int) $parent['level'] + 1;
                if ($level > 4) {
                    respond(['ok' => false, 'error' => 'MAX_DEPTH_REACHED'], 422);
                }
            }

            $stmt = $pdo->prepare('SELECT COALESCE(MAX(order_index), 0) + 1 AS next_index FROM thesis_nodes WHERE parent_id <=> ?');
            $stmt->execute([$parentId]);
            $nextOrder = (int) ($stmt->fetch()['next_index'] ?? 1);

            $stmt = $pdo->prepare('INSERT INTO thesis_nodes (parent_id, level, title, order_index) VALUES (?, ?, ?, ?)');
            $stmt->execute([$parentId, $level, $title, $nextOrder]);

            respond(['ok' => true, 'id' => (int) $pdo->lastInsertId()]);
        }

        case 'edit_node': {
            $nodeId = (int) ($input['node_id'] ?? 0);
            $title = trim((string) ($input['title'] ?? ''));
            if ($nodeId <= 0 || $title === '') {
                respond(['ok' => false, 'error' => 'INVALID_INPUT'], 422);
            }

            $stmt = $pdo->prepare('UPDATE thesis_nodes SET title = ? WHERE id = ?');
            $stmt->execute([$title, $nodeId]);
            respond(['ok' => true]);
        }

        case 'delete_node': {
            $nodeId = (int) ($input['node_id'] ?? 0);
            if ($nodeId <= 0) {
                respond(['ok' => false, 'error' => 'INVALID_NODE_ID'], 422);
            }

            $stmt = $pdo->prepare('DELETE FROM thesis_nodes WHERE id = ?');
            $stmt->execute([$nodeId]);
            respond(['ok' => true]);
        }

        case 'reorder_node': {
            $nodeId = (int) ($input['node_id'] ?? 0);
            $direction = (string) ($input['direction'] ?? '');
            if ($nodeId <= 0 || !in_array($direction, ['up', 'down'], true)) {
                respond(['ok' => false, 'error' => 'INVALID_INPUT'], 422);
            }

            $stmt = $pdo->prepare('SELECT id, parent_id, order_index FROM thesis_nodes WHERE id = ?');
            $stmt->execute([$nodeId]);
            $current = $stmt->fetch();
            if (!$current) {
                respond(['ok' => false, 'error' => 'NODE_NOT_FOUND'], 404);
            }

            $operator = $direction === 'up' ? '<' : '>';
            $sort = $direction === 'up' ? 'DESC' : 'ASC';

            $stmt = $pdo->prepare(
                "SELECT id, order_index FROM thesis_nodes
                 WHERE parent_id <=> ? AND order_index {$operator} ?
                 ORDER BY order_index {$sort}, id {$sort}
                 LIMIT 1"
            );
            $stmt->execute([$current['parent_id'], $current['order_index']]);
            $swap = $stmt->fetch();

            if (!$swap) {
                respond(['ok' => true]);
            }

            $pdo->beginTransaction();
            $update = $pdo->prepare('UPDATE thesis_nodes SET order_index = ? WHERE id = ?');
            $update->execute([(int) $swap['order_index'], (int) $current['id']]);
            $update->execute([(int) $current['order_index'], (int) $swap['id']]);
            $pdo->commit();

            respond(['ok' => true]);
        }

        case 'get_ideas': {
            $nodeId = (int) ($_GET['node_id'] ?? $input['node_id'] ?? 0);
            if ($nodeId <= 0) {
                respond(['ok' => false, 'error' => 'INVALID_NODE_ID'], 422);
            }

            $includeDescendants = filter_var($_GET['aggregate'] ?? $input['aggregate'] ?? 'true', FILTER_VALIDATE_BOOLEAN);

            $nodes = getAllNodes($pdo);
            $childrenMap = buildChildrenMap($nodes);
            $pathMap = buildPathMap($nodes);

            $nodeIds = $includeDescendants ? descendantsOf($nodeId, $childrenMap) : [$nodeId];
            $placeholders = implode(',', array_fill(0, count($nodeIds), '?'));

            $stmt = $pdo->prepare(
                "SELECT i.id, i.node_id, i.idea_type, i.content, i.priority, i.is_done, i.created_at, i.updated_at
                 FROM ideas i
                 WHERE i.node_id IN ({$placeholders})
                 ORDER BY i.is_done ASC, i.priority ASC, i.updated_at DESC, i.id DESC"
            );
            $stmt->execute($nodeIds);
            $ideas = $stmt->fetchAll();

            foreach ($ideas as &$idea) {
                $idea['id'] = (int) $idea['id'];
                $idea['node_id'] = (int) $idea['node_id'];
                $idea['priority'] = (int) $idea['priority'];
                $idea['is_done'] = (bool) $idea['is_done'];
                $idea['path'] = $pathMap[$idea['node_id']] ?? '';
            }
            unset($idea);

            respond([
                'ok' => true,
                'ideas' => $ideas,
                'node_ids' => $nodeIds,
            ]);
        }

        case 'add_idea': {
            $nodeId = (int) ($input['node_id'] ?? 0);
            $type = (string) ($input['idea_type'] ?? 'note');
            $content = trim((string) ($input['content'] ?? ''));
            $priority = (int) ($input['priority'] ?? 2);

            if ($nodeId <= 0 || $content === '') {
                respond(['ok' => false, 'error' => 'INVALID_INPUT'], 422);
            }

            if (!in_array($type, ['addition', 'review', 'article', 'reference', 'note'], true)) {
                $type = 'note';
            }

            if (!in_array($priority, [1, 2, 3], true)) {
                $priority = 2;
            }

            $stmt = $pdo->prepare('INSERT INTO ideas (node_id, idea_type, content, priority, is_done) VALUES (?, ?, ?, ?, 0)');
            $stmt->execute([$nodeId, $type, $content, $priority]);

            respond(['ok' => true, 'id' => (int) $pdo->lastInsertId()]);
        }

        case 'edit_idea': {
            $ideaId = (int) ($input['idea_id'] ?? 0);
            $content = trim((string) ($input['content'] ?? ''));
            $type = (string) ($input['idea_type'] ?? 'note');
            $priority = (int) ($input['priority'] ?? 2);

            if ($ideaId <= 0 || $content === '') {
                respond(['ok' => false, 'error' => 'INVALID_INPUT'], 422);
            }

            if (!in_array($type, ['addition', 'review', 'article', 'reference', 'note'], true)) {
                $type = 'note';
            }

            if (!in_array($priority, [1, 2, 3], true)) {
                $priority = 2;
            }

            $stmt = $pdo->prepare('UPDATE ideas SET content = ?, idea_type = ?, priority = ? WHERE id = ?');
            $stmt->execute([$content, $type, $priority, $ideaId]);
            respond(['ok' => true]);
        }

        case 'delete_idea': {
            $ideaId = (int) ($input['idea_id'] ?? 0);
            if ($ideaId <= 0) {
                respond(['ok' => false, 'error' => 'INVALID_IDEA_ID'], 422);
            }

            $stmt = $pdo->prepare('DELETE FROM ideas WHERE id = ?');
            $stmt->execute([$ideaId]);
            respond(['ok' => true]);
        }

        case 'toggle_idea': {
            $ideaId = (int) ($input['idea_id'] ?? 0);
            $isDone = filter_var($input['is_done'] ?? false, FILTER_VALIDATE_BOOLEAN);
            if ($ideaId <= 0) {
                respond(['ok' => false, 'error' => 'INVALID_IDEA_ID'], 422);
            }

            $stmt = $pdo->prepare('UPDATE ideas SET is_done = ? WHERE id = ?');
            $stmt->execute([$isDone ? 1 : 0, $ideaId]);
            respond(['ok' => true]);
        }

        case 'search': {
            $q = trim((string) ($_GET['q'] ?? $input['q'] ?? ''));
            if ($q === '') {
                respond(['ok' => true, 'results' => []]);
            }

            $nodes = getAllNodes($pdo);
            $pathMap = buildPathMap($nodes);

            $nodeStmt = $pdo->prepare(
                'SELECT id, title FROM thesis_nodes
                 WHERE title LIKE ?
                 ORDER BY id DESC LIMIT 20'
            );
            $like = '%' . $q . '%';
            $nodeStmt->execute([$like]);
            $nodeResults = $nodeStmt->fetchAll();

            $ideaStmt = $pdo->prepare(
                'SELECT i.id, i.node_id, i.content
                 FROM ideas i
                 WHERE i.content LIKE ?
                 ORDER BY i.updated_at DESC
                 LIMIT 20'
            );
            $ideaStmt->execute([$like]);
            $ideaResults = $ideaStmt->fetchAll();

            $results = [];
            foreach ($nodeResults as $n) {
                $id = (int) $n['id'];
                $results[] = [
                    'result_type' => 'node',
                    'node_id' => $id,
                    'path' => $pathMap[$id] ?? $n['title'],
                    'snippet' => $n['title'],
                ];
            }

            foreach ($ideaResults as $i) {
                $nodeId = (int) $i['node_id'];
                $snippet = mb_substr((string) $i['content'], 0, 120);
                $results[] = [
                    'result_type' => 'idea',
                    'idea_id' => (int) $i['id'],
                    'node_id' => $nodeId,
                    'path' => $pathMap[$nodeId] ?? '',
                    'snippet' => $snippet,
                ];
            }

            respond(['ok' => true, 'results' => $results]);
        }

        case 'dashboard': {
            $stats = [
                'chapters' => 0,
                'ideas_total' => 0,
                'ideas_done' => 0,
                'ideas_urgent' => 0,
                'ideas_by_type' => [
                    'addition' => 0,
                    'review' => 0,
                    'article' => 0,
                    'reference' => 0,
                    'note' => 0,
                ],
            ];

            $stats['chapters'] = (int) $pdo->query('SELECT COUNT(*) AS c FROM thesis_nodes WHERE level = 1')->fetch()['c'];

            $ideaAgg = $pdo->query(
                'SELECT
                    COUNT(*) AS ideas_total,
                    SUM(CASE WHEN is_done = 1 THEN 1 ELSE 0 END) AS ideas_done,
                    SUM(CASE WHEN priority = 1 AND is_done = 0 THEN 1 ELSE 0 END) AS ideas_urgent
                 FROM ideas'
            )->fetch();

            $stats['ideas_total'] = (int) ($ideaAgg['ideas_total'] ?? 0);
            $stats['ideas_done'] = (int) ($ideaAgg['ideas_done'] ?? 0);
            $stats['ideas_urgent'] = (int) ($ideaAgg['ideas_urgent'] ?? 0);

            $types = $pdo->query('SELECT idea_type, COUNT(*) as c FROM ideas GROUP BY idea_type')->fetchAll();
            foreach ($types as $row) {
                $type = (string) $row['idea_type'];
                if (array_key_exists($type, $stats['ideas_by_type'])) {
                    $stats['ideas_by_type'][$type] = (int) $row['c'];
                }
            }

            $nodes = getAllNodes($pdo);
            $pathMap = buildPathMap($nodes);

            $latest = $pdo->query(
                'SELECT id, node_id, content, idea_type, priority, is_done, created_at
                 FROM ideas
                 ORDER BY created_at DESC
                 LIMIT 5'
            )->fetchAll();

            $urgent = $pdo->query(
                'SELECT id, node_id, content, idea_type, priority, is_done, created_at
                 FROM ideas
                 WHERE priority = 1 AND is_done = 0
                 ORDER BY created_at DESC
                 LIMIT 10'
            )->fetchAll();

            foreach ($latest as &$idea) {
                $idea['id'] = (int) $idea['id'];
                $idea['node_id'] = (int) $idea['node_id'];
                $idea['priority'] = (int) $idea['priority'];
                $idea['is_done'] = (bool) $idea['is_done'];
                $idea['path'] = $pathMap[$idea['node_id']] ?? '';
            }
            unset($idea);

            foreach ($urgent as &$idea) {
                $idea['id'] = (int) $idea['id'];
                $idea['node_id'] = (int) $idea['node_id'];
                $idea['priority'] = (int) $idea['priority'];
                $idea['is_done'] = (bool) $idea['is_done'];
                $idea['path'] = $pathMap[$idea['node_id']] ?? '';
            }
            unset($idea);

            respond([
                'ok' => true,
                'csrf_token' => $_SESSION['csrf_token'],
                'stats' => $stats,
                'latest_ideas' => $latest,
                'urgent_ideas' => $urgent,
            ]);
        }

        default:
            respond(['ok' => false, 'error' => 'UNKNOWN_ACTION'], 404);
    }
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    respond([
        'ok' => false,
        'error' => 'SERVER_ERROR',
        'message' => $e->getMessage(),
    ], 500);
}
