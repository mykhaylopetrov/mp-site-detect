<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Detector.php';
require_once __DIR__ . '/../src/Cache.php';
require_once __DIR__ . '/../src/SpamProtection.php';

// Локальні налаштування (config.php у .gitignore): PAGESPEED_API_KEY та інше.
if (is_file(__DIR__ . '/../config.php')) {
    require_once __DIR__ . '/../config.php';
}

use App\Cache;
use App\Detector;
use App\SpamProtection;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if (!function_exists('mp_send_json')) {
    function mp_send_json(array $payload, int $status = 200): void
    {
        http_response_code($status);
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
}

$raw = $_POST['url'] ?? $_GET['url'] ?? '';
if ($raw === '') {
    mp_send_json([
        'success' => false,
        'error' => 'Не введено URL або домен',
    ], 400);
}

$spamGuard = (new SpamProtection())->guard([
    'csrf_token' => $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? null,
    'hp' => $_POST['hp'] ?? $_POST['website_url'] ?? $_GET['hp'] ?? null,
    'js' => $_POST['js'] ?? $_POST['js_token'] ?? $_GET['js'] ?? null,
    'ts' => $_POST['ts'] ?? $_POST['form_loaded_at'] ?? $_GET['ts'] ?? null,
]);
if (!$spamGuard['ok']) {
    if (($spamGuard['reason'] ?? '') === 'rate_limit' && isset($spamGuard['retry_after'])) {
        header('Retry-After: ' . (int)$spamGuard['retry_after']);
    }
    mp_send_json([
        'success' => false,
        'error' => $spamGuard['error'] ?? 'Запит відхилено',
    ], (int)($spamGuard['http_status'] ?? 400));
}

$force = isset($_REQUEST['force']) && (string)$_REQUEST['force'] !== '' && (string)$_REQUEST['force'] !== '0';
$ttlParam = isset($_REQUEST['ttl']) ? (int)$_REQUEST['ttl'] : 0;
$ttl = $ttlParam > 0 ? $ttlParam : Cache::DEFAULT_TTL;

try {
    $detector = new Detector((string)$raw);
    $normalizedDomain = $detector->getDomain();

    $cache = new Cache(null, $ttl);

    if (!$force) {
        $cached = $cache->get($normalizedDomain);
        if ($cached !== null) {
            $cachedAt = is_file($cache->fileFor($normalizedDomain))
                ? filemtime($cache->fileFor($normalizedDomain))
                : time();
            $cached['cached'] = true;
            mp_send_json([
                'success' => true,
                'cached' => true,
                'cached_at' => date('c', $cachedAt),
                'data' => $cached,
            ]);
        }
    }

    $data = $detector->analyze();
    $cache->set($normalizedDomain, $data);

    mp_send_json([
        'success' => true,
        'cached' => false,
        'data' => $data,
    ]);
} catch (\Throwable $e) {
    mp_send_json([
        'success' => false,
        'error' => $e->getMessage(),
    ], 400);
}
