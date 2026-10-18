<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Detector.php';
require_once __DIR__ . '/../src/Cache.php';
require_once __DIR__ . '/../src/SpamProtection.php';

use App\Cache;
use App\Detector;
use App\SpamProtection;

/**
 * SSE-ендпоінт для потокової видачі результатів аналізу сайту.
 * Замість одного великого JSON повертає серію подій:
 *   - cached     : надіслано на початку, якщо результат взято з кешу
 *   - meta       : базова інформація (domain, url, ip, checked_at)
 *   - location   : місцезнаходження за IP
 *   - hosting    : хостинг-провайдер
 *   - whois      : WHOIS-інформація
 *   - cms        : виявлені CMS (з вбудованими WordPress-деталями всередині, якщо WP)
 *   - frameworks : PHP/JS-фреймворки
 *   - server     : єдина секція Веб-сервер (веб-сервер, Node.js, PHP, Python, CDN, база даних)
 *   - complete   : фінальний результат
 *   - error      : повідомлення про помилку
 *
 * Параметри:
 *   - url    : URL або домен для аналізу (обов'язково)
 *   - force  : 1 — ігнорувати кеш, виконати свіжий аналіз (необов'язково)
 *   - ttl    : TTL кешу в секундах (необов'язково, 86400 за замовчуванням)
 */

// Вимикаємо буферизацію виводу, щоб події летіли клієнту одразу.
@ini_set('output_buffering', '0');
@ini_set('implicit_flush', '1');
@ob_implicit_flush(true);
while (ob_get_level() > 0) {
    @ob_end_clean();
}

set_time_limit(0);
if (function_exists('session_status')) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
}

// Заголовки SSE
header('Content-Type: text/event-stream; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, no-transform');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // вимикає буферизацію у nginx
header('Access-Control-Allow-Origin: *');

$spamGuard = (new SpamProtection())->guard([
    'csrf_token' => $_GET['csrf_token'] ?? null,
    'hp' => $_GET['hp'] ?? null,
    'js' => $_GET['js'] ?? null,
    'ts' => $_GET['ts'] ?? null,
]);
if (!$spamGuard['ok']) {
    mp_stream_send('error', ['error' => $spamGuard['error'] ?? 'Запит відхилено системою захисту']);
    exit;
}

/**
 * Надсилає одну подію SSE.
 *
 * @param string $name назва події
 * @param mixed  $data дані (серіалізуються у JSON)
 */
function mp_stream_send(string $name, $data): void
{
    $payload = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($payload === false) {
        $payload = '{"error":"Помилка серіалізації"}';
    }
    echo 'event: ' . $name . "\n";
    echo 'data: ' . $payload . "\n\n";
    @ob_flush();
    @flush();
}

/**
 * Відправляє всі секції результату як окремі SSE-події.
 * Використовується і для свіжого аналізу, і для видачі з кешу.
 *
 * @param array<string, mixed> $data повний результат analyze()
 */
function mp_stream_emit_result(array $data): void
{
    mp_stream_send('meta', [
        'domain' => $data['domain'] ?? '',
        'url' => $data['url'] ?? '',
        'ip' => $data['ip'] ?? null,
        'checked_at' => $data['checked_at'] ?? date('c'),
    ]);

    $sections = $data['sections'] ?? [];
    $order = ['location', 'hosting', 'whois', 'cms', 'frameworks', 'server'];
    foreach ($order as $section) {
        if (!empty($sections[$section])) {
            mp_stream_send($section, $sections[$section]);
        }
    }

    mp_stream_send('complete', $data);
}

$raw = $_GET['url'] ?? '';
if (!is_string($raw) || trim($raw) === '') {
    mp_stream_send('error', ['error' => 'Не введено URL або домен']);
    exit;
}

$force = isset($_GET['force']) && (string)$_GET['force'] !== '' && (string)$_GET['force'] !== '0';
$ttlParam = isset($_GET['ttl']) ? (int)$_GET['ttl'] : 0;
$ttl = $ttlParam > 0 ? $ttlParam : Cache::DEFAULT_TTL;

try {
    $detector = new Detector($raw);
    $normalizedDomain = $detector->getDomain();

    $cache = new Cache(null, $ttl);

    if (!$force) {
        $cached = $cache->get($normalizedDomain);
        if ($cached !== null) {
            $cachedAt = is_file($cache->fileFor($normalizedDomain))
                ? filemtime($cache->fileFor($normalizedDomain))
                : time();
            mp_stream_send('cached', [
                'domain' => $normalizedDomain,
                'cached_at' => date('c', $cachedAt),
                'ttl' => $ttl,
            ]);
            mp_stream_emit_result($cached);
            exit;
        }
    }

    // Свіжий аналіз
    $result = null;
    $detector->analyzeWithCallback(function (string $section, $data) use (&$result): void {
        if ($section === 'complete') {
            $result = $data;
            return; // complete надішлемо в кінці через emit_result
        }
        mp_stream_send($section, $data);
    });

    if (is_array($result) && !empty($result['domain'])) {
        $cache->set($result['domain'], $result);
        // Зберігаємо дані й надсилаємо complete-подію
        $result['cached'] = false;
        mp_stream_send('complete', $result);
    }
} catch (\Throwable $e) {
    mp_stream_send('error', ['error' => $e->getMessage()]);
    exit;
}
