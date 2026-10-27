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
 *   - pagespeed  : покази Google PageSpeed Insights (Lighthouse mobile: бали + метрики)
 *   - complete   : фінальний результат
 *   - error      : повідомлення про помилку
 *
 * Паралельні стріми (щоб повільний PageSpeed не затримував швидкі блоки):
 *   - only=pagespeed : виконати й віддати лише PageSpeed (фронтенд відкриває
 *     цей стрім паралельно з основним); кешується окремо (`<domain>.pagespeed`),
 *     тому записи паралельних стрімів не конфліктують
 *   - skip=a,b       : виконати все, крім перелічених секцій (основний стрім
 *     фронтенда передає skip=pagespeed)
 * Без only/skip — колишня поведінка: все в одному стрімі (для сумісності).
 *
 * Параметри:
 *   - url    : URL або домен для аналізу (обов'язково)
 *   - force  : 1 — ігнорувати кеш, виконати свіжий аналіз (необов'язково)
 *   - ttl    : TTL кешу в секундах (необов'язково, 86400 за замовчуванням)
 *   - only   : comma-separated список секцій (напр. only=pagespeed)
 *   - skip   : comma-separated список секцій для пропуску
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
    $order = ['location', 'hosting', 'whois', 'cms', 'frameworks', 'server', 'pagespeed'];
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

/**
 * Розбирає comma-separated параметр (only/skip) у список допустимих секцій.
 *
 * @return string[]
 */
function mp_stream_parse_sections($value): array
{
    if (!is_string($value) || trim($value) === '') {
        return [];
    }
    $allowed = ['meta', 'location', 'hosting', 'whois', 'cms', 'frameworks', 'server', 'pagespeed'];
    $out = [];
    foreach (explode(',', $value) as $part) {
        $part = strtolower(trim($part));
        if ($part !== '' && in_array($part, $allowed, true) && !in_array($part, $out, true)) {
            $out[] = $part;
        }
    }
    return $out;
}

$only = mp_stream_parse_sections($_GET['only'] ?? null);
$skip = mp_stream_parse_sections($_GET['skip'] ?? null);

try {
    $detector = new Detector($raw);
    $normalizedDomain = $detector->getDomain();

    $cache = new Cache(null, $ttl);
    // Режим only=... кешується окремим ключем (суфікс без ':' і '/',
    // бо Cache::hashDomain відрізає все після них), щоб паралельні стріми
    // (основний + pagespeed) не затирали записи одне одного.
    $cacheKey = !empty($only) ? $normalizedDomain . '.' . implode('.', $only) : $normalizedDomain;

    if (!$force) {
        $cached = $cache->get($cacheKey);
        if ($cached !== null) {
            $cachedAt = is_file($cache->fileFor($cacheKey))
                ? filemtime($cache->fileFor($cacheKey))
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
    }, $only, $skip);

    if (is_array($result) && !empty($result['domain'])) {
        $cache->set($cacheKey, $result);
        // Зберігаємо дані й надсилаємо complete-подію
        $result['cached'] = false;
        mp_stream_send('complete', $result);
    }
} catch (\Throwable $e) {
    mp_stream_send('error', ['error' => $e->getMessage()]);
    exit;
}
