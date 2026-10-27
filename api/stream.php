<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Detector.php';
require_once __DIR__ . '/../src/Cache.php';
require_once __DIR__ . '/../src/SpamProtection.php';

// Local settings (config.php in .gitignore): PAGESPEED_API_KEY and more.
if (is_file(__DIR__ . '/../config.php')) {
    require_once __DIR__ . '/../config.php';
}

use App\Cache;
use App\Detector;
use App\SpamProtection;

/**
 * SSE endpoint for streaming site analysis results.
 * Instead of one large JSON it returns a series of events:
 *   - cached     : sent at the start if the result is taken from cache
 *   - meta       : basic info (domain, url, ip, checked_at)
 *   - location   : IP-based location
 *   - hosting    : hosting provider
 *   - whois      : WHOIS info
 *   - cms        : detected CMS (with built-in WordPress details inside, if WP)
 *   - frameworks : PHP/JS frameworks
 *   - server     : single Web Server section (web server, Node.js, PHP, Python, CDN, database)
 *   - pagespeed  : Google PageSpeed Insights scores (Lighthouse mobile: scores + metrics)
 *   - complete   : final result
 *   - error      : error message
 *
 * Parallel streams (so slow PageSpeed does not delay fast blocks):
 *   - only=pagespeed : run and return PageSpeed only (the frontend opens
 *     this stream in parallel with the main one); cached separately
 *     (`<domain>.pagespeed`), so parallel stream records do not conflict
 *   - skip=a,b       : run everything except the listed sections (the frontend
 *     main stream passes skip=pagespeed)
 * Without only/skip — legacy behavior: everything in one stream (for compatibility).
 *
 * Parameters:
 *   - url    : URL or domain to analyze (required)
 *   - force  : 1 — ignore cache, run a fresh analysis (optional)
 *   - ttl    : cache TTL in seconds (optional, 86400 by default)
 *   - only   : comma-separated list of sections (e.g. only=pagespeed)
 *   - skip   : comma-separated list of sections to skip
 */

// Disable output buffering so events reach the client immediately.
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

// SSE headers
header('Content-Type: text/event-stream; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, no-transform');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // disables buffering in nginx
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
 * Sends a single SSE event.
 *
 * @param string $name event name
 * @param mixed  $data payload (serialized to JSON)
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
 * Sends all result sections as separate SSE events.
 * Used both for fresh analysis and for serving from cache.
 *
 * @param array<string, mixed> $data full analyze() result
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
 * Parses a comma-separated parameter (only/skip) into a list of allowed sections.
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
    // only=... mode is cached under a separate key (suffix without ':' and '/',
    // because Cache::hashDomain strips everything after them) so parallel streams
    // (main + pagespeed) do not overwrite each other's records.
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

    // Fresh analysis
    $result = null;
    $detector->analyzeWithCallback(function (string $section, $data) use (&$result): void {
        if ($section === 'complete') {
            $result = $data;
            return; // complete will be sent at the end via emit_result
        }
        mp_stream_send($section, $data);
    }, $only, $skip);

    if (is_array($result) && !empty($result['domain'])) {
        $cache->set($cacheKey, $result);
        // Persist data and send the complete event
        $result['cached'] = false;
        mp_stream_send('complete', $result);
    }
} catch (\Throwable $e) {
    mp_stream_send('error', ['error' => $e->getMessage()]);
    exit;
}
