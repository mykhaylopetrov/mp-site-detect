<?php

declare(strict_types=1);

namespace App;

use RuntimeException;

/**
 * Site information detection class:
 * IP address, geolocation, hosting, WHOIS, CMS, frameworks and other technologies.
 */
final class Detector
{
    private string $input;
    private string $scheme;
    private string $domain;
    private string $url;
    private array $httpHeaders = [];
    private ?string $html = null;
    private array $signatures = [];
    /** Negotiated HTTP protocol version of the main request (HTTP/1.1, HTTP/2, …) or null. */
    private ?string $httpVersion = null;

    public function __construct(string $input)
    {
        $input = trim($input);
        if ($input === '') {
            throw new RuntimeException('Введіть URL або домен');
        }

        if (!preg_match('~^https?://~i', $input)) {
            $input = 'https://' . $input;
        }

        $parts = parse_url($input);
        if (!$parts || empty($parts['host'])) {
            throw new RuntimeException('Некоректний формат URL');
        }

        $this->input = $input;
        $this->scheme = strtolower($parts['scheme'] ?? 'https');
        $this->domain = preg_replace('/^www\./i', '', strtolower($parts['host']));
        $this->url = $this->scheme . '://' . $parts['host']
            . (isset($parts['port']) ? ':' . $parts['port'] : '')
            . ($parts['path'] ?? '/');

        $this->signatures = $this->loadSignatures();
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * Run a full site analysis.
     *
     * @param string[] $only run only these sections (empty = all)
     * @param string[] $skip skip these sections
     */
    public function analyze(array $only = [], array $skip = []): array
    {
        $result = [
            'input' => $this->input,
            'domain' => $this->domain,
            'url' => $this->url,
            'checked_at' => date('c'),
            'sections' => [],
        ];

        $this->runAnalysis(function (string $section, $data) use (&$result) {
            if ($section === 'meta') {
                foreach ($data as $k => $v) {
                    $result[$k] = $v;
                }
            } else {
                $result['sections'][$section] = $data;
            }
        }, $only, $skip);

        return $result;
    }

    /**
     * Run analysis with progressive notification for each module.
     * Calls $emit($sectionName, $sectionData) immediately after each completed step.
     * Allows streaming (SSE) delivery of results in real time.
     *
     * @param callable(string, mixed): void $emit
     * @param string[] $only run only these sections (empty = all)
     * @param string[] $skip skip these sections
     */
    public function analyzeWithCallback(callable $emit, array $only = [], array $skip = []): array
    {
        $result = [
            'input' => $this->input,
            'domain' => $this->domain,
            'url' => $this->url,
            'checked_at' => date('c'),
            'sections' => [],
        ];

        $this->runAnalysis(function (string $section, $data) use (&$result, $emit) {
            if ($section === 'meta') {
                foreach ($data as $k => $v) {
                    $result[$k] = $v;
                }
            } else {
                $result['sections'][$section] = $data;
            }
            $emit($section, $data);
        }, $only, $skip);

        $emit('complete', $result);
        return $result;
    }

    /**
     * Internal sequential walk through all analysis steps.
     * Calls $onSection($name, $data) after each completed step.
     * Section name 'meta' is used for basic info (domain, ip, url, checked_at).
     *
     * @param callable(string, mixed): void $onSection
     * @param string[] $only run only these sections (empty = all) — allows
     *               moving slow blocks (PageSpeed) into a separate parallel stream
     * @param string[] $skip skip these sections without running their work
     */
    private function runAnalysis(callable $onSection, array $only = [], array $skip = []): void
    {
        $want = static function (string $section) use ($only, $skip): bool {
            if (!empty($only) && !in_array($section, $only, true)) {
                return false;
            }
            return !in_array($section, $skip, true);
        };

        $ip = ($want('meta') || $want('location') || $want('hosting'))
            ? $this->resolveIp($this->domain)
            : null;

        if ($want('meta')) {
            $onSection('meta', [
                'domain' => $this->domain,
                'url' => $this->url,
                'ip' => $ip,
                'checked_at' => date('c'),
            ]);
        }

        if ($ip !== null && ($want('location') || $want('hosting'))) {
            $geo = $this->lookupGeo($ip);
            if ($geo !== null) {
                if ($want('location')) {
                    $onSection('location', $geo['location']);
                }
                if ($want('hosting')) {
                    $onSection('hosting', $geo['hosting']);
                }
            }
        }

        if ($want('whois')) {
            $whois = $this->lookupWhois($this->domain);
            if ($whois !== null) {
                $onSection('whois', $whois);
            }
        }

        $needHtml = $want('cms') || $want('frameworks') || $want('server');
        $html = $needHtml ? $this->fetchHtml() : null;
        $cms = [];
        $frameworks = [];
        $serverInfo = null;
        if ($needHtml && $html !== null) {
            $generator = $this->extractMeta($html, 'generator');
            $cms = $this->detectCms($html, $generator);
            // Fallback: if HTML is a Hostia/bot-challenge placeholder page without WP markers,
            // but the site is still on WordPress — probe well-known WP endpoints with direct requests.
            if (empty($cms)) {
                $probed = $this->probeCmsViaEndpoints();
                if (!empty($probed)) {
                    $cms = $probed;
                }
            }
            if (!empty($cms)) {
                // If WordPress is found — embed its details directly into the CMS item
                $isWordPress = false;
                foreach ($cms as $cmsItem) {
                    if ($cmsItem['name'] === 'WordPress') {
                        $isWordPress = true;
                        break;
                    }
                }
                if ($isWordPress) {
                    $wpDetails = $this->detectWordPressDetails($html, $generator);
                    if ($wpDetails !== null) {
                        foreach ($cms as &$item) {
                            if ($item['name'] === 'WordPress') {
                                $item['wordpress'] = $wpDetails;
                                break;
                            }
                        }
                        unset($item);
                    }
                }
                // If Joomla is found — embed its details (version, template, extensions)
                $isJoomla = false;
                foreach ($cms as $cmsItem) {
                    if ($cmsItem['name'] === 'Joomla') {
                        $isJoomla = true;
                        break;
                    }
                }
                if ($isJoomla) {
                    $joomlaDetails = $this->detectJoomlaDetails($html, $generator);
                    if ($joomlaDetails !== null) {
                        foreach ($cms as &$item) {
                            if ($item['name'] === 'Joomla') {
                                $item['joomla'] = $joomlaDetails;
                                break;
                            }
                        }
                        unset($item);
                    }
                }
                // If Drupal is found — embed its details (version, theme, modules)
                $isDrupal = false;
                foreach ($cms as $cmsItem) {
                    if ($cmsItem['name'] === 'Drupal') {
                        $isDrupal = true;
                        break;
                    }
                }
                if ($isDrupal) {
                    $drupalDetails = $this->detectDrupalDetails($html, $generator, $this->httpHeaders);
                    if ($drupalDetails !== null) {
                        foreach ($cms as &$item) {
                            if ($item['name'] === 'Drupal') {
                                $item['drupal'] = $drupalDetails;
                                break;
                            }
                        }
                        unset($item);
                    }
                }
                if ($want('cms')) {
                    $onSection('cms', $cms);
                }
            }

            if ($want('frameworks')) {
                $frameworks = $this->detectFrameworks($html, $this->httpHeaders);
                if (!empty($frameworks)) {
                    $onSection('frameworks', $frameworks);
                }
            }

            if ($want('server')) {
                $serverInfo = $this->detectWebServer($this->httpHeaders, $cms, $frameworks);
                $cdn = $this->detectCdn($this->httpHeaders, $html);
                $dbInfo = $this->detectDatabase($this->httpHeaders, $html, $cms, $frameworks, []);
                $nodeInfo = $this->detectNodeJs($this->httpHeaders, $html);
                $pythonInfo = $this->detectPython($this->httpHeaders, $html, $frameworks);
                $unified = $this->buildUnifiedServer($serverInfo, $cdn, $dbInfo, $nodeInfo, $pythonInfo);
                $onSection('server', $unified);
            }
        } elseif ($needHtml) {
            // Even if HTML failed to load, try to detect the server from headers (may come from a redirect)
            if (!empty($this->httpHeaders)) {
                $serverInfo = $this->detectWebServer($this->httpHeaders, $cms, $frameworks);
            } else {
                $serverInfo = ['name' => 'невідомо', 'version' => null, 'raw' => null, 'powered_by' => null, 'security_headers' => [], 'note' => 'Server-заголовок відсутній'];
            }
            $cdn = null;
            $dbInfo = $this->detectDatabase($this->httpHeaders, $html, $cms, $frameworks, []);
            $nodeInfo = $this->detectNodeJs($this->httpHeaders, $html);
            $pythonInfo = $this->detectPython($this->httpHeaders, $html, $frameworks);
            $unified = $this->buildUnifiedServer($serverInfo, $cdn, $dbInfo, $nodeInfo, $pythonInfo);
            if ($want('server')) {
                $onSection('server', $unified);
            }
        }

        // PageSpeed Insights (Google) — a separate block, PSI scores only.
        // Slow (Lighthouse takes 10–60s per strategy), so the frontend
        // requests it via a separate parallel stream (only=pagespeed).
        if ($want('pagespeed')) {
            $pagespeed = $this->detectPageSpeed();
            if ($pagespeed !== null) {
                $onSection('pagespeed', $pagespeed);
            }
        }
    }

    /**
     * Google PageSpeed Insights API key (optional, but recommended).
     * Without a key the quota is low (~100 requests/day per IP); with a key — ~25,000/day for free.
     * Set via `config.php` (recommended), env `PAGESPEED_API_KEY`
     * or the `PAGESPEED_API_KEY` constant.
     * NOTE: in Google Cloud Console the key must have
     * Application restrictions = None (requests go from the server without Referer —
     * a "Websites / HTTP referrers" restriction produces a
     * "Requests from referer <empty> are blocked" error).
     */
    private function getPageSpeedApiKey(): ?string
    {
        $env = getenv('PAGESPEED_API_KEY');
        if (is_string($env) && trim($env) !== '') {
            return trim($env);
        }
        if (!empty($_ENV['PAGESPEED_API_KEY']) && is_string($_ENV['PAGESPEED_API_KEY'])) {
            $v = trim($_ENV['PAGESPEED_API_KEY']);
            if ($v !== '') {
                return $v;
            }
        }
        if (defined('PAGESPEED_API_KEY') && is_string(constant('PAGESPEED_API_KEY'))) {
            $v = trim((string)constant('PAGESPEED_API_KEY'));
            if ($v !== '') {
                return $v;
            }
        }
        return null;
    }

    /**
     * Separate PageSpeed block — Google PageSpeed Insights (Lighthouse) scores only.
     * Returns two strategies side by side for comparison: `mobile` and `desktop`.
     * Each: category scores (0–100), key lab metrics (FCP/LCP/TBT/CLS/SI/TTI)
     * and a field (CrUX, if present). On strategy failure its array contains
     * `error`, so the card shows the reason instead of disappearing.
     *
     * @return array<string, mixed>|null
     */
    private function detectPageSpeed(): ?array
    {
        $target = $this->url !== '' ? $this->url : 'https://' . $this->domain . '/';
        $key = $this->getPageSpeedApiKey();

        $urls = [
            'mobile' => $this->buildPageSpeedApiUrl($target, 'mobile', $key),
            'desktop' => $this->buildPageSpeedApiUrl($target, 'desktop', $key),
        ];
        $fetched = $this->fetchPageSpeedMulti($urls, 70);

        // A key restricted to "Websites / HTTP referrers" rejects server requests
        // (without Referer): "Requests from referer <empty> are blocked".
        // Blocked strategies are retried WITHOUT a key (low quota, but the block will show data).
        $usedFallback = false;
        if ($key !== null) {
            foreach (['mobile', 'desktop'] as $strategy) {
                $one = $fetched[$strategy] ?? null;
                if ($one !== null && $this->isKeyBlockedResponse($one[0], $one[1])) {
                    $retry = $this->fetchPageSpeedBody(
                        $this->buildPageSpeedApiUrl($target, $strategy, null),
                        70
                    );
                    if ($retry !== null) {
                        $fetched[$strategy] = $retry;
                        $usedFallback = true;
                    }
                }
            }
        }

        $mobile = $this->parsePageSpeedResponse($target, 'mobile', $fetched['mobile'] ?? null, $key, $usedFallback);
        $desktop = $this->parsePageSpeedResponse($target, 'desktop', $fetched['desktop'] ?? null, $key, $usedFallback);

        $fetchTime = $mobile['fetch_time'] ?? null;
        if ($fetchTime === null) {
            $fetchTime = $desktop['fetch_time'] ?? null;
        }

        return [
            'tested_url' => $mobile['tested_url'] ?? $desktop['tested_url'] ?? $target,
            'fetch_time' => $fetchTime,
            'mobile' => $mobile,
            'desktop' => $desktop,
            'key_fallback' => $usedFallback,
        ];
    }

    private function buildPageSpeedApiUrl(string $target, string $strategy, ?string $key): string
    {
        $api = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed'
            . '?url=' . urlencode($target)
            . '&strategy=' . urlencode($strategy)
            . '&category=performance'
            . '&category=accessibility'
            . '&category=best-practices'
            . '&category=seo';
        if ($key !== null && $key !== '') {
            $api .= '&key=' . urlencode($key);
        }
        return $api;
    }

    /**
     * Whether a PSI response means a blocked key (referer restrictions, etc.).
     */
    private function isKeyBlockedResponse(int $httpCode, string $body): bool
    {
        if ($httpCode !== 400 && $httpCode !== 403) {
            return false;
        }
        $data = json_decode($body, true);
        $msg = is_array($data) ? (string)($data['error']['message'] ?? '') : '';
        $reason = is_array($data)
            ? (string)(($data['error']['errors'][0]['reason'] ?? '') . ' ' . ($data['error']['status'] ?? ''))
            : '';
        $hay = strtolower($msg . ' ' . $reason);
        return str_contains($hay, 'referer')
            || str_contains($hay, 'blocked')
            || str_contains($hay, 'keyinvalid')
            || str_contains($hay, 'api_key_http_referrer_blocked')
            || str_contains($hay, 'permission_denied');
    }

    /**
     * Parse one PSI response into a strategy structure.
     *
     * @param array{0: int, 1: string}|null $fetched
     * @return array<string, mixed>
     */
    private function parsePageSpeedResponse(string $target, string $strategy, ?array $fetched, ?string $key, bool $usedFallback): array
    {
        if ($fetched === null) {
            return [
                'strategy' => $strategy,
                'tested_url' => $target,
                'error' => 'PageSpeed API не відповіла (таймаут 70 с). Спробуйте оновити пізніше.',
            ];
        }
        [$httpCode, $body] = $fetched;
        $data = json_decode((string)$body, true);
        if (!is_array($data)) {
            return [
                'strategy' => $strategy,
                'tested_url' => $target,
                'error' => 'PageSpeed API повернула некоректну відповідь (HTTP ' . $httpCode . ').',
            ];
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            $msg = $data['error']['message'] ?? ('HTTP ' . $httpCode);
            // Friendly messages for typical quota/analysis errors
            if (str_contains(strtolower((string)$msg), 'quota') || $httpCode === 429) {
                if ($usedFallback) {
                    $msg = 'Ключ PageSpeed API заблоковано за referer, а безключова квота сервера вичерпана. '
                        . 'У Google Cloud Console → Credentials → ваш ключ встановіть Application restrictions = None '
                        . '(API restrictions = PageSpeed Insights API), зачекайте 1–2 хв і оновіть.';
                } elseif ($key !== null) {
                    $msg = 'Перевищено квоту ключа PageSpeed API. Спробуйте пізніше.';
                } else {
                    $msg = 'Перевищено безключову квоту PageSpeed API. Додайте ключ PAGESPEED_API_KEY (config.php) або спробуйте пізніше.';
                }
            } elseif (str_contains(strtolower((string)$msg), 'referer')
                || str_contains(strtolower((string)$msg), 'blocked')
            ) {
                $msg = 'Ключ PageSpeed API обмежено HTTP-referrer’ами, а серверні запити йдуть без Referer. '
                    . 'У Google Cloud Console → Credentials → ваш ключ встановіть Application restrictions = None '
                    . '(API restrictions = PageSpeed Insights API). Оригінал: ' . $msg;
            } elseif (str_contains(strtolower((string)$msg), 'lighthouse')) {
                $msg = 'Lighthouse не зміг проаналізувати сторінку: ' . $msg;
            }
            return [
                'strategy' => $strategy,
                'tested_url' => $target,
                'error' => $msg,
            ];
        }

        $lh = $data['lighthouseResult'] ?? [];
        $cats = $lh['categories'] ?? [];
        $audits = $lh['audits'] ?? [];
        $loadingExp = $data['loadingExperience'] ?? null;

        $score = static function (array $cats, string $id): ?int {
            $s = $cats[$id]['score'] ?? null;
            return is_numeric($s) ? (int)round((float)$s * 100) : null;
        };

        $metric = static function (array $audits, string $id): ?array {
            $a = $audits[$id] ?? null;
            if (!is_array($a)) {
                return null;
            }
            $num = $a['numericValue'] ?? null;
            $display = $a['displayValue'] ?? null;
            if ($num === null && $display === null) {
                return null;
            }
            return [
                'value' => is_numeric($num) ? (float)$num : null,
                'display' => is_string($display) ? $display : null,
            ];
        };

        $fieldMetrics = null;
        $fieldCategory = null;
        if (is_array($loadingExp)) {
            $fieldCategory = $loadingExp['overall_category'] ?? null;
            $m = $loadingExp['metrics'] ?? [];
            $pick = static function (array $m, string $id): ?array {
                $e = $m[$id] ?? null;
                if (!is_array($e)) {
                    return null;
                }
                return [
                    'percentile' => $e['percentile'] ?? null,
                    'category' => $e['category'] ?? null,
                ];
            };
            $fieldMetrics = [
                'FCP' => $pick($m, 'FIRST_CONTENTFUL_PAINT_MS'),
                'LCP' => $pick($m, 'LARGEST_CONTENTFUL_PAINT_MS'),
                'CLS' => $pick($m, 'CUMULATIVE_LAYOUT_SHIFT_SCORE'),
                'INP' => $pick($m, 'INTERACTION_TO_NEXT_PAINT'),
            ];
            $fieldMetrics = array_filter($fieldMetrics, static fn($v) => $v !== null);
            if (empty($fieldMetrics)) {
                $fieldMetrics = null;
            }
        }

        $result = [
            'strategy' => $strategy,
            'tested_url' => $lh['finalUrl'] ?? $target,
            'fetch_time' => $data['analysisUTCTimestamp'] ?? ($lh['fetchTime'] ?? null),
            'performance' => $score($cats, 'performance'),
            'accessibility' => $score($cats, 'accessibility'),
            'best_practices' => $score($cats, 'best-practices'),
            'seo' => $score($cats, 'seo'),
            'metrics' => array_filter([
                'FCP' => $metric($audits, 'first-contentful-paint'),
                'LCP' => $metric($audits, 'largest-contentful-paint'),
                'TBT' => $metric($audits, 'total-blocking-time'),
                'CLS' => $metric($audits, 'cumulative-layout-shift'),
                'SI' => $metric($audits, 'speed-index'),
                'TTI' => $metric($audits, 'interactive'),
            ], static fn($v) => $v !== null),
            'field_category' => $fieldCategory,
            'field_metrics' => $fieldMetrics,
        ];

        // If there are no scores at all — treat the response as empty
        if ($result['performance'] === null && $result['accessibility'] === null
            && $result['seo'] === null && empty($result['metrics'])) {
            return [
                'strategy' => $strategy,
                'tested_url' => $target,
                'error' => 'PageSpeed API повернула порожній результат для цієї сторінки.',
            ];
        }

        return $result;
    }

    /**
     * Parallel requests to the PageSpeed API (mobile + desktop at once via curl_multi).
     * Without cURL — sequentially via fetchPageSpeedBody.
     *
     * @param array<string, string> $urls ['mobile' => url, 'desktop' => url]
     * @return array<string, array{0: int, 1: string}|null>
     */
    private function fetchPageSpeedMulti(array $urls, int $timeout = 70): array
    {
        $out = ['mobile' => null, 'desktop' => null];
        if (!function_exists('curl_multi_init')) {
            foreach ($urls as $strategy => $url) {
                $out[$strategy] = $this->fetchPageSpeedBody($url, $timeout);
            }
            return $out;
        }

        $mh = curl_multi_init();
        $handles = [];
        foreach ($urls as $strategy => $url) {
            $ch = curl_init($url);
            if ($ch === false) {
                continue;
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_USERAGENT => 'MP-Site-Detect/pagespeed',
                CURLOPT_ENCODING => '',
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$strategy] = $ch;
        }

        if (empty($handles)) {
            curl_multi_close($mh);
            return $out;
        }

        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running > 0) {
                curl_multi_select($mh, 1.0);
            }
        } while ($running > 0 && $status === CURLM_OK);

        foreach ($handles as $strategy => $ch) {
            $body = curl_multi_getcontent($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_multi_remove_handle($mh, $ch);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            $out[$strategy] = ($body === false || $body === '') ? null : [$code, (string)$body];
        }
        curl_multi_close($mh);
        return $out;
    }

    /**
     * HTTP request to the PageSpeed API with an extended timeout (Lighthouse thinks for 10–60s).
     *
     * @return array{0: int, 1: string}|null [http_code, body]
     */
    private function fetchPageSpeedBody(string $apiUrl, int $timeout = 70): ?array
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($apiUrl);
            if ($ch === false) {
                return null;
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_USERAGENT => 'MP-Site-Detect/pagespeed',
                CURLOPT_ENCODING => '',
            ]);
            $body = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            if ($body === false || $body === '') {
                return null;
            }
            return [$code, (string)$body];
        }

        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeout,
                'header' => "User-Agent: MP-Site-Detect/pagespeed\r\nAccept: application/json\r\n",
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $body = @file_get_contents($apiUrl, false, $ctx);
        if ($body === false || $body === '') {
            return null;
        }
        $code = 200;
        $headers = $this->captureHeaders();
        foreach ($headers as $h) {
            if (preg_match('~^HTTP/\S+\s+(\d{3})~i', $h, $m)) {
                $code = (int)$m[1];
            }
        }
        return [$code, (string)$body];
    }

    /**
     * Formats an error_reporting() value into a human-readable string.
     */
    private function formatErrorReporting(int $level): string
    {
        if ($level === 0) {
            return 'вимкнено (E_NONE)';
        }

        $map = [
            E_ERROR => 'E_ERROR',
            E_WARNING => 'E_WARNING',
            E_PARSE => 'E_PARSE',
            E_NOTICE => 'E_NOTICE',
            E_CORE_ERROR => 'E_CORE_ERROR',
            E_CORE_WARNING => 'E_CORE_WARNING',
            E_COMPILE_ERROR => 'E_COMPILE_ERROR',
            E_COMPILE_WARNING => 'E_COMPILE_WARNING',
            E_USER_ERROR => 'E_USER_ERROR',
            E_USER_WARNING => 'E_USER_WARNING',
            E_USER_NOTICE => 'E_USER_NOTICE',
            E_RECOVERABLE_ERROR => 'E_RECOVERABLE_ERROR',
            E_DEPRECATED => 'E_DEPRECATED',
            E_USER_DEPRECATED => 'E_USER_DEPRECATED',
        ];
        // E_STRICT is deprecated since PHP 8.4 — check the version to avoid triggering
        // a deprecation notice on newer versions.
        if (PHP_VERSION_ID < 80400 && defined('E_STRICT')) {
            $map[E_STRICT] = 'E_STRICT';
        }

        $names = [];
        foreach ($map as $bit => $name) {
            if ($bit === 0) {
                continue;
            }
            if (($level & $bit) === $bit) {
                $names[] = $name;
            }
        }
        return $names ? implode(' | ', $names) : (string)$level;
    }

    private function resolveIp(string $domain): ?string
    {
        $records = @dns_get_record($domain, DNS_A);
        if (!empty($records[0]['ip'])) {
            return $records[0]['ip'];
        }

        $ip = @gethostbyname($domain);
        if ($ip && $ip !== $domain && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return null;
    }

    private function lookupGeo(string $ip): ?array
    {
        $url = 'http://ip-api.com/json/' . urlencode($ip)
            . '?lang=uk&fields=status,message,country,regionName,city,district,zip,lat,lon,timezone,isp,org,as,query,reverse,hosting';

        $body = $this->httpGet($url, 8);
        if ($body === null) {
            return null;
        }

        $data = json_decode($body, true);
        if (!is_array($data) || ($data['status'] ?? '') !== 'success') {
            return null;
        }

        $location = [
            'Країна' => $data['country'] ?? null,
            'Регіон' => $data['regionName'] ?? null,
            'Місто' => $data['city'] ?? null,
            'Район' => $data['district'] ?? null,
            'Поштовий індекс' => $data['zip'] ?? null,
            'Часовий пояс' => $data['timezone'] ?? null,
            'Координати' => (isset($data['lat'], $data['lon']))
                ? sprintf('%.4f, %.4f', $data['lat'], $data['lon'])
                : null,
            'Зворотний DNS' => $data['reverse'] ?? null,
        ];

        $hosting = [
            'Провайдер (ISP)' => $data['isp'] ?? null,
            'Організація' => $data['org'] ?? null,
            'AS' => $data['as'] ?? null,
            'Хостинг' => !empty($data['hosting']) ? 'Так (дата-центр)' : 'Ні (можливо, корпоративний)',
        ];

        return [
            'location' => $this->cleanFields($location),
            'hosting' => $this->cleanFields($hosting),
        ];
    }

    private function lookupWhois(string $domain): ?array
    {
        $url = 'https://who-dat.as93.net/' . urlencode($domain);
        $body = $this->httpGet($url, 12);
        $data = null;
        if ($body !== null) {
            $data = json_decode($body, true);
        }

        // If the RDAP response is valid — parse it (main path)
        if (is_array($data) && !isset($data['error'])) {
            $domainName = is_string($data['domain'] ?? null) ? $data['domain'] : $domain;
            if (!empty($data['isRegistered']) && $data['isRegistered'] === false) {
                return [
                    'Домен' => $domainName,
                    'Статус' => 'Домен не зареєстрований',
                ];
            }
            // If registrar/date data is present — return the result
            if (!empty($data['registrar']) || !empty($data['dates'])) {
                $registrar = $data['registrar'] ?? [];
                $dates = $data['dates'] ?? [];

                $nameservers = $data['nameservers'] ?? [];
                $status = $data['status'] ?? [];
                $nsList = [];
                if (is_array($nameservers)) {
                    foreach ($nameservers as $ns) {
                        if (is_string($ns)) {
                            $nsList[] = $ns;
                        } elseif (is_array($ns) && isset($ns['name'])) {
                            $nsList[] = $ns['name'];
                        }
                    }
                }
                if (!is_array($status)) {
                    $status = [$status];
                }

                $abuseEmail = $registrar['abuseEmail'] ?? $registrar['email'] ?? null;

                $whois = [
                    'Домен' => $domainName,
                    'Реєстратор' => $registrar['name'] ?? null,
                    'IANA ID' => isset($registrar['ianaId']) ? (string)$registrar['ianaId'] : null,
                    'URL реєстратора' => $registrar['url'] ?? null,
                    'Дата створення' => $this->formatDate($dates['created'] ?? null),
                    'Дата оновлення' => $this->formatDate($dates['updated'] ?? null),
                    'Дата закінчення' => $this->formatDate($dates['expires'] ?? null),
                    'DNSSEC' => isset($data['dnssec']['signed']) ? ($data['dnssec']['signed'] ? 'Так' : 'Ні') : null,
                    'Статуси домену' => !empty($status) ? implode(', ', $status) : null,
                    'DNS-сервери' => !empty($nsList) ? implode("\n", $nsList) : null,
                    'E-mail для скарг' => $this->formatEmails($abuseEmail),
                ];

                $cleaned = $this->cleanFields($whois);
                // If at least domain + one more field remain after cleanup — treat as valid
                if (count($cleaned) > 1) {
                    return $cleaned;
                }
            }
            // Otherwise — possibly a delegated-zone domain (.lviv.ua etc.) where hostmaster RDAP returns 501.
            // Try the TCP WHOIS fallback.
        }

        // Fallback 1: TCP WHOIS via whois.ua (automatically redirects to whois.lviv.ua / whois.uar.net)
        $fallback = $this->lookupWhoisViaTcp($domain);
        if ($fallback !== null) {
            return $fallback;
        }

        // Fallback 2: if RDAP returned an explicit error but TCP also failed — show
        // an informative block instead of hiding the section, so the user sees the reason.
        if (is_array($data) && isset($data['error'])) {
            $detail = $data['error']['detail'] ?? $data['error']['message'] ?? '';
            // For delegated zones rdap.hostmaster.ua often returns 501 — this does not mean WHOIS is missing
            return $this->cleanFields([
                'Домен' => $domain,
                'Примітка' => 'WHOIS через RDAP тимчасово недоступний для цієї зони (registry error 501). Спробуйте оновити пізніше — дані буде отримано через резервний WHOIS.',
                'Деталі' => $detail ?: null,
            ]);
        }

        // If the primary HTTP request got no response at all — try TCP once more, and if it is also empty — return null
        // (the section will not be shown, but this is an edge case where the network is unreachable).
        return null;
    }

    /**
     * Backup WHOIS via TCP (port 43) for delegated .ua zones (lviv.ua, kharkiv.ua, etc.).
     * Uses whois.ua, which automatically redirects to whois.lviv.ua / whois.uar.net.
     */
    private function lookupWhoisViaTcp(string $domain): ?array
    {
        // Try several servers in turn — parse the first successful result
        $servers = ['whois.ua', 'whois.uar.net'];
        foreach ($servers as $server) {
            $raw = $this->whoisTcpQuery($domain, $server, 6);
            if ($raw === null || $raw === '') {
                continue;
            }
            $parsed = $this->parseWhoisTcp($raw, $domain);
            if ($parsed !== null && count($parsed) > 1) {
                return $parsed;
            }
        }
        return null;
    }

    /**
     * Performs a TCP query to a WHOIS server.
     */
    private function whoisTcpQuery(string $domain, string $server, int $timeout = 5): ?string
    {
        $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);
        if ($fp === false || $fp === null) {
            return null;
        }
        // Read timeout
        @stream_set_timeout($fp, $timeout);
        @fwrite($fp, $domain . "\r\n");
        $out = '';
        while (!feof($fp)) {
            $chunk = @fgets($fp, 4096);
            if ($chunk === false) {
                break;
            }
            $out .= $chunk;
        }
        @fclose($fp);
        return $out !== '' ? $out : null;
    }

    /**
     * Parses raw WHOIS text (UARNet / whois.ua redirect format) into a display structure.
     */
    private function parseWhoisTcp(string $raw, string $domain): ?array
    {
        // Filter out "No match" / domain-not-found cases
        $lower = strtolower($raw);
        if (str_contains($lower, 'no match') || str_contains($lower, 'no entries found') || str_contains($lower, 'not found') && str_contains($lower, 'no data')) {
            // Check that this is really a domain-missing message, not just a "status: not found"
            if (preg_match('~no match for|no entries found for|domain not found~i', $raw)) {
                return [
                    'Домен' => $domain,
                    'Статус' => 'Домен не зареєстрований',
                ];
            }
        }
        // For UARNet the format differs: "Domain Name:", "Registrar:", "Creation Date:" etc.
        // Also support the hostmaster.ua "% Domain:" / "domain:" format.
        $map = [
            'Домен' => ['Domain Name', 'domain'],
            'Реєстратор' => ['Registrar', 'registrar'],
            'URL реєстратора' => ['Registrar URL', 'Registrar Address', 'registrar url'],
            'Дата створення' => ['Creation Date', 'Created On', 'Registered on', 'Created'],
            'Дата оновлення' => ['Updated Date', 'Last Updated On', 'Modified'],
            'Дата закінчення' => ['Registry Expiry Date', 'Expiration Date', 'Expir', 'Expires'],
            'Статуси домену' => ['Domain Status', 'status'],
            'E-mail для скарг' => ['Registrar Abuse Contact Email', 'Registrar Abuse Email', 'abuse email'],
        ];

        $result = ['Домен' => $domain];
        $nsList = [];
        $statusList = [];

        // Split into lines and parse "Key: value"
        $lines = preg_split('/\r\n|\n|\r/', $raw);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '%' || $line[0] === '#') {
                continue;
            }
            $colonPos = strpos($line, ':');
            if ($colonPos === false) {
                continue;
            }
            $key = trim(substr($line, 0, $colonPos));
            $value = trim(substr($line, $colonPos + 1));
            if ($value === '' || $value === '-') {
                continue;
            }
            $keyLower = strtolower($key);

            // DNS servers — there may be several "Name Server:" / "nserver:" / "nameserver" lines
            if (in_array($keyLower, ['name server', 'nserver', 'nameserver', 'name servers'], true)) {
                // Value may be "dns1.hostiq.ua" or "dns1.hostiq.ua 185.68.16.16"
                $ns = preg_split('/\s+/', $value)[0];
                $ns = strtolower(trim($ns));
                if ($ns !== '' && filter_var($ns, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $nsList[] = $ns;
                } elseif ($ns !== '') {
                    $nsList[] = $ns;
                }
                continue;
            }
            if ($keyLower === 'domain status' || $keyLower === 'status') {
                // "ok https://icann.org/epp#ok" format — take the first word
                $statusList[] = $value;
                continue;
            }

            foreach ($map as $uaKey => $aliases) {
                foreach ($aliases as $alias) {
                    if (strtolower($alias) === $keyLower) {
                        // Do not overwrite if already set
                        if (!isset($result[$uaKey]) || $result[$uaKey] === null) {
                            // Format dates
                            if (str_contains($uaKey, 'Дата')) {
                                $result[$uaKey] = $this->formatDate($value);
                            } else {
                                $result[$uaKey] = $value;
                            }
                        }
                        break 2;
                    }
                }
            }
        }

        if (!empty($nsList)) {
            $result['DNS-сервери'] = implode("\n", array_unique($nsList));
        }
        if (!empty($statusList)) {
            // Normalize statuses: "ok https://..." -> "ok"
            $norm = array_map(static fn($s) => trim(explode(' ', $s)[0]), $statusList);
            $result['Статуси домену'] = implode(', ', array_unique($norm));
        }

        // If at least the registrar or dates could be extracted — treat as valid
        $hasData = isset($result['Реєстратор']) || isset($result['Дата створення']) || isset($result['Дата закінчення']) || isset($result['DNS-сервери']);
        if (!$hasData) {
            return null;
        }

        // Add a source note for delegated zones
        // Do not add it as a separate field to avoid clutter, but it can stay for debugging
        return $this->cleanFields($result);
    }

    private function fetchHtml(): ?string
    {
        if ($this->html !== null) {
            return $this->html;
        }

        $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        $acceptLang = 'uk,en;q=0.9';

        // First try cURL — it returns headers more reliably
        // ($http_response_header on some hosts gets emptied after
        // several consecutive file_get_contents calls — e.g. when DNS-WHOIS,
        // ip-api, then HTML are called. cURL is isolated per request).
        if (function_exists('curl_init')) {
            $result = $this->fetchWithCurl($this->url, $userAgent, $acceptLang, 15);
            if ($result === null) {
                $fallback = 'http://' . $this->domain . '/';
                if ($fallback !== $this->url) {
                    $result = $this->fetchWithCurl($fallback, $userAgent, $acceptLang, 10);
                    if ($result !== null) {
                        $this->url = $fallback;
                    }
                }
            }
            if ($result !== null) {
                $this->httpHeaders = $result['headers'];
                $this->html = $result['body'];
                return $this->html;
            }
            return null;
        }

        // Fallback via file_get_contents (if cURL is unavailable)
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 15,
                'header' => "User-Agent: $userAgent\r\n"
                    . "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    . "Accept-Language: $acceptLang\r\n",
                'follow_location' => 1,
                'max_redirects' => 5,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $html = @file_get_contents($this->url, false, $ctx);
        if ($html === false) {
            $fallback = 'http://' . $this->domain . '/';
            if ($fallback !== $this->url) {
                $html = @file_get_contents($fallback, false, $ctx);
                if ($html !== false) {
                    $this->url = $fallback;
                }
            }
        }

        if ($html === false) {
            return null;
        }

        $this->httpHeaders = $this->captureHeaders();
        $this->html = $html;
        return $this->html;
    }

    /**
     * Load a page via cURL.
     * Returns an array ['headers' => [...], 'body' => '...'] or null on failure.
     *
     * @return array{headers: string[], body: string}|null
     */
    private function fetchWithCurl(string $url, string $userAgent, string $acceptLang, int $timeout): ?array
    {
        $ch = curl_init();
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,           // return headers in the response body
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => $userAgent,
            CURLOPT_HTTPHEADER => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: ' . $acceptLang,
            ],
            CURLOPT_ENCODING => '',          // gzip/deflate support
        ]);
        $response = curl_exec($ch);
        if ($response === false) {
            // PHP 8.0+ does not need curl_close (no-op), but call it for compatibility
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            return null;
        }
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        // Negotiated protocol version of the final response (a real fact about the stack).
        $protoNum = (int)curl_getinfo($ch, CURLINFO_HTTP_VERSION);
        $this->httpVersion = match (true) {
            $protoNum === (int)CURL_HTTP_VERSION_1_0 => 'HTTP/1.0',
            $protoNum === (int)CURL_HTTP_VERSION_1_1 => 'HTTP/1.1',
            in_array($protoNum, [(int)CURL_HTTP_VERSION_2_0, (int)CURL_HTTP_VERSION_2TLS, (int)CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE], true) => 'HTTP/2',
            defined('CURL_HTTP_VERSION_3') && $protoNum === (int)CURL_HTTP_VERSION_3 => 'HTTP/3',
            default => null,
        };
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }

        $rawHeaders = substr((string)$response, 0, (int)$headerSize);
        $body = substr((string)$response, (int)$headerSize);

        // With FOLLOWLOCATION cURL concatenates headers of ALL responses in the
        // redirect chain. Only the FINAL response headers are needed for analysis —
        // otherwise Server/X-Powered-By from an intermediate 301/302 (often a different server)
        // would overwrite the real ones. Split into blocks by status lines and take the last one.
        $headers = $this->parseLastResponseHeaders($rawHeaders);
        return ['headers' => $headers, 'body' => $body];
    }

    /**
     * Extract headers of the last response from a raw cURL block
     * (multiple "HTTP/1.1 301 ..." + headers on redirects).
     *
     * @return string[]
     */
    private function parseLastResponseHeaders(string $raw): array
    {
        $blocks = preg_split('~(?=^HTTP/\d(?:\.\d)?\s+\d{3}\b)~mi', $raw);
        if (is_array($blocks) && count($blocks) > 1) {
            $raw = (string)end($blocks);
        }
        return $this->parseRawHeaders($raw);
    }

    /**
     * Parser for raw HTTP headers ("Name: value\r\n" format) into an array of strings.
     *
     * @return string[]
     */
    private function parseRawHeaders(string $raw): array
    {
        $lines = preg_split('/\r\n|\n|\r/', $raw);
        $result = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || stripos($line, 'HTTP/') === 0) {
                continue;
            }
            if (str_contains($line, ':')) {
                $result[] = $line;
            }
        }
        return $result;
    }

    private function detectCms(string $html, ?string $generator): array
    {
        $candidates = $this->signatures['cms'] ?? [];
        $lower = strtolower($html);
        // Strip noise (base64 blobs, embedded fonts/images) so that short
        // signals like "modx" / "sqsp" / "aspx" do not match inside them.
        // Wappalyzer looks for signals in tags/attributes, not in raw text.
        $cleanLower = strtolower($this->stripNoiseForDetection($html));

        $scored = [];
        foreach ($candidates as $name => $info) {
            $strongHits = 0;
            $weakHits = 0;
            $hasGenerator = false;

            if ($generator) {
                $gen = strtolower($generator);
                foreach ($info['generators'] ?? [] as $g) {
                    if (str_contains($gen, strtolower($g))) {
                        $hasGenerator = true;
                        break;
                    }
                }
            }

            foreach ($info['strong'] ?? [] as $sign) {
                if ($this->preciseSignMatch($html, $lower, $cleanLower, (string)$sign)) {
                    $strongHits++;
                }
            }
            foreach ($info['weak'] ?? [] as $sign) {
                if ($this->preciseSignMatch($html, $lower, $cleanLower, (string)$sign)) {
                    $weakHits++;
                }
            }
            // Backward compatibility with the old 'signs' format: URL-like → strong, rest → weak.
            foreach ($info['signs'] ?? [] as $sign) {
                $s = strtolower((string)$sign);
                $isUrlLike = (str_contains($s, '/') || str_contains($s, '.') || str_contains($s, ':') || str_contains($s, '='))
                    && strlen($s) >= 5;
                if (!$this->preciseSignMatch($html, $lower, $cleanLower, (string)$sign)) {
                    continue;
                }
                if ($isUrlLike) {
                    $strongHits++;
                } else {
                    $weakHits++;
                }
            }

            // Threshold as in Wappalyzer: a generator, or 1 strong, or ≥2 weak.
            // A single weak signal (e.g. "sqsp" or "modx" somewhere in the text) is not enough.
            if (!$hasGenerator && $strongHits < 1 && $weakHits < 2) {
                continue;
            }

            $score = ($hasGenerator ? 10 : 0) + $strongHits * 3 + $weakHits;
            $scored[$name] = [
                'info' => $info,
                'score' => $score,
                'strong' => $strongHits,
                'weak' => $weakHits,
                'hasGenerator' => $hasGenerator,
            ];
        }

        if (empty($scored)) {
            return [];
        }

        // CMS mutual exclusion: two different CMSs almost never stand side by side.
        // If there is a CMS with authoritative proof (generator or ≥2 strong),
        // drop others that have only 1 strong without a generator.
        $hasAuthoritative = false;
        foreach ($scored as $s) {
            if ($s['hasGenerator'] || $s['strong'] >= 2) {
                $hasAuthoritative = true;
                break;
            }
        }
        if ($hasAuthoritative) {
            foreach ($scored as $name => $s) {
                if (!$s['hasGenerator'] && $s['strong'] < 1) {
                    unset($scored[$name]);
                }
            }
            // If several with 1 strong remain — keep only the best one.
            // (e.g. WordPress with /wp-content/ + /wp-includes/ beats MODX with 1 weak match)
            if (count($scored) > 1) {
                $maxScore = max(array_column($scored, 'score'));
                // Keep all with a generator, otherwise — only the top by score.
                $withGen = array_filter($scored, static fn($s) => $s['hasGenerator']);
                if (!empty($withGen)) {
                    $scored = $withGen;
                } else {
                    $scored = array_filter($scored, static fn($s) => $s['score'] >= $maxScore);
                    // On equal scores prefer the higher strong count.
                    if (count($scored) > 1) {
                        $maxStrong = max(array_column($scored, 'strong'));
                        $scored = array_filter($scored, static fn($s) => $s['strong'] >= $maxStrong);
                    }
                }
            }
        }

        $result = [];
        foreach ($scored as $name => $s) {
            $info = $s['info'];
            $result[] = [
                'name' => $name,
                'confidence' => $info['confidence'] ?? ($s['hasGenerator'] || $s['strong'] > 0 ? 'high' : 'medium'),
                'description' => $info['description'] ?? '',
                'site' => $info['site'] ?? null,
            ];
        }
        // Sort by score (most confident first).
        usort($result, static function ($a, $b) use ($scored) {
            return ($scored[$b['name']]['score'] ?? 0) <=> ($scored[$a['name']]['score'] ?? 0);
        });
        return $result;
    }

    /**
     * Removes noise for precise matching: data-URIs with base64 and long
     * spaceless base64 chains (embedded fonts/images in <style>/<script>).
     * Short signals "modx"/"sqsp"/"aspx" falsely matched inside them.
     */
    private function stripNoiseForDetection(string $html): string
    {
        $clean = preg_replace('~data:[a-z0-9/+;_=-]+;base64,[A-Za-z0-9+/=]{120,}~i', ' ', $html);
        if (!is_string($clean)) {
            $clean = $html;
        }
        $clean = preg_replace('~[A-Za-z0-9+/=]{300,}~', ' ', $clean);
        return is_string($clean) ? $clean : $html;
    }

    /**
     * Precise signal matching in the Wappalyzer style.
     * - URL/path-like (with "/" "." ":" "=" and length ≥5) — substring, but in cleaned
     *   HTML without base64 noise (base64 has no dots, so "squarespace.com" is impossible there).
     * - __VIEWSTATE — only as <input name="__VIEWSTATE"> (not a substring).
     * - ".aspx" — only with a dot and a word boundary (not "aspx" inside text).
     * - Bare words ("modx", "flask") — only with \b word boundaries on cleaned HTML.
     */
    private function preciseSignMatch(string $html, string $lower, string $cleanLower, string $sign): bool
    {
        $s = strtolower($sign);
        if ($s === '') {
            return false;
        }

        if ($s === '__viewstate') {
            return (bool)preg_match('~<input[^>]+name\s*=\s*["\']__VIEWSTATE["\']~i', $html);
        }

        if ($s === 'aspx') {
            // Require ".aspx" with a boundary — as in links/forms, not in base64.
            return (bool)preg_match('~\.aspx\b~i', $html);
        }

        $isUrlLike = (str_contains($s, '/') || str_contains($s, '.') || str_contains($s, ':') || str_contains($s, '='))
            && strlen($s) >= 5;
        if ($isUrlLike) {
            return str_contains($cleanLower, $s);
        }

        // Bare word: word boundaries on cleaned HTML.
        return (bool)preg_match('~\b' . preg_quote($sign, '~') . '\b~i', $cleanLower);
    }

    /**
     * Backup CMS check via direct requests when HTML is an anti-bot placeholder.
     * Returns an array in detectCms format or empty.
     */
    private function probeCmsViaEndpoints(): array
    {
        // Probe several characteristic WP endpoints
        $checks = [
            $this->url . '/wp-json/' => function(string $body): bool {
                if ($body === '') return false;
                $data = json_decode($body, true);
                if (!is_array($data)) return false;
                // Routes with wp/v2 present — a clear WP REST API sign
                if (!empty($data['routes']) && is_array($data['routes'])) {
                    foreach (array_keys($data['routes']) as $route) {
                        if (str_starts_with((string)$route, '/wp/')) return true;
                    }
                }
                if (!empty($data['namespaces']) && is_array($data['namespaces'])) {
                    foreach ($data['namespaces'] as $ns) {
                        if (str_contains((string)$ns, 'wp/v2')) return true;
                    }
                }
                return false;
            },
            $this->url . '/readme.html' => function(string $body): bool {
                return stripos($body, 'WordPress') !== false && stripos($body, 'Version') !== false;
            },
            $this->url . '/wp-login.php' => function(string $body): bool {
                // WP login page contains loginform
                return stripos($body, 'loginform') !== false || stripos($body, 'wp-submit') !== false;
            },
            $this->url . '/wp-includes/js/wp-emoji-release.min.js' => function(string $body): bool {
                // SPA sites (Angular/React) serve the homepage for any unknown path.
                // So check that this is really a JS file, not an HTML fallback, and that it contains twemoji.
                if (stripos($body, '<!DOCTYPE') !== false || stripos($body, '<html') !== false) {
                    return false;
                }
                return stripos($body, 'twemoji') !== false;
            },
        ];

        foreach ($checks as $url => $validator) {
            $body = $this->httpGet($url, 5);
            if ($body === null || $body === '') continue;
            // If this is a Hostia anti-bot placeholder — skip it (check the characteristic marker)
            if (stripos($body, 'hostia-antirobot') !== false || stripos($body, 'Я не Робот') !== false) {
                continue;
            }
            try {
                if ($validator($body)) {
                    return [[
                        'name' => 'WordPress',
                        'confidence' => 'medium',
                        'description' => 'Найпопулярніша CMS у світі з відкритим кодом.',
                        'site' => 'https://wordpress.org',
                    ]];
                }
            } catch (\Throwable $e) {
                continue;
            }
        }
        return [];
    }

    private function detectFrameworks(string $html, array $headers): array
    {
        $lower = strtolower($html);
        $cleanLower = strtolower($this->stripNoiseForDetection($html));
        $found = [];

        foreach ($this->signatures['frameworks'] as $name => $info) {
            $strongHits = 0;
            $weakHits = 0;
            $headerHit = false;

            foreach ($info['strong'] ?? [] as $sign) {
                if ($this->preciseSignMatch($html, $lower, $cleanLower, (string)$sign)) {
                    $strongHits++;
                    break;
                }
            }
            // Legacy 'signs': URL-like ones count as strong, bare words — as weak.
            foreach ($info['signs'] ?? [] as $sign) {
                $s = strtolower((string)$sign);
                // The "x-powered-by: ..." service marker is looked up in headers only, not in HTML.
                if (str_starts_with($s, 'x-powered-by:')) {
                    continue;
                }
                $isUrlLike = (str_contains($s, '/') || str_contains($s, '.') || str_contains($s, '='))
                    && strlen($s) >= 5;
                if (!$this->preciseSignMatch($html, $lower, $cleanLower, (string)$sign)) {
                    continue;
                }
                if ($isUrlLike) {
                    $strongHits++;
                    break;
                }
                $weakHits++;
            }
            foreach ($info['weak'] ?? [] as $sign) {
                if ($this->preciseSignMatch($html, $lower, $cleanLower, (string)$sign)) {
                    $weakHits++;
                }
            }
            foreach ($info['headers'] ?? [] as $h) {
                foreach ($headers as $header) {
                    if (stripos($header, $h) !== false) {
                        $headerHit = true;
                        break 2;
                    }
                }
            }

            // Threshold: a header or a strong signal, or ≥2 weak.
            // A single weak signal (e.g. "csrf-token", "aspx" in base64) is not enough.
            $matched = $headerHit || $strongHits >= 1 || $weakHits >= 2;
            if ($matched) {
                $found[$name] = $info;
            }
        }

        $result = [];
        foreach ($found as $name => $info) {
            $result[] = [
                'name' => $name,
                'type' => $info['type'] ?? 'framework',
                'description' => $info['description'] ?? '',
                'site' => $info['site'] ?? null,
            ];
        }
        return $result;
    }

    private function detectTechnologies(string $html, array $headers): array
    {
        $found = [];
        $lower = strtolower($html);
        $headersStr = strtolower(implode("\n", $headers));

        foreach ($this->signatures['technologies'] as $name => $info) {
            $matched = false;
            foreach ($info['signs'] ?? [] as $sign) {
                if (str_contains($lower, strtolower($sign))) {
                    $matched = true;
                    break;
                }
            }
            if (!$matched && !empty($info['headers'])) {
                foreach ($info['headers'] as $h) {
                    if (str_contains($headersStr, strtolower($h))) {
                        $matched = true;
                        break;
                    }
                }
            }
            if ($matched) {
                $found[$name] = $info;
            }
        }

        $result = [];
        foreach ($found as $name => $info) {
            $result[] = [
                'name' => $name,
                'category' => $info['category'] ?? 'Інше',
                'description' => $info['description'] ?? '',
            ];
        }
        return $result;
    }

    /**
     * CDN detection configuration.
     * Each entry: ['name' => ..., 'headers' => [...], 'server_match' => ..., 'via_match' => ..., 'html_signs' => [...]]
     */
    private const CDN_SIGNATURES = [
        'Cloudflare' => [
            'priority' => 1,
            'headers' => [
                ['name' => 'cf-ray', 'extract' => 'pop', 'sep' => '-'],
                ['name' => 'cf-cache-status', 'extract' => 'cache_status'],
            ],
            'server_match' => 'cloudflare',
            'html_signs' => ['cdn-cgi/', 'cloudflare.com/cdn', 'data-cfemail'],
        ],
        'Amazon CloudFront' => [
            'priority' => 2,
            'headers' => [
                ['name' => 'x-amz-cf-id', 'extract' => 'cf_id'],
                ['name' => 'x-cache', 'value_match' => 'cloudfront', 'extract' => 'cache_status'],
            ],
            'server_match' => 'cloudfront',
            'via_match' => 'cloudfront',
            'html_signs' => ['cloudfront.net'],
        ],
        'Fastly' => [
            'priority' => 3,
            'headers' => [
                ['name' => 'x-served-by', 'extract' => 'served_by'],
                ['name' => 'x-fastly-request-id', 'extract' => 'request_id'],
            ],
            'html_signs' => ['fastly.net', 'fastly-insights'],
        ],
        'Akamai' => [
            'priority' => 4,
            'headers' => [
                ['name' => 'x-akamai-', 'match_prefix' => true],
            ],
            'server_match' => 'akamai',
            'html_signs' => ['akamaihd.net', 'akamaiedge.net', 'edgesuite.net', 'akamai.net'],
        ],
        'QUIC.cloud' => [
            'priority' => 5,
            'headers' => [
                ['name' => 'x-quic', 'match_prefix' => true],
                ['name' => 'x-litespeed-cache', 'extract' => 'cache_status'],
                ['name' => 'x-litespeed-tag', 'extract' => 'tag'],
            ],
            'via_match' => 'quic.cloud',
            'html_signs' => ['quic.cloud', 'quic-p.com'],
        ],
        'BunnyCDN' => [
            'priority' => 6,
            'headers' => [
                ['name' => 'x-bunny-origin-id', 'extract' => 'origin_id'],
                ['name' => 'x-bunny-region', 'extract' => 'region'],
            ],
            'server_match' => 'bunnycdn',
            'html_signs' => ['bunny.net', 'b-cdn.net'],
        ],
        'KeyCDN' => [
            'priority' => 7,
            'headers' => [],
            'server_match' => 'keycdn-engine',
            'html_signs' => ['kxcdn.com'],
        ],
        'Sucuri CloudProxy' => [
            'priority' => 8,
            'headers' => [
                ['name' => 'x-sucuri-id', 'extract' => 'sucuri_id'],
                ['name' => 'x-sucuri-cache', 'extract' => 'cache_status'],
            ],
            'server_match' => 'sucuri',
            'html_signs' => ['sucuri-script', 'cloudproxy'],
        ],
        'StackPath / NetDNA' => [
            'priority' => 9,
            'headers' => [],
            'server_match' => 'netdna',
            'html_signs' => ['stackpath', 'netdna', 'stackpathcdn'],
        ],
        'Imperva Incapsula' => [
            'priority' => 10,
            'headers' => [
                ['name' => 'x-iinfo', 'extract' => 'iinfo'],
            ],
            'html_signs' => ['imperva', 'incapsula'],
        ],
        'Varnish (cache)' => [
            'priority' => 11,
            'headers' => [
                ['name' => 'x-varnish', 'extract' => 'varnish_id'],
                ['name' => 'via', 'value_match' => 'varnish', 'extract' => 'via'],
            ],
            'html_signs' => [],
        ],
    ];

    /**
     * Web server detection from HTTP headers.
     *
     * Returns a structure:
     *   [
     *     'name'             => string  — name (nginx, Apache, LiteSpeed, IIS, Caddy, cloudflare, etc.)
     *     'version'          => string|null  — version, if disclosed
     *     'powered_by'       => string|null  — X-Powered-By
     *     'security_headers' => array        — X-Frame-Options, HSTS, CSP, etc.
     *     'note'             => string|null  — explanation if the server is hidden
     *     'raw'              => string|null  — raw Server header value
     *     'server_modules'   => array        — secondary tokens from Server (OpenSSL/PHP …)
     *     'via'/'x_server'   => string|null  — proxy/backend evidence
     *     'php_present'      => bool         — whether PHP is definitely present (headers/cookies/CMS inference)
     *     'php_source'       => string|null  — source of the PHP conclusion
     *   ]
     */
    private function detectWebServer(array $headers, array $cms = [], array $frameworks = []): array
    {
        $result = [
            'name' => 'невідомо',
            'version' => null,
            'powered_by' => null,
            'php_version' => null,
            'php_version_source' => null,
            'php_present' => false,
            'php_source' => null,
            'server_modules' => [],
            'security_headers' => [],
            'note' => null,
            'raw' => null,
        ];

        $rawPoweredBy = null;
        $serverMatched = false;
        $rawVia = null;
        $rawXServer = null;

        foreach ($headers as $h) {
            $colon = strpos($h, ':');
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($h, 0, $colon)));
            $value = trim(substr($h, $colon + 1));

            switch ($name) {
                case 'server':
                    // On a redirect chain take the LAST Server value
                    // (the final server, not an intermediate 301 redirect).
                    $result['raw'] = $value;
                    $parsed = $this->parseServerHeader($value);
                    if ($parsed !== null) {
                        $result['name'] = $parsed['name'];
                        $result['version'] = $parsed['version'];
                        if (!empty($parsed['extras'])) {
                            $result['server_modules'] = $parsed['extras'];
                        }
                        $serverMatched = true;
                    } else {
                        // Unknown format — still show as is
                        $result['name'] = $value !== '' ? $value : 'невідомо';
                        $serverMatched = $value !== '';
                    }
                    break;
                case 'via':
                    $rawVia = $value;
                    break;
                case 'x-powered-by':
                    $rawPoweredBy = $value;
                    $result['powered_by'] = $value;
                    break;
                case 'x-server':
                case 'x-backend-server':
                case 'x-served-by':
                    // Extra hint when Server is hidden (Varnish/Fastly, load balancers).
                    if ($rawXServer === null && $value !== '') {
                        $rawXServer = $name . ': ' . $value;
                    }
                    break;
                case 'x-frame-options':
                    $result['security_headers']['X-Frame-Options'] = $value;
                    break;
                case 'content-security-policy':
                    $result['security_headers']['Content-Security-Policy'] =
                        mb_strlen($value) > 100 ? mb_substr($value, 0, 100) . '…' : $value;
                    break;
                case 'strict-transport-security':
                    $result['security_headers']['Strict-Transport-Security'] = $value;
                    break;
                case 'x-content-type-options':
                    $result['security_headers']['X-Content-Type-Options'] = $value;
                    break;
                case 'referrer-policy':
                    $result['security_headers']['Referrer-Policy'] = $value;
                    break;
                case 'permissions-policy':
                    $result['security_headers']['Permissions-Policy'] =
                        mb_strlen($value) > 100 ? mb_substr($value, 0, 100) . '…' : $value;
                    break;
            }
        }

        if (!$serverMatched) {
            // Server header is missing. Try to detect via X-Powered-By
            // and other indirect signs.
            if ($rawPoweredBy !== null) {
                $lowerPb = strtolower($rawPoweredBy);
                if (str_contains($lowerPb, 'asp.net')) {
                    $result['name'] = 'IIS (ASP.NET)';
                    $result['note'] = 'Виявлено за X-Powered-By (Server-заголовок приховано)';
                } elseif (str_contains($lowerPb, 'express')) {
                    $result['name'] = 'Express (Node.js)';
                    $result['note'] = 'Виявлено за X-Powered-By (Server-заголовок приховано)';
                } elseif (str_contains($lowerPb, 'php')) {
                    $result['name'] = 'PHP-застосунок';
                    $result['note'] = 'Веб-сервер не ідентифіковано (Server-заголовок приховано; PHP може працювати на nginx, Apache, LiteSpeed тощо)';
                } else {
                    $result['note'] = 'Server-заголовок приховано (X-Powered-By: ' . $rawPoweredBy . ')';
                }
            } else {
                $result['note'] = 'Server-заголовок відсутній (прихований конфігурацією сервера або CDN)';
            }
        } else {
            $lowerName = strtolower($result['name']);
            if ($lowerName === 'cloudflare') {
                $result['note'] = 'Реальний веб-сервер прихований за Cloudflare (у заголовку Server: cloudflare)';
            } elseif (in_array($lowerName, ['cloudfront', 'amazon s3', 'amazons3', 's3', 'akamai', 'akamaighost', 'netdna-cache', 'google web server', 'gws'], true)) {
                $result['note'] = 'Реальний веб-сервер прихований за CDN (потрібно дивитись оригінальний Server-заголовок на початку ланцюга)';
            } elseif ($lowerName === 'varnish' || $lowerName === 'squid' || $lowerName === 'envoy') {
                $result['note'] = 'Виявлено reverse-proxy/кеш (' . $result['name'] . ') — реальний backend-сервер за ним не видно ззовні';
            }
        }

        // Store Via / X-Server as evidence (the frontend ignores them, but they are in JSON/PDF debug).
        if ($rawVia !== null) {
            $result['via'] = mb_substr($rawVia, 0, 160);
        }
        if ($rawXServer !== null) {
            $result['x_server'] = mb_substr($rawXServer, 0, 160);
        }

        // Exact PHP version — only if directly disclosed by a header (X-Powered-By / Server), no CMS guessing
        $phpVersion = null;
        $phpSource = null;
        if ($rawPoweredBy !== null && preg_match('~php/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.-][A-Za-z0-9]+)*)~i', $rawPoweredBy, $m)) {
            $phpVersion = $m[1];
            $phpSource = 'X-Powered-By';
        } elseif ($result['raw'] !== null && preg_match('~php/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.-][A-Za-z0-9]+)*)~i', $result['raw'], $m)) {
            $phpVersion = $m[1];
            $phpSource = 'Server';
        }

        // If the header is hidden on the homepage (often cached), try precise PHP endpoints
        if ($phpVersion === null) {
            $extra = $this->probePhpVersionViaHeaders();
            if ($extra !== null) {
                $phpVersion = $extra['version'];
                $phpSource = $extra['source'];
            }
        }

        // Last resort — an open phpinfo (gives the exact version if the admin left the file)
        if ($phpVersion === null) {
            $probe = $this->probePhpInfo(rtrim($this->url, '/') . '/phpinfo.php');
            if ($probe === null) {
                $probe = $this->probePhpInfo(rtrim($this->url, '/') . '/info.php');
            }
            if ($probe !== null && !empty($probe['version'])) {
                $phpVersion = $probe['version'];
                $phpSource = 'phpinfo';
            }
        }

        if ($phpVersion !== null) {
            $result['php_version'] = $phpVersion;
            $result['php_version_source'] = $phpSource;
            $result['php_present'] = true;
            $result['php_source'] = $phpSource;
        } else {
            // Explicitly drop empty php fields to avoid cluttering the response
            unset($result['php_version'], $result['php_version_source']);
        }

        // PHP presence without an exact version (honest inference, as with DB):
        // 1) PHP token in Server without a version, 2) PHPSESSID cookie, 3) PHP CMS/framework.
        if (!$result['php_present']) {
            if ($rawPoweredBy !== null && stripos($rawPoweredBy, 'php') !== false) {
                $result['php_present'] = true;
                $result['php_source'] = 'X-Powered-By';
            } elseif ($result['raw'] !== null && preg_match('~php(?:$|[^a-z])~i', $result['raw'])) {
                $result['php_present'] = true;
                $result['php_source'] = 'Server';
            } else {
                foreach ($headers as $h) {
                    if (stripos($h, 'PHPSESSID') !== false) {
                        $result['php_present'] = true;
                        $result['php_source'] = 'Set-Cookie: PHPSESSID';
                        break;
                    }
                }
            }
        }
        if (!$result['php_present']) {
            $phpCms = ['WordPress', 'Joomla', 'Drupal', 'OpenCart', 'PrestaShop', 'Magento', '1С-Бітрікс', 'MODX', 'phpBB', 'vBulletin'];
            foreach ($cms as $c) {
                if (in_array($c['name'] ?? '', $phpCms, true)) {
                    $result['php_present'] = true;
                    $result['php_source'] = 'CMS inference (' . $c['name'] . ')';
                    break;
                }
            }
            if (!$result['php_present']) {
                foreach ($frameworks as $fw) {
                    if (in_array($fw['name'] ?? '', ['Laravel', 'Symfony', 'Yii', 'CodeIgniter', 'CakePHP'], true)) {
                        $result['php_present'] = true;
                        $result['php_source'] = 'Framework inference (' . $fw['name'] . ')';
                        break;
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Node.js detection from headers and HTML.
     * @return array{present: bool, version: ?string, source: ?string}
     */
    private function detectNodeJs(array $headers, ?string $html): array
    {
        $version = null;
        $source = null;
        $present = false;

        foreach ($headers as $h) {
            $colon = strpos($h, ':');
            if ($colon === false) continue;
            $name = strtolower(trim(substr($h, 0, $colon)));
            $value = trim(substr($h, $colon + 1));
            if ($value === '') continue;
            $low = strtolower($value);
            if ($name === 'x-powered-by') {
                if (str_contains($low, 'express')) {
                    $present = true;
                    $source = $source ?? 'X-Powered-By: Express';
                    if (preg_match('~express/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                        $version = $m[1];
                    }
                }
                if (str_contains($low, 'node')) {
                    $present = true;
                    $source = $source ?? 'X-Powered-By: Node.js';
                    if (preg_match('~node(?:\.js)?/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                        $version = $m[1];
                        $source = 'X-Powered-By: Node.js';
                    }
                }
            }
            if ($name === 'server' && str_contains($low, 'node')) {
                $present = true;
                $source = $source ?? 'Server: Node.js';
                if (preg_match('~node(?:\.js)?/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                    $version = $m[1];
                }
            }
        }

        // HTML signals (presence only, no version)
        if ($html !== null && !$present) {
            $lowHtml = strtolower($html);
            if (str_contains($lowHtml, 'x-powered-by: express') || str_contains($lowHtml, '__next_data__') || str_contains($lowHtml, '__nuxt__')) {
                // Next/Nuxt run on Node, but the version is unknown
                // Do not mark Node as present from headers alone to avoid false positives
            }
        }

        return ['present' => $present, 'version' => $version, 'source' => $source];
    }

    /**
     * Python detection from headers, HTML and frameworks.
     * @return array{present: bool, version: ?string, source: ?string}
     */
    private function detectPython(array $headers, ?string $html, array $frameworks = []): array
    {
        $version = null;
        $source = null;
        $present = false;

        foreach ($headers as $h) {
            $colon = strpos($h, ':');
            if ($colon === false) continue;
            $name = strtolower(trim(substr($h, 0, $colon)));
            $value = trim(substr($h, $colon + 1));
            if ($value === '') continue;
            $low = strtolower($value);
            if (in_array($name, ['server', 'x-powered-by', 'x-python-version'], true)) {
                if (str_contains($low, 'gunicorn')) {
                    $present = true;
                    $source = $source ?? 'Server: gunicorn';
                    if (preg_match('~gunicorn/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                        $version = $m[1];
                        $source = 'Server: gunicorn';
                    }
                }
                if (str_contains($low, 'uvicorn')) {
                    $present = true;
                    $source = $source ?? 'Server: uvicorn';
                    if (preg_match('~uvicorn/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                        $version = $m[1];
                    }
                }
                if (str_contains($low, 'python')) {
                    $present = true;
                    $source = $source ?? $name . ': Python';
                    if (preg_match('~python/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                        $version = $m[1];
                        $source = $name . ': Python';
                    }
                }
                if (str_contains($low, 'wsgi')) {
                    $present = true;
                    $source = $source ?? $name . ': WSGI';
                }
            }
        }

        // Inference from Python frameworks
        if (!$present) {
            foreach ($frameworks as $fw) {
                $n = $fw['name'] ?? '';
                if (in_array($n, ['Django', 'Flask'], true)) {
                    $present = true;
                    $source = $source ?? 'Framework inference (' . $n . ')';
                    break;
                }
            }
        }

        return ['present' => $present, 'version' => $version, 'source' => $source];
    }

    /**
     * Build a unified Web server section (full width) with all subsystems.
     */
    private function buildUnifiedServer(array $serverInfo, ?array $cdn, array $dbInfo, array $nodeInfo, array $pythonInfo): array
    {
        $result = $serverInfo;

        // PHP is already in $serverInfo (php_version / php_present / php_source) — leave as is

        // Negotiated HTTP protocol of the main request (a real fact about the stack).
        $result['http_version'] = $this->httpVersion;

        // Node.js
        $result['node_present'] = $nodeInfo['present'] ?? false;
        $result['node_version'] = $nodeInfo['version'] ?? null;
        $result['node_source'] = $nodeInfo['source'] ?? null;

        // Python
        $result['python_present'] = $pythonInfo['present'] ?? false;
        $result['python_version'] = $pythonInfo['version'] ?? null;
        $result['python_source'] = $pythonInfo['source'] ?? null;

        // CDN
        if ($cdn !== null) {
            $result['cdn_provider'] = $cdn['provider'] ?? null;
            $result['cdn_detection'] = $cdn['detection'] ?? null;
            // Keep extra CDN fields for debugging, but they are optional
            foreach ($cdn as $k => $v) {
                if (!in_array($k, ['provider', 'detection'], true)) {
                    $result['cdn_' . $k] = $v;
                }
            }
        } else {
            $result['cdn_provider'] = null;
            $result['cdn_detection'] = null;
        }

        // DB
        $result['dbms'] = $dbInfo['dbms'] ?? null;
        $result['db_version'] = $dbInfo['version'] ?? null;
        $result['db_source'] = $dbInfo['source'] ?? null;
        $result['db_note'] = $dbInfo['note'] ?? null;
        $result['db_detected'] = $dbInfo['detected'] ?? false;
        if (isset($dbInfo['evidence'])) {
            $result['db_evidence'] = $dbInfo['evidence'];
        }

        return $result;
    }

    /**
     * Extra header probing for PHP on endpoints where X-Powered-By is often not hidden by cache.
     * Checks /wp-login.php, /index.php, /xmlrpc.php with a short HEAD request.
     * Returns ['version'=>string,'source'=>string] or null.
     */
    private function probePhpVersionViaHeaders(): ?array
    {
        $base = rtrim($this->url, '/');
        $candidates = [
            $base . '/wp-login.php',
            $base . '/index.php',
            $base . '/xmlrpc.php',
        ];
        foreach ($candidates as $u) {
            $headers = $this->fetchHeaders($u);
            if (empty($headers)) {
                continue;
            }
            foreach ($headers as $h) {
                $colon = strpos($h, ':');
                if ($colon === false) {
                    continue;
                }
                $name = strtolower(trim(substr($h, 0, $colon)));
                $value = trim(substr($h, $colon + 1));
                if ($value === '') {
                    continue;
                }
                if (in_array($name, ['x-powered-by', 'x-php-version', 'x-php', 'server'], true) && preg_match('~php/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.-][A-Za-z0-9]+)*)~i', $value, $m)) {
                    return ['version' => $m[1], 'source' => $name . ' (' . basename(parse_url($u, PHP_URL_PATH)) . ')'];
                }
            }
        }
        return null;
    }

    /**
     * Perform a HEAD/GET request and return an array of headers ("Name: value" lines) or [].
     */
    private function fetchHeaders(string $url): array
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                return [];
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_NOBODY => true, // HEAD is enough for headers
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT => 3,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_USERAGENT => 'MP-Site-Detect/php-probe',
            ]);
            $resp = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            if ($resp === false || $code < 200 || $code >= 400) {
                return [];
            }
            // With NOBODY the body is absent, so the whole resp is headers
            return $this->parseRawHeaders((string)$resp);
        }
        // Fallback via get_headers
        $headers = @get_headers($url, 1);
        if (!is_array($headers)) {
            return [];
        }
        $out = [];
        foreach ($headers as $k => $v) {
            if (is_int($k)) {
                $out[] = $v;
            } else {
                $out[] = $k . ': ' . (is_array($v) ? end($v) : $v);
            }
        }
        return $out;
    }

    /**
     * Strict check for an exposed phpinfo file.
     * Returns null if the file does not exist / is not a genuine phpinfo,
     * otherwise an array ['isPhpInfo'=>bool,'version'=>?string].
     * Requirements: HTTP 200 + <title>phpinfo or PHP Version presence.
     *
     * @return array{isPhpInfo: bool, version: ?string}|null
     */
    private function probePhpInfo(string $url): ?array
    {
        if (!function_exists('curl_init')) {
            $body = $this->httpGet($url, 4);
            if ($body === null || $body === '') {
                return null;
            }
            $headers = $this->captureHeaders();
            $is404 = false;
            foreach ($headers as $h) {
                if (preg_match('~^HTTP/\S+\s+404\b~i', $h)) {
                    $is404 = true;
                    break;
                }
            }
            if ($is404) {
                return null;
            }
            $hasTitle = (bool)preg_match('~<title[^>]*>\s*phpinfo\(\)~i', $body);
            $hasVersion = (bool)preg_match('~PHP\s+Version\s+[0-9]+\.[0-9]+~i', $body);
            if (!$hasTitle && !$hasVersion) {
                return null;
            }
            $version = null;
            if (preg_match('~PHP\s+Version\s+([0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9]+)*)~i', $body, $m)) {
                $version = $m[1];
            }
            return ['isPhpInfo' => true, 'version' => $version];
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 4,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'MP-Site-Detect/phpinfo-probe',
            CURLOPT_ENCODING => '',
            CURLOPT_NOBODY => false,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
        if ($body === false || $body === '' || $code !== 200) {
            return null;
        }
        $hasTitle = (bool)preg_match('~<title[^>]*>\s*phpinfo\(\)~i', $body);
        $hasVersion = (bool)preg_match('~PHP\s+Version\s+[0-9]+\.[0-9]+~i', $body);
        if (!$hasTitle && !$hasVersion) {
            return null;
        }
        $version = null;
        if (preg_match('~PHP\s+Version\s+([0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9]+)*)~i', $body, $m)) {
            $version = $m[1];
        }
        return ['isPhpInfo' => true, 'version' => $version];
    }

    /**
     * Remote DBMS detection for the scanned site.
     * Tries to pin down the DBMS and its version (MySQL/MariaDB/PostgreSQL/SQLite/Progress/MSSQL/Oracle).
     * Sources in priority order:
     *  1) phpinfo (strict, HTTP 200 + title) — parses Client API version / Server version
     *  2) leak in HTML (SQL errors with a version)
     *  3) X-DB-* headers (rare)
     *  4) inference from CMS/framework (WordPress→ MySQL/MariaDB without a version)
     * If the exact version cannot be determined remotely — returns detected=false or version=null with an explanation.
     *
     * @return array{detected: bool, dbms: ?string, version: ?string, source: ?string, note: string, evidence: ?string}
     */
    private function detectDatabase(array $headers, ?string $html, array $cms = [], array $frameworks = [], array $tech = []): array
    {
        $headersStr = strtolower(implode("\n", $headers));
        $htmlLower = $html !== null ? strtolower($html) : '';
        $htmlRaw = $html ?? '';

        // 1) Try phpinfo (most accurate — gives both type and version)
        $phpInfoBody = $this->fetchPhpInfoBody();
        if ($phpInfoBody !== null) {
            $parsed = $this->parseDbFromPhpInfo($phpInfoBody);
            if ($parsed !== null && !empty($parsed['dbms'])) {
                $note = 'Визначено за відкритим phpinfo() — витік конфігурації, рекомендується закрити доступ.';
                if (!empty($parsed['version'])) {
                    $note = 'Точна СУБД та версія визначені за phpinfo() (' . $parsed['dbms'] . ' ' . $parsed['version'] . '). ' . $note;
                }
                return [
                    'detected' => true,
                    'dbms' => $parsed['dbms'],
                    'version' => $parsed['version'] ?? null,
                    'source' => 'phpinfo',
                    'note' => $note,
                    'evidence' => $parsed['evidence'] ?? null,
                ];
            }
        }

        // 2) Headers that directly point to a DB (rare, but exact)
        foreach ($headers as $h) {
            $colon = strpos($h, ':');
            if ($colon === false) continue;
            $name = strtolower(trim(substr($h, 0, $colon)));
            $value = trim(substr($h, $colon + 1));
            if (preg_match('~^(x-db-version|x-mysql-version|x-mariadb-version|x-postgres-version)~i', $name) && $value !== '') {
                if (preg_match('~([a-z]+).*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i', $value, $m)) {
                    return [
                        'detected' => true,
                        'dbms' => ucfirst(strtolower($m[1])),
                        'version' => $m[2],
                        'source' => $name,
                        'note' => 'Точна версія визначена за HTTP-заголовком ' . $name . '.',
                        'evidence' => $h,
                    ];
                }
            }
        }

        // 3) Leak in HTML — search for SQL errors with a version
        if ($html !== null) {
            $patterns = [
                'MySQL' => '~MySQL[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
                'MariaDB' => '~MariaDB[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
                'PostgreSQL' => '~PostgreSQL[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
                'SQLite' => '~SQLite[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
                'Progress' => '~Progress[^<]{0,80}?(?:OpenEdge)?[^<]{0,20}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
                'MSSQL' => '~(?:Microsoft SQL Server|MSSQL)[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
                'Oracle' => '~Oracle[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i',
            ];
            foreach ($patterns as $dbms => $pat) {
                if (preg_match($pat, $htmlRaw, $m)) {
                    $ver = $m[1] ?? null;
                    // Check that error-DB signs are nearby, so random mentions are not caught
                    $hasError = preg_match('~SQLSTATE|SQL syntax|server has gone away|pg_query|sqlite|ORA-|Progress error~i', $htmlRaw);
                    if ($ver !== null || $hasError) {
                        return [
                            'detected' => true,
                            'dbms' => $dbms,
                            'version' => $ver,
                            'source' => 'HTML leak',
                            'note' => $ver !== null
                                ? 'СУБД та версія виявлені за витоком SQL-помилки в HTML (' . $dbms . ' ' . $ver . '). Рекомендується приховати детальні помилки БД.'
                                : 'Тип СУБД виявлено за витоком SQL-помилки (' . $dbms . '), але точну версію приховано.',
                            'evidence' => mb_substr(trim(preg_replace('~\s+~u', ' ', $m[0])), 0, 180),
                        ];
                    }
                }
            }
            // Lighter search without a version — just a DB mention in an error context
            if (preg_match('~SQLSTATE|MySQL server has gone away|MariaDB server version|pg_query\(\)|SQLite3::|Progress OpenEdge|Microsoft SQL Server|ORA-[0-9]+~i', $htmlRaw, $m)) {
                $guess = 'MySQL';
                $low = strtolower($m[0]);
                if (str_contains($low, 'postgres') || str_contains($low, 'pg_query')) $guess = 'PostgreSQL';
                elseif (str_contains($low, 'sqlite')) $guess = 'SQLite';
                elseif (str_contains($low, 'progress')) $guess = 'Progress';
                elseif (str_contains($low, 'sql server') || str_contains($low, 'mssql')) $guess = 'MSSQL';
                elseif (str_contains($low, 'ora-')) $guess = 'Oracle';
                elseif (str_contains($low, 'mariadb')) $guess = 'MariaDB';
                return [
                    'detected' => true,
                    'dbms' => $guess,
                    'version' => null,
                    'source' => 'HTML leak',
                    'note' => 'Тип СУБД виявлено за витоком SQL-помилки (' . $guess . '), але точну версію дистанційно визначити неможливо — сервер приховує деталі.',
                    'evidence' => mb_substr(trim($m[0]), 0, 120),
                ];
            }
        }

        // 4) Inference from CMS / framework (likely, without an exact version)
        $phpCms = ['WordPress','Joomla','Drupal','OpenCart','PrestaShop','Magento','1С-Бітрікс','MODX','phpBB','vBulletin'];
        $cmsList = [];
        foreach ($cms as $c) {
            $n = $c['name'] ?? '';
            if (in_array($n, $phpCms, true)) $cmsList[] = $n;
        }
        if (!empty($cmsList)) {
            // WordPress/Joomla/Drupal traditionally run on MySQL/MariaDB
            return [
                'detected' => true,
                'dbms' => 'MySQL / MariaDB',
                'version' => null,
                'source' => 'CMS inference (' . implode(', ', $cmsList) . ')',
                'note' => null,
                'evidence' => null,
            ];
        }

        $phpFrameworks = ['Laravel','Symfony','Yii','CodeIgniter','CakePHP'];
        $fwList = [];
        foreach ($frameworks as $fw) {
            if (in_array($fw['name'] ?? '', $phpFrameworks, true)) $fwList[] = $fw['name'];
        }
        if (!empty($fwList)) {
            return [
                'detected' => true,
                'dbms' => 'MySQL / MariaDB / PostgreSQL / SQLite',
                'version' => null,
                'source' => 'Framework inference (' . implode(', ', $fwList) . ')',
                'note' => 'Сайт використовує PHP-фреймворк (' . implode(', ', $fwList) . '), який підтримує кілька СУБД (MySQL, MariaDB, PostgreSQL, SQLite). Точну СУБД дистанційно визначити неможливо.',
                'evidence' => null,
            ];
        }

        // 5) Nothing found — the exact DBMS cannot be determined
        return [
            'detected' => false,
            'dbms' => null,
            'version' => null,
            'source' => null,
            'note' => 'Точну СУБД та її версію дистанційно визначити неможливо. Сервер не розкриває заголовки X-DB-*, у HTML немає витоків SQL-помилок, а phpinfo закрито. Для точної діагностики потрібен доступ до сервера (конфіг, phpinfo, SHOW VARIABLES).',
            'evidence' => null,
        ];
    }

    /**
     * Fetch the phpinfo body if the file is open (strict HTTP 200 + markers), otherwise null.
     */
    private function fetchPhpInfoBody(): ?string
    {
        $candidates = [
            rtrim($this->url, '/') . '/phpinfo.php',
            rtrim($this->url, '/') . '/info.php',
        ];
        foreach ($candidates as $u) {
            $probe = $this->probePhpInfo($u);
            if ($probe !== null && ($probe['isPhpInfo'] ?? false)) {
                // Re-fetch the body (probe already checked it but did not return the body)
                if (function_exists('curl_init')) {
                    $ch = curl_init($u);
                    if ($ch === false) continue;
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_HEADER => false,
                        CURLOPT_FOLLOWLOCATION => false,
                        CURLOPT_TIMEOUT => 4,
                        CURLOPT_CONNECTTIMEOUT => 3,
                        CURLOPT_SSL_VERIFYPEER => false,
                        CURLOPT_SSL_VERIFYHOST => false,
                        CURLOPT_USERAGENT => 'MP-Site-Detect/db-probe',
                        CURLOPT_ENCODING => '',
                    ]);
                    $body = curl_exec($ch);
                    if (PHP_VERSION_ID < 80000) curl_close($ch);
                    if (is_string($body) && $body !== '' && stripos($body, 'phpinfo') !== false) {
                        return $body;
                    }
                } else {
                    $body = $this->httpGet($u, 4);
                    if (is_string($body) && $body !== '' && stripos($body, 'phpinfo') !== false) {
                        return $body;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Parse DBMS and version from phpinfo HTML.
     * @return array{dbms: string, version: ?string, evidence: ?string}|null
     */
    private function parseDbFromPhpInfo(string $body): ?array
    {
        $checks = [
            'MariaDB' => ['needle' => 'MariaDB', 'pat' => '~MariaDB[^<]{0,120}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i'],
            'MySQL' => ['needle' => 'MySQL', 'pat' => '~(?:Client API version|Server version|MySQL)[^<]{0,80}?([0-9]+\.[0-9]+\.[0-9]+)~i'],
            'PostgreSQL' => ['needle' => 'PostgreSQL', 'pat' => '~PostgreSQL[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i'],
            'SQLite' => ['needle' => 'SQLite', 'pat' => '~SQLite[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i'],
            'Progress' => ['needle' => 'Progress', 'pat' => '~Progress[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i'],
            'MSSQL' => ['needle' => 'sqlsrv', 'pat' => '~sqlsrv[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i'],
            'Oracle' => ['needle' => 'oci8', 'pat' => '~oci8[^<]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)~i'],
        ];
        foreach ($checks as $dbms => $cfg) {
            if (stripos($body, $cfg['needle']) === false) continue;
            $version = null;
            $evidence = null;
            if (preg_match($cfg['pat'], $body, $m)) {
                $version = $m[1] ?? null;
                $evidence = mb_substr(trim(preg_replace('~\s+~u', ' ', $m[0])), 0, 160);
            } else {
                // A DB section found without a version — still record the type
                $evidence = $cfg['needle'];
            }
            return ['dbms' => $dbms, 'version' => $version, 'evidence' => $evidence];
        }
        // Additionally: if pdo_mysql / mysqli is present — this is MySQL/MariaDB without an exact version
        if (stripos($body, 'pdo_mysql') !== false || stripos($body, 'mysqli') !== false) {
            return ['dbms' => 'MySQL / MariaDB', 'version' => null, 'evidence' => 'pdo_mysql/mysqli'];
        }
        return null;
    }

    /**
     * Server header parser: nginx/1.24.0, Apache/2.4.52 (Ubuntu),
     * LiteSpeed, Microsoft-IIS/10.0, cloudflare, openresty/1.21.4.1, etc.
     * Can parse COMPOUND values ("nginx/1.24.0 (Ubuntu)",
     * "Apache/2.4.52 (Ubuntu) OpenSSL/1.1.1f", "Server: DPS/2.0 + nginx")
     * as in Wappalyzer: find the first KNOWN server token, normalize the name.
     * Additionally collects secondary tokens (OpenSSL/mod_ssl/PHP) into 'extras'.
     * Returns ['name' => ..., 'version' => string|null, 'extras' => array]
     * or null for empty/invalid.
     */
    private function parseServerHeader(string $value): ?array
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        // Normalize known names (different spellings → canonical).
        $normalize = static function (string $name): string {
            $low = strtolower($name);
            $map = [
                'microsoft-iis' => 'IIS',
                'iis' => 'IIS',
                'openresty' => 'OpenResty',
                'openlitespeed' => 'OpenLiteSpeed',
                'litespeed' => 'LiteSpeed',
                'cloudflare' => 'cloudflare',
                'cloudfront' => 'cloudfront',
                'amazons3' => 'Amazon S3',
                'akamai' => 'Akamai',
                'akamaighost' => 'AkamaiGHost',
                'netdna-cache' => 'NetDNA-cache',
                'gws' => 'Google Web Server',
                'bigip' => 'BIG-IP',
            ];
            if (isset($map[$low])) {
                return $map[$low];
            }
            // nginx/Apache/Caddy/Lighttpd/Cherokee/Squid/Varnish/Envoy/Tengine/Cowboy/Kestrel — as is, capitalized
            $keep = ['nginx', 'apache', 'caddy', 'lighttpd', 'cherokee', 'squid', 'varnish', 'envoy', 'tengine', 'cowboy', 'kestrel', 'haproxy', 'trafficserver'];
            if (in_array($low, $keep, true)) {
                return ucfirst($low) === 'Nginx' ? 'nginx' : $name;
            }
            return $name;
        };

        // Collect all "name[/version]" tokens from the value.
        if (preg_match_all('~([A-Za-z][A-Za-z0-9\-\+\._]*)(?:/([0-9][0-9A-Za-z\.\-]+))?~', $value, $all, PREG_SET_ORDER)) {
            $known = ['nginx', 'apache', 'litespeed', 'openlitespeed', 'openresty', 'caddy', 'microsoft-iis', 'iis', 'cloudflare', 'cloudfront', 'amazons3', 's3', 'akamai', 'akamaighost', 'netdna-cache', 'gws', 'varnish', 'squid', 'envoy', 'lighttpd', 'cherokee', 'tengine', 'haproxy', 'cowboy', 'kestrel', 'bigip'];
            // Secondary versioned tokens worth showing separately (real facts).
            $extras = [];
            foreach ($all as $tok) {
                $lowTok = strtolower($tok[1]);
                if (in_array($lowTok, ['openssl', 'mod_ssl'], true) && isset($tok[2]) && $tok[2] !== '') {
                    $extras['OpenSSL'] = $tok[2];
                } elseif ($lowTok === 'php' && isset($tok[2]) && $tok[2] !== '') {
                    $extras['PHP'] = $tok[2];
                }
            }
            foreach ($all as $tok) {
                $low = strtolower($tok[1]);
                if (in_array($low, $known, true)) {
                    $ver = isset($tok[2]) && $tok[2] !== '' ? $tok[2] : null;
                    // Filter out junk like a "(Ubuntu)" version without leading digits — the regex already requires a digit.
                    return ['name' => $normalize($tok[1]), 'version' => $ver, 'extras' => $extras];
                }
            }
            // No known token — return the first meaningful token as is
            // (e.g. "DPS/2.0", "QRATOR", custom WAF).
            $first = $all[0];
            // Skip service tokens like "Ubuntu", "OpenSSL", "PHP", "mod_ssl".
            foreach ($all as $tok) {
                $low = strtolower($tok[1]);
                if (in_array($low, ['ubuntu', 'debian', 'openssl', 'mod_ssl', 'php', 'mod_perl', 'mod_wsgi', 'unix'], true)) {
                    continue;
                }
                $ver = isset($tok[2]) && $tok[2] !== '' ? $tok[2] : null;
                return ['name' => $tok[1], 'version' => $ver, 'extras' => $extras];
            }
            $ver = isset($first[2]) && $first[2] !== '' ? $first[2] : null;
            return ['name' => $first[1], 'version' => $ver, 'extras' => $extras];
        }

        return null;
    }

    /**
     * CDN detection (content delivery network).
     *
     * Checks headers and HTML against the CDN_SIGNATURES config.
     * Returns an array with fields: provider, detection + extra fields (ray_id, pop, served_by, etc.).
     */
    private function detectCdn(array $headers, string $html): ?array
    {
        $lowerHtml = strtolower($html);
        $candidates = [];

        foreach (self::CDN_SIGNATURES as $provider => $cfg) {
            $detection = null;
            $extra = [];

            // 1. Specific headers
            foreach ($cfg['headers'] ?? [] as $hc) {
                foreach ($headers as $h) {
                    $colon = strpos($h, ':');
                    if ($colon === false) {
                        continue;
                    }
                    $hName = strtolower(trim(substr($h, 0, $colon)));
                    $hValue = trim(substr($h, $colon + 1));

                    if (!empty($hc['match_prefix'])) {
                        if (str_starts_with($hName, $hc['name'])) {
                            $detection = $detection ?? $hc['name'] . '* header';
                            if (isset($hc['extract'])) {
                                $extra[$hc['extract']] = $hValue;
                            }
                        }
                        continue;
                    }

                    if ($hName !== $hc['name']) {
                        continue;
                    }
                    if (isset($hc['value_match']) && stripos($hValue, $hc['value_match']) === false) {
                        continue;
                    }

                    $detection = $detection ?? ($hc['name'] . ' header');
                    if (isset($hc['extract'])) {
                        if ($hc['extract'] === 'pop' && isset($hc['sep'])) {
                            $parts = explode($hc['sep'], $hValue);
                            $extra['ray_id'] = $hValue;
                            $extra['pop'] = end($parts) ?: null;
                        } else {
                            $extra[$hc['extract']] = $hValue;
                        }
                    }
                }
            }

            // 2. Server header
            if (!empty($cfg['server_match'])) {
                foreach ($headers as $h) {
                    $colon = strpos($h, ':');
                    if ($colon === false) {
                        continue;
                    }
                    $hName = strtolower(trim(substr($h, 0, $colon)));
                    if ($hName !== 'server') {
                        continue;
                    }
                    $hValue = strtolower(trim(substr($h, $colon + 1)));
                    if (str_contains($hValue, strtolower($cfg['server_match']))) {
                        $detection = $detection ?? 'Server header';
                        break;
                    }
                }
            }

            // 3. Via header
            if (!empty($cfg['via_match'])) {
                foreach ($headers as $h) {
                    $colon = strpos($h, ':');
                    if ($colon === false) {
                        continue;
                    }
                    $hName = strtolower(trim(substr($h, 0, $colon)));
                    if ($hName !== 'via') {
                        continue;
                    }
                    $hValue = strtolower(trim(substr($h, $colon + 1)));
                    if (str_contains($hValue, strtolower($cfg['via_match']))) {
                        $detection = $detection ?? 'Via header';
                        $extra['via'] = $hValue;
                        break;
                    }
                }
            }

            if ($detection !== null) {
                $candidates[] = [
                    'provider' => $provider,
                    'detection' => $detection,
                    'priority' => $cfg['priority'],
                    'extra' => $extra,
                ];
            }
        }

        // 4. Fallback on HTML content
        if (empty($candidates)) {
            foreach (self::CDN_SIGNATURES as $provider => $cfg) {
                foreach ($cfg['html_signs'] ?? [] as $sign) {
                    if (str_contains($lowerHtml, strtolower($sign))) {
                        $candidates[] = [
                            'provider' => $provider,
                            'detection' => 'HTML content (' . $sign . ')',
                            'priority' => $cfg['priority'] + 100, // lower priority than headers
                            'extra' => [],
                        ];
                        break;
                    }
                }
            }
        }

        if (empty($candidates)) {
            return null;
        }

        usort($candidates, static fn($a, $b) => $a['priority'] <=> $b['priority']);
        $best = $candidates[0];
        $result = [
            'provider' => $best['provider'],
            'detection' => $best['detection'],
        ];
        foreach ($best['extra'] as $k => $v) {
            $result[$k] = $v;
        }
        return $result;
    }

    private function extractTitle(string $html): ?string
    {
        if (preg_match('~<title[^>]*>([^<]+)</title>~iu', $html, $m)) {
            return trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        }
        return null;
    }

    private function extractMeta(string $html, string $name): ?string
    {
        $pattern = '~<meta\s[^>]*name\s*=\s*["\']' . preg_quote($name, '~') . '["\'][^>]*content\s*=\s*["\']([^"\']+)["\']~iu';
        if (preg_match($pattern, $html, $m)) {
            return trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        }
        $pattern = '~<meta\s[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']' . preg_quote($name, '~') . '["\']~iu';
        if (preg_match($pattern, $html, $m)) {
            return trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        }
        return null;
    }

    private function formatDate(?string $raw): ?string
    {
        if (!$raw) {
            return null;
        }
        $ts = strtotime($raw);
        if ($ts === false) {
            return $raw;
        }
        return date('d.m.Y H:i', $ts);
    }

    private function formatEmails(mixed $emails): ?string
    {
        if (!$emails) {
            return null;
        }
        if (is_string($emails)) {
            return $emails;
        }
        if (is_array($emails)) {
            $list = [];
            foreach ($emails as $email) {
                if (is_string($email)) {
                    $list[] = $email;
                }
            }
            return $list ? implode(', ', $list) : null;
        }
        return null;
    }

    private function cleanFields(array $fields): array
    {
        foreach ($fields as $key => $value) {
            if ($value === null || $value === '' || $value === []) {
                unset($fields[$key]);
            }
        }
        return $fields;
    }

    private function httpGet(string $url, int $timeout = 10): ?string
    {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeout,
                'header' => "User-Agent: MP-Site-Detect/1.0\r\nAccept: application/json\r\n",
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);
        $body = @file_get_contents($url, false, $ctx);
        return $body === false ? null : $body;
    }

    /**
     * Capture HTTP headers of the last request.
     * Works with PHP 8.5+ (http_get_last_response_headers) and earlier versions.
     */
    private function captureHeaders(): array
    {
        if (function_exists('http_get_last_response_headers')) {
            $headers = @http_get_last_response_headers();
            return is_array($headers) ? $headers : [];
        }
        return $GLOBALS['http_response_header'] ?? [];
    }

    /**
     * WordPress theme and plugin detection from HTML plus extra requests.
     */
    private function detectWordPressDetails(string $html, ?string $generator = null): ?array
    {
        $theme = $this->detectWordPressTheme($html);
        $parentTheme = null;

        // If the active theme is a child, first load info about the parent theme
        // to use its "Tested up to" for WP version detection.
        if (is_array($theme) && !empty($theme['parent_slug'])) {
            $parentTheme = $this->fetchThemeInfo($theme['parent_slug']);
        }

        $versionInfo = $this->detectWordPressVersion($html, $generator, $theme, $parentTheme);
        $plugins = $this->detectWordPressPlugins($html);
        $this->fillPluginVersionsFromPage($plugins, $html, $generator);
        $pageBuilders = $this->detectPageBuilder($html, $plugins);
        $wooCommerce = $this->detectWooCommerce($html, $plugins);
        $loginInfo = $this->detectWordPressLoginUrl($html);

        $hasAny = ($versionInfo['version'] !== null || $versionInfo['version_min'] !== null)
            || $theme !== null
            || !empty($plugins)
            || !empty($pageBuilders)
            || ($wooCommerce !== null && !empty($wooCommerce['active']))
            || ($loginInfo !== null && (!empty($loginInfo['url']) || !empty($loginInfo['is_hidden'])));

        if (!$hasAny) {
            return null;
        }

        $result = [
            'version' => $versionInfo['version'],
            'version_min' => $versionInfo['version_min'],
            'version_source' => $versionInfo['source'],
            'version_note' => $versionInfo['note'],
            'theme' => $theme,
            'plugins' => $plugins,
            'page_builders' => $pageBuilders,
            'woocommerce' => $wooCommerce,
            'login_url' => $loginInfo,
            'note' => 'Виявлено лише ті плагіни, які завантажуються на перевіреній сторінці. '
                . 'Інші активні плагіни можуть не потрапити у звіт.',
        ];

        if ($parentTheme !== null) {
            $result['parent_theme'] = $parentTheme;
            unset($result['theme']['parent_slug']);
        }

        return $result;
    }

    /**
     * WordPress admin login URL detection.
     *
     * Logic:
     *  1) Check standard addresses `/wp-login.php` and `/wp-admin/` —
     *     if at least one shows login page signs (200 with a form
     *     or a 302 to wp-login), return it as `is_default = true`.
     *  2) If the standard ones return 404 and `/wp-admin/` redirects to
     *     a custom path — check the redirect target for a login page.
     *  3) Otherwise scan HTML for links containing login-like
     *     keywords and probe each candidate.
     *  4) If nothing is found — return a structure with `is_hidden = true`
     *     and an explanation for the user.
     *
     * @return array{url: ?string, path: ?string, is_default: bool, is_custom: bool, is_hidden: bool, status_code: ?int, note: string, detection_method: ?string}
     */
    private function detectWordPressLoginUrl(string $html): array
    {
        $base = rtrim($this->url, '/');
        $origin = $this->scheme . '://' . parse_url($this->url, PHP_URL_HOST)
            . (parse_url($this->url, PHP_URL_PORT) ? ':' . parse_url($this->url, PHP_URL_PORT) : '');

        // 1. Standard addresses
        $defaults = ['/wp-login.php', '/wp-admin/'];
        foreach ($defaults as $path) {
            $probe = $this->probeUrlForLogin($base . $path);
            if ($probe['is_login']) {
                $fullUrl = $base . $path;
                // For /wp-admin/ a 302 may occur → location holds the full login URL
                if ($path === '/wp-admin/' && !empty($probe['redirect_location'])) {
                    $loc = $probe['redirect_location'];
                    // If the redirect leads to a custom path that is a login — show it
                    if (!str_contains(strtolower($loc), 'wp-login.php') && !str_contains(strtolower($loc), 'wp-admin')) {
                        $customProbe = $this->probeUrlForLogin($this->resolveUrl($loc, $origin));
                        if ($customProbe['is_login']) {
                            return [
                                'url' => $this->resolveUrl($loc, $origin),
                                'path' => parse_url($this->resolveUrl($loc, $origin), PHP_URL_PATH) ?: $loc,
                                'is_default' => false,
                                'is_custom' => true,
                                'is_hidden' => false,
                                'status_code' => $customProbe['status'],
                                'note' => 'Адресу входу змінено — виявлено кастомну адресу за редиректом з /wp-admin/.',
                                'detection_method' => 'redirect:/wp-admin/ → ' . $loc,
                            ];
                        }
                    }
                }
                return [
                    'url' => $fullUrl,
                    'path' => $path,
                    'is_default' => true,
                    'is_custom' => false,
                    'is_hidden' => false,
                    'status_code' => $probe['status'],
                    'note' => 'Стандартна адреса входу доступна.',
                    'detection_method' => 'probe:' . $path . ' (' . $probe['status'] . ')',
                ];
            }
        }

        // If /wp-admin/ redirects to a custom path — check it even when the probe did not directly report is_login
        $adminProbe = $this->probeUrlForLogin($base . '/wp-admin/');
        if (!empty($adminProbe['redirect_location'])) {
            $loc = $adminProbe['redirect_location'];
            $locLower = strtolower($loc);
            // If the redirect is not to wp-login.php and not a 404 page — it may be a custom login
            if (!str_contains($locLower, 'wp-login.php') && $locLower !== '' && $adminProbe['status'] >= 300 && $adminProbe['status'] < 400) {
                $resolved = $this->resolveUrl($loc, $origin);
                // Ignore redirects to the homepage or external domains
                $resolvedHost = strtolower(parse_url($resolved, PHP_URL_HOST) ?? '');
                $ownHost = strtolower(parse_url($origin, PHP_URL_HOST) ?? '');
                if ($resolvedHost === $ownHost || $resolvedHost === '') {
                    $customProbe = $this->probeUrlForLogin($resolved);
                    if ($customProbe['is_login']) {
                        return [
                            'url' => $resolved,
                            'path' => parse_url($resolved, PHP_URL_PATH) ?: $loc,
                            'is_default' => false,
                            'is_custom' => true,
                            'is_hidden' => false,
                            'status_code' => $customProbe['status'],
                            'note' => 'Адресу входу змінено — виявлено кастомну адресу за редиректом з /wp-admin/.',
                            'detection_method' => 'redirect:/wp-admin/ → ' . $loc,
                        ];
                    }
                }
            }
        }

        // 2. Scan HTML for candidates (links with login/admin in href)
        $candidates = $this->extractLoginCandidates($html);
        foreach ($candidates as $candidatePath) {
            // Skip standard ones — already checked
            if (in_array($candidatePath, ['/wp-login.php', '/wp-admin', '/wp-admin/'], true)) {
                continue;
            }
            $full = $this->resolveUrl($candidatePath, $origin);
            // If the candidate matches base (i.e. relative without a slash) — normalize it
            if (!str_starts_with($candidatePath, '/') && !preg_match('~^https?://~i', $candidatePath)) {
                $full = $base . '/' . ltrim($candidatePath, '/');
            }
            $probe = $this->probeUrlForLogin($full);
            if ($probe['is_login']) {
                return [
                    'url' => $full,
                    'path' => parse_url($full, PHP_URL_PATH) ?: $candidatePath,
                    'is_default' => false,
                    'is_custom' => true,
                    'is_hidden' => false,
                    'status_code' => $probe['status'],
                    'note' => 'Адресу входу змінено — кастомну адресу виявлено за посиланням у HTML.',
                    'detection_method' => 'html:' . $candidatePath,
                ];
            }
        }

        // 3. Nothing found — hidden
        return [
            'url' => null,
            'path' => null,
            'is_default' => false,
            'is_custom' => false,
            'is_hidden' => true,
            'status_code' => $adminProbe['status'] ?? null,
            'note' => 'Адреса за замовчуванням входу в адмін-панель була змінена власником сайту. Визначити нову адресу дистанційно неможливо — вона прихована плагіном безпеки (наприклад, WPS Hide Login, iThemes Security та ін.).',
            'detection_method' => null,
        ];
    }

    /**
     * Probe a URL to check whether it is a WordPress login page.
     *
     * @return array{is_login: bool, status: ?int, redirect_location: ?string, body: ?string}
     */
    private function probeUrlForLogin(string $url): array
    {
        $result = ['is_login' => false, 'status' => null, 'redirect_location' => null, 'body' => null];

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                return $result;
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_USERAGENT => 'MP-Site-Detect/wp-login-probe',
                CURLOPT_ENCODING => '',
            ]);
            $resp = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $headerSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            $result['status'] = $code;
            if ($resp === false) {
                return $result;
            }
            $rawHeaders = substr((string)$resp, 0, $headerSize);
            $body = substr((string)$resp, $headerSize);
            $result['body'] = $body;
            // Also check via curl_getinfo redirect_url if the header was not parsed
            if (is_string($redirectUrl) && $redirectUrl !== '') {
                $result['redirect_location'] = $result['redirect_location'] ?? $redirectUrl;
            }

            // Find the Location header (takes priority over CURLINFO_REDIRECT_URL)
            foreach ($this->parseRawHeaders($rawHeaders) as $h) {
                if (stripos($h, 'Location:') === 0) {
                    $result['redirect_location'] = trim(substr($h, 9));
                    break;
                }
            }

            // 1) Redirect to login
            if ($code >= 300 && $code < 400 && $result['redirect_location'] !== null) {
                $locLower = strtolower($result['redirect_location']);
                if (str_contains($locLower, 'wp-login') || str_contains($locLower, 'wp-admin') || str_contains($locLower, 'login') || str_contains($locLower, 'dashboard')) {
                    // Filter out canonical redirects like lanet.ua/wp-login.php → www.lanet.ua/wp-login.php
                    // (same path, only a different host/scheme) — they do not indicate WordPress presence
                    $requestedPath = strtolower(parse_url($url, PHP_URL_PATH) ?? '/');
                    // redirect_location may be relative or absolute
                    $redirectPath = strtolower(parse_url($result['redirect_location'], PHP_URL_PATH) ?? '/');
                    // Normalize the trailing slash for comparison
                    $normReq = rtrim($requestedPath, '/') ?: '/';
                    $normRedir = rtrim($redirectPath, '/') ?: '/';
                    if ($normReq === $normRedir) {
                        // Same path — canonical redirect (www ↔ non-www, http ↔ https)
                        // Do not treat this as a WordPress-login sign
                        return $result;
                    }
                    if (str_contains($locLower, 'wp-login') || str_contains($locLower, 'wp-admin')) {
                        $result['is_login'] = true;
                        return $result;
                    }
                }
                // For custom ones — do not conclude immediately, let the caller check the target separately
                return $result;
            }

            // 2) 200 with login form signs
            if ($code === 200 && $body !== '') {
                if ($this->isWpLoginPage($body, $url)) {
                    $result['is_login'] = true;
                    return $result;
                }
            }

            // 3) 403 with login signs (some hosts return 403 but the body is a login)
            if ($code === 403 && $body !== '' && $this->isWpLoginPage($body, $url)) {
                $result['is_login'] = true;
                return $result;
            }

            return $result;
        }

        // Fallback without cURL — via get_headers + file_get_contents
        $headers = @get_headers($url, true);
        if (is_array($headers)) {
            $code = 0;
            foreach ($headers as $k => $v) {
                if (is_int($k) && preg_match('~HTTP/\S+\s+(\d{3})~i', (string)$v, $m)) {
                    $code = (int)$m[1];
                }
            }
            $result['status'] = $code ?: null;
            $loc = $headers['Location'] ?? $headers['location'] ?? null;
            if (is_array($loc)) $loc = end($loc);
            if (is_string($loc) && $loc !== '') $result['redirect_location'] = $loc;
            if ($code >= 300 && $code < 400 && $result['redirect_location'] !== null) {
                $locLower = strtolower($result['redirect_location']);
                if (str_contains($locLower, 'wp-login') || str_contains($locLower, 'wp-admin')) {
                    $requestedPath = strtolower(parse_url($url, PHP_URL_PATH) ?? '/');
                    $redirectPath = strtolower(parse_url($result['redirect_location'], PHP_URL_PATH) ?? '/');
                    $normReq = rtrim($requestedPath, '/') ?: '/';
                    $normRedir = rtrim($redirectPath, '/') ?: '/';
                    if ($normReq !== $normRedir) {
                        $result['is_login'] = true;
                        return $result;
                    }
                }
            }
        }
        $body = $this->httpGet($url, 5);
        if (is_string($body) && $body !== '' && ($result['status'] === 200 || $result['status'] === 403)) {
            $result['body'] = $body;
            if ($this->isWpLoginPage($body, $url)) {
                $result['is_login'] = true;
            }
        }
        return $result;
    }

    /**
     * Check whether HTML is a WordPress login page.
     */
    private function isWpLoginPage(string $body, string $url = ''): bool
    {
        $lower = strtolower($body);
        // Most reliable WordPress login form markers
        if (str_contains($lower, 'id="loginform"') || str_contains($lower, "id='loginform'")) {
            return true;
        }
        if (str_contains($lower, 'name="log"') && str_contains($lower, 'name="pwd"') && str_contains($lower, 'wp-submit')) {
            return true;
        }
        if (str_contains($lower, 'name="log"') && str_contains($lower, 'name="pwd"') && str_contains($lower, 'wordpress')) {
            return true;
        }
        // wp-login header + form
        if (str_contains($lower, 'wp-login.php') && str_contains($lower, 'wordpress') && str_contains($lower, '<form')) {
            // Make sure this is not just a content mention but the actual login page
            if (preg_match('~<form[^>]*\baction\s*=\s*["\'][^"\']*wp-login\.php["\']~i', $body)) {
                return true;
            }
        }
        // Fallback: if the URL is wp-login.php and the body has "log in" + wordpress
        if (str_contains(strtolower($url), 'wp-login.php') && str_contains($lower, 'wordpress') && (str_contains($lower, 'log in') || str_contains($lower, 'увійти') || str_contains($lower, 'вхід'))) {
            return true;
        }
        return false;
    }

    /**
     * Extract custom login-path candidates from HTML.
     *
     * @return string[] list of paths/URLs (e.g. "/my-login/", "/hidden-admin/")
     */
    private function extractLoginCandidates(string $html): array
    {
        $candidates = [];
        if (preg_match_all('~href\s*=\s*["\']([^"\']+)["\']~i', $html, $m)) {
            foreach ($m[1] as $href) {
                $href = html_entity_decode(trim($href), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($href === '' || $href === '#') continue;
                $lowerHref = strtolower($href);
                if (str_starts_with($lowerHref, 'javascript:') || str_starts_with($lowerHref, 'mailto:') || str_starts_with($lowerHref, 'tel:') || str_starts_with($lowerHref, 'data:')) {
                    continue;
                }
                // Skip static resources
                if (preg_match('~\.(css|js|mjs|jpg|jpeg|png|gif|webp|avif|svg|woff2?|ttf|eot|pdf|zip|mp4|mp3)(?:[?#]|$)~i', $lowerHref)) {
                    continue;
                }
                // Skip wp-content / wp-includes
                if (str_contains($lowerHref, '/wp-content/') || str_contains($lowerHref, '/wp-includes/')) {
                    continue;
                }
                // Only those containing login-like keywords
                if (!preg_match('~(login|log-in|signin|sign-in|admin|dashboard|auth|enter|my-login|secret)~i', $href)) {
                    continue;
                }
                // Exclude logout
                if (str_contains($lowerHref, 'logout') || str_contains($lowerHref, 'action=logout')) {
                    continue;
                }
                // Normalization
                $path = strtok($href, '#') ?: $href;
                if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
                    $parts = parse_url($path);
                    if (!isset($parts['host'])) continue;
                    $host = strtolower($parts['host']);
                    $ownHost = strtolower(parse_url($this->url, PHP_URL_HOST) ?? '');
                    if ($host !== $ownHost && $host !== 'www.' . $ownHost && $ownHost !== 'www.' . $host) {
                        continue; // foreign domain
                    }
                    $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
                } elseif (str_starts_with($path, '//')) {
                    continue;
                } elseif (!str_starts_with($path, '/')) {
                    // relative path — convert to absolute
                    if (!str_contains($path, '/') && strlen($path) < 3) continue;
                    if (str_starts_with($path, './')) $path = substr($path, 2);
                    $path = '/' . ltrim($path, '/');
                }
                if (!str_starts_with($path, '/')) continue;
                if (strlen($path) > 160) continue;
                // Duplicates
                $candidates[$path] = true;
                if (count($candidates) >= 20) break;
            }
        }
        return array_keys($candidates);
    }

    /**
     * Resolve a relative/absolute Location into a full URL.
     */
    private function resolveUrl(string $location, string $origin): string
    {
        $location = trim($location);
        if ($location === '') return $origin . '/';
        if (preg_match('~^https?://~i', $location)) return $location;
        if (str_starts_with($location, '//')) return $this->scheme . ':' . $location;
        if (str_starts_with($location, '/')) return $origin . $location;
        return rtrim($origin, '/') . '/' . ltrim($location, '/');
    }

    /**
     * Fill in plugin versions from non-asset sources on the page (only for entries
     * without a version — never overwrites):
     * - Yoast SEO writes the version into a comment `<!-- ... Yoast SEO plugin vX.Y ... -->`;
     * - All in One SEO writes the version into the meta generator `All in One SEO (AIOSEO) X.Y`.
     *
     * @param array<int, array<string, mixed>> $plugins
     */
    private function fillPluginVersionsFromPage(array &$plugins, string $html, ?string $generator): void
    {
        $extra = [];
        if (preg_match('~Yoast SEO plugin v([0-9][0-9A-Za-z._-]*)~i', $html, $m)
            && preg_match('~^\d+\.\d+~', $m[1])) {
            $extra['wordpress-seo'] = [$m[1], 'html-comment'];
        }
        if (is_string($generator) && $generator !== ''
            && preg_match('~All in One SEO \(AIOSEO\) ([0-9][0-9A-Za-z._-]*)~i', $generator, $m)
            && preg_match('~^\d+\.\d+~', $m[1])) {
            $extra['all-in-one-seo-pack'] = [$m[1], 'meta-generator'];
        }

        if (empty($extra)) {
            return;
        }
        foreach ($plugins as &$p) {
            $slug = $p['slug'] ?? null;
            if (is_string($slug) && isset($extra[$slug]) && empty($p['version'])) {
                [$ver, $src] = $extra[$slug];
                $p['version'] = $ver;
                $p['version_source'] = $src;
            }
        }
        unset($p);
    }

    /**
     * WordPress version detection from reliable sources.
     *
     * Priority (returns STRUCTURED info, not just a string):
     *   1. `<meta name="generator" content="WordPress X.Y.Z">` — generated dynamically
     *      on every request, so this is the most reliable signal. Returns the EXACT version.
     *   2. `/readme.html` — a static file shipped with the core. May be
     *      outdated, so it is used as a fallback. Returns the EXACT version.
     *   3. `Tested up to: X.Y` header in the active (or parent) theme's `style.css` —
     *      the theme author updates this field after testing with a new WP version. Very
     *      close to the exact version (usually matches or lags by 1 minor).
     *   4. REST endpoints `/wp-json/` — give a MINIMUM lower bound of the version
     *      (presence of `wp-abilities/v1` means ≥ 7.0).
     *   5. Twemoji version from `wp-includes/js/wp-emoji-release.min.js` — an extra
     *      signal for newer WP versions (≥ 6.0).
     *
     * No fallback on `?ver=` in `/wp-includes/` for scripts: it often
     * holds the jQuery version (`jquery.min.js?ver=3.7.1`), not WordPress.
     *
     * @param array<string, mixed>|null $theme        active theme data (from `detectWordPressTheme`)
     * @param array<string, mixed>|null $parentTheme  parent theme data (from `fetchThemeInfo`), if any
     * @return array{
     *   version: ?string,        // exact version, if determined
     *   version_min: ?string,    // lower version bound from all available signals
     *   source: string,          // 'generator' | 'readme' | 'theme_tested' | 'rest_api' | 'twemoji' | 'hidden'
     *   note: ?string            // user-facing explanation
     * }
     */
    private function detectWordPressVersion(string $html, ?string $generator = null, ?array $theme = null, ?array $parentTheme = null): array
    {
        $result = [
            'version' => null,
            'version_min' => null,
            'source' => 'hidden',
            'note' => null,
        ];

        // 1. meta generator — the most accurate signal (generated dynamically).
        $gen = $generator ?? $this->extractMeta($html, 'generator');
        if (is_string($gen) && $gen !== '' && preg_match('~^\s*WordPress\s+([0-9][0-9.]*(?:-[A-Za-z0-9.-]+)?)\s*$~i', $gen, $m)) {
            $result['version'] = $m[1];
            $result['version_min'] = $m[1];
            $result['source'] = 'generator';
            $result['note'] = null;
            return $result;
        }

        // 2. /readme.html — a static core file, may be outdated.
        $readme = $this->httpGet($this->url . '/readme.html', 6);
        if ($readme) {
            if (preg_match(
                '~<p\b[^>]*\bstyle\s*=\s*["\'][^"\']*\btext-align\s*:\s*center\b[^"\']*["\'][^>]*>\s*(?:<strong>)?\s*Version\s+([0-9][0-9.]*(?:-[A-Za-z0-9.-]+)?)\s*(?:</strong>)?~i',
                $readme,
                $m
            )) {
                $result['version'] = $m[1];
                $result['version_min'] = $m[1];
                $result['source'] = 'readme';
                $result['note'] = null;
                return $result;
            }
        }

        // 3. "Tested up to" header in style.css.
        // Look at the active theme first, then the parent theme (child themes
        // often lack the "Tested up to" field; the parent defines the real version).
        $testedSource = null;
        $testedVersion = null;
        $testedThemeName = null;

        if (is_array($theme) && !empty($theme['tested_up_to'])) {
            $testedSource = $theme;
            $testedVersion = $theme['tested_up_to'];
            $testedThemeName = $theme['name'] ?? $theme['slug'] ?? null;
        } elseif (is_array($parentTheme) && !empty($parentTheme['tested_up_to'])) {
            $testedSource = $parentTheme;
            $testedVersion = $parentTheme['tested_up_to'];
            $testedThemeName = $parentTheme['name'] ?? $parentTheme['slug'] ?? null;
        }

        if ($testedVersion !== null && preg_match('~^([0-9]+(?:\.[0-9]+){1,2})~', $testedVersion, $m)) {
            $result['version'] = $m[1];
            $result['version_min'] = $m[1];
            $result['source'] = 'theme_tested';
            $result['note'] = sprintf(
                'Визначено за полем «Tested up to» у style.css теми «%s». Точна версія WP може бути новішою.',
                $testedThemeName ?: 'невідомо'
            );
            return $result;
        }

        // 4-5. Lower version bound: REST endpoints + twemoji version.
        $restMin = $this->detectWordPressVersionFromRest();
        $twemojiMin = $this->detectWordPressVersionFromTwemoji();

        $candidates = array_filter([$restMin, $twemojiMin], static fn($v) => is_string($v) && $v !== '');
        if (!empty($candidates)) {
            $bestMin = null;
            foreach ($candidates as $v) {
                if ($bestMin === null || version_compare($v, $bestMin, '>')) {
                    $bestMin = $v;
                }
            }
            $result['version_min'] = $bestMin;
            $result['source'] = $twemojiMin !== null && ($restMin === null || version_compare($twemojiMin, $restMin, '>'))
                ? 'twemoji'
                : 'rest_api';
            $result['note'] = sprintf(
                'Точна версія прихована власником сайту. Відомо лише, що вона ≥ %s.',
                $bestMin
            );
        }

        return $result;
    }

    /**
     * Determine the minimum lower bound of the WordPress version from REST endpoints.
     * This is NOT the exact version — only a guaranteed lower bound.
     *
     * WordPress 7.0+ routes (`wp-abilities/v1`, `wp-block-editor/v1`) were added so that
     * a site on WP 7.x does not show an outdated version just because
     * we only know routes up to 6.6.
     */
    private function detectWordPressVersionFromRest(): ?string
    {
        $body = $this->httpGet($this->url . '/wp-json/', 6);
        if (!$body) {
            return null;
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            return null;
        }

        $routes = $data['routes'] ?? null;
        if (!is_array($routes)) {
            return null;
        }

        $namespaces = is_array($data['namespaces'] ?? null) ? $data['namespaces'] : [];

        // Mapping "present route → minimum WP version".
        // WP 7.0+ routes added from release notes / dev blogs.
        $hints = [
            // WP 7.0+ — Abilities API
            '/wp-abilities/v1'                  => '7.0',
            '/wp-abilities/v1/categories'       => '7.0',
            '/wp-abilities/v1/abilities'        => '7.0',
            // WP 7.0+ — Block editor REST namespace (export, navigation-fallback)
            '/wp-block-editor/v1'               => '7.0',
            '/wp-block-editor/v1/export'        => '7.0',
            '/wp-block-editor/v1/navigation-fallback' => '7.0',
            // WP 6.5+ — Font Library
            '/wp/v2/font-collections'           => '6.5',
            '/wp/v2/font-families'              => '6.5',
            '/wp/v2/fonts'                      => '6.5',
            // WP 6.6+ — Icons
            '/wp/v2/icons'                      => '6.6',
            // WP 6.0+ — Pattern categories
            '/wp/v2/block-patterns/categories'  => '6.0',
            // WP 5.9+ — Patterns & block-based themes
            '/wp/v2/block-patterns/patterns'    => '5.9',
            '/wp/v2/global-styles'              => '5.9',
            // WP 5.8+ — comment meta + block templates
            '/wp/v2/comments'                   => '5.8',
            // WP 5.5+ — block directory
            '/wp/v2/block-directory/search'     => '5.5',
            // WP 5.3+ — new site editor endpoints
            '/wp/v2/templates'                  => '5.3',
            // WP 5.0+ — Gutenberg
            '/wp/v2/blocks'                     => '5.0',
            // WP 4.9+ — Gutenberg
            '/wp/v2/widgets'                    => '4.9',
            // WP 4.7+ — REST API baseline
            '/wp/v2/settings'                   => '4.7',
        ];

        $best = null;
        foreach ($hints as $route => $minVer) {
            if (isset($routes[$route])) {
                if ($best === null || version_compare($minVer, $best, '>')) {
                    $best = $minVer;
                }
            }
        }

        // Extra namespace check
        foreach ($namespaces as $ns) {
            if (!is_string($ns)) {
                continue;
            }
            if ($ns === 'wp-abilities/v1' || $ns === 'wp-block-editor/v1') {
                if ($best === null || version_compare('7.0', $best, '>')) {
                    $best = '7.0';
                }
            }
        }

        return $best;
    }

    /**
     * Determine the minimum lower bound of the WordPress version from the twemoji version
     * loaded from `wp-includes/js/wp-emoji-release.min.js`.
     *
     * This is NOT an exact signal (twemoji may lag behind WP), but it is useful as
     * an extra lower bound for WP 6.0+, where the twemoji version is updated together
     * with the core.
     *
     * @return string|null minimum WP version or null if it could not be determined
     */
    private function detectWordPressVersionFromTwemoji(): ?string
    {
        $body = $this->httpGet($this->url . '/wp-includes/js/wp-emoji-release.min.js', 4);
        if (!is_string($body) || $body === '') {
            return null;
        }
        if (!preg_match('~twemoji@(\d+)\.(\d+)\.(\d+)~', $body, $m)) {
            return null;
        }
        $major = (int)$m[1];
        $minor = (int)$m[2];
        $patch = (int)$m[3];

        // Map twemoji version → minimum WP version.
        // Values picked from official WordPress release notes.
        // If twemoji is at or above the threshold, return the matching minimum WP version.
        $map = [
            ['twemoji' => [15, 1, 0], 'wp' => '6.3'],
            ['twemoji' => [16, 0, 0], 'wp' => '6.6'],
            ['twemoji' => [17, 0, 0], 'wp' => '6.8'],
            ['twemoji' => [18, 0, 0], 'wp' => '7.1'],
        ];

        $best = null;
        foreach ($map as $entry) {
            [$tMaj, $tMin, $tPat] = $entry['twemoji'];
            $wpMin = $entry['wp'];
            $twemojiVer = [$major, $minor, $patch];
            $twemojiMin = [$tMaj, $tMin, $tPat];
            if ($twemojiVer >= $twemojiMin) {
                if ($best === null || version_compare($wpMin, $best, '>')) {
                    $best = $wpMin;
                }
            }
        }

        return $best;
    }

    /**
     * Detect all page builders used on the site.
     *
     * Returns an array — a site may use Elementor,
     * WPBakery, and other combinations at the same time.
     *
     * NOTE: Gutenberg (Block Editor) is deliberately NOT included here — it is core
     * WordPress by default and is often present alongside Elementor,
     * so showing it would only add noise.
     *
     * For each candidate check three signal levels in priority order:
     *   1. body class    — most accurate
     *   2. plugin        — confirms installation
     *   3. HTML traces   — most generic (block classes, attributes, comments)
     *
     * @return array<int, array{name:string,description:string,site:string,detection:string}>|null
     */
    private function detectPageBuilder(string $html, array $plugins): ?array
    {
        $bodyClass = $this->extractBodyClass($html);
        $lowerBody = strtolower($bodyClass);
        $lowerHtml = strtolower($html);

        $pluginSlugs = [];
        foreach ($plugins as $p) {
            if (!empty($p['slug']) && is_string($p['slug'])) {
                $pluginSlugs[] = strtolower($p['slug']);
            }
        }

        $builders = [
            [
                'name' => 'Elementor',
                'description' => 'Популярний конструктор сторінок з drag-and-drop інтерфейсом.',
                'site' => 'https://elementor.com',
                'body_classes' => ['elementor-page', 'elementor-default', 'elementor-editor-active'],
                'plugin_slugs' => ['elementor', 'elementor-pro'],
                'signs' => [
                    '/wp-content/plugins/elementor/',
                    '/wp-content/plugins/elementor-pro/',
                    'class="elementor-widget-',
                    'class=\'elementor-widget-',
                ],
            ],
            [
                'name' => 'Divi Builder',
                'description' => 'Конструктор від Elegant Themes (часто разом із темою Divi).',
                'site' => 'https://www.elegantthemes.com',
                'body_classes' => ['et_pb_builder', 'et_pb_pagebuilder_layout', 'et_pb_root', 'et-fb-root-ancestor'],
                'plugin_slugs' => ['divi-builder', 'et-builder'],
                'signs' => ['/wp-content/themes/Divi/', 'et_pb_', 'divi-builder-script'],
            ],
            [
                'name' => 'Bricks',
                'description' => 'Сучасний конструктор, орієнтований на продуктивність і чистий код.',
                'site' => 'https://bricksbuilder.io',
                'body_classes' => ['bricks-is-frontend', 'bricks-builder'],
                'plugin_slugs' => ['bricks', 'bricksbuilder'],
                'signs' => ['/wp-content/themes/bricks/'],
            ],
            [
                'name' => 'Beaver Builder',
                'description' => 'Гнучкий конструктор для дизайнерів і розробників.',
                'site' => 'https://www.wpbeaverbuilder.com',
                'body_classes' => ['fl-builder', 'fl-builder-active', 'fl-builder-frame'],
                'plugin_slugs' => ['beaver-builder-lite-version', 'beaver-builder', 'bb-plugin', 'bb-theme-builder', 'ultimate-addons-for-beaver-builder'],
                'signs' => ['/wp-content/plugins/bb-plugin/', '/wp-content/plugins/beaver-builder/'],
            ],
            [
                'name' => 'WPBakery (Visual Composer)',
                'description' => 'Один із найпопулярніших конструкторів, особливо в темах зі стажем.',
                'site' => 'https://wpbakery.com',
                'body_classes' => ['wpb_row', 'vc_row', 'vc_row-o-full-height', 'wpb_column'],
                'plugin_slugs' => ['js_composer', 'visual_composer', 'wpbakery-visual-composer'],
                'signs' => ['/wp-content/plugins/js_composer/'],
            ],
            [
                'name' => 'SiteOrigin Page Builder',
                'description' => 'Безкоштовний конструктор від SiteOrigin.',
                'site' => 'https://siteorigin.com',
                'body_classes' => ['siteorigin-panels', 'panel-grid', 'siteorigin_widget'],
                'plugin_slugs' => ['siteorigin-panels'],
                'signs' => ['/wp-content/plugins/siteorigin-panels/'],
            ],
            [
                'name' => 'Thrive Architect',
                'description' => 'Конструктор від Thrive Themes із фокусом на конверсії.',
                'site' => 'https://thrivethemes.com/architect',
                'body_classes' => [],
                'plugin_slugs' => ['thrive-visual-editor', 'thrive-architect', 'thrive-theme-builder'],
                'signs' => ['/wp-content/plugins/thrive-visual-editor/', 'thrive-'],
            ],
            [
                'name' => 'Oxygen',
                'description' => 'Потужний конструктор для розробників, замінює стандартний шаблон.',
                'site' => 'https://oxygenbuilder.com',
                'body_classes' => [],
                'plugin_slugs' => ['oxygen', 'oxygen-woocommerce'],
                'signs' => ['/wp-content/plugins/oxygen/', 'ct-css-'],
            ],
            [
                'name' => 'Avada Live (Fusion Builder)',
                'description' => 'Конструктор від теми Avada.',
                'site' => 'https://avada.theme-fusion.com',
                'body_classes' => [],
                'plugin_slugs' => ['fusion-builder', 'fusion-core', 'avada-builder'],
                'signs' => ['/wp-content/themes/Avada/', '/wp-content/plugins/fusion-builder/'],
            ],
            [
                'name' => 'Live Composer',
                'description' => 'Безкоштовний front-end конструктор.',
                'site' => 'https://livecomposerplugin.com',
                'body_classes' => ['dslca-enabled'],
                'plugin_slugs' => ['live-composer-page-builder'],
                'signs' => ['/wp-content/plugins/live-composer-page-builder/'],
            ],
        ];

        $detected = [];
        foreach ($builders as $builder) {
            $method = null;

            // 1. body class — the most reliable signal
            foreach ($builder['body_classes'] as $cls) {
                if ($cls !== '' && str_contains($lowerBody, strtolower($cls))) {
                    $method = 'body_class';
                    break;
                }
            }

            // 2. plugin in the detected list
            if ($method === null) {
                foreach ($builder['plugin_slugs'] as $slug) {
                    if (in_array(strtolower($slug), $pluginSlugs, true)) {
                        $method = 'plugin';
                        break;
                    }
                }
            }

            // 3. characteristic HTML traces
            if ($method === null) {
                foreach ($builder['signs'] as $sign) {
                    if ($sign !== '' && str_contains($lowerHtml, strtolower($sign))) {
                        $method = 'html';
                        break;
                    }
                }
            }

            if ($method !== null) {
                $detected[] = [
                    'name' => $builder['name'],
                    'description' => $builder['description'],
                    'site' => $builder['site'],
                    'detection' => $method,
                ];
            }
        }

        return empty($detected) ? null : $detected;
    }

    /**
     * WooCommerce presence detection plus connected payment/shipping modules.
     */
    private function detectWooCommerce(string $html, array $plugins): ?array
    {
        $lowerHtml = strtolower($html);

        $pluginSlugs = [];
        $wooVersion = null;
        $hasWoo = false;

        foreach ($plugins as $p) {
            if (empty($p['slug']) || !is_string($p['slug'])) {
                continue;
            }
            $slug = strtolower($p['slug']);
            $pluginSlugs[] = $slug;

            if ($slug === 'woocommerce') {
                $hasWoo = true;
                if (!empty($p['version'])) {
                    $wooVersion = $p['version'];
                }
            }
        }

        // Extra WooCommerce signs in HTML
        if (!$hasWoo) {
            if (str_contains($lowerHtml, '/wp-content/plugins/woocommerce/')
                || str_contains($lowerHtml, 'wc-ajax')
                || str_contains($lowerHtml, 'woocommerce-') ) {
                $hasWoo = true;
            }
        }

        if (!$hasWoo) {
            return null;
        }

        $paymentSlugs = [
            'woocommerce-gateway-stripe' => 'Stripe',
            'woocommerce-stripe-gateway' => 'Stripe',
            'stripe' => 'Stripe',
            'woocommerce-paypal-payments' => 'PayPal',
            'paypal-for-woocommerce' => 'PayPal',
            'woocommerce-gateway-paypal-express-checkout' => 'PayPal Express',
            'woocommerce-square' => 'Square',
            'square' => 'Square',
            'woocommerce-braintree' => 'Braintree',
            'braintree-payments' => 'Braintree',
            'mollie-payments-for-woocommerce' => 'Mollie',
            'woocommerce-adyen' => 'Adyen',
            'adyen-for-woocommerce' => 'Adyen',
            'razorpay-for-woocommerce' => 'Razorpay',
            'woocommerce-payments' => 'WooCommerce Payments',
            'amazon-pay' => 'Amazon Pay',
            'klarna-payments-for-woocommerce' => 'Klarna',
            'klarna-checkout-for-woocommerce' => 'Klarna Checkout',
            'afterpay-for-woocommerce' => 'Afterpay',
            'payfast-for-woocommerce' => 'Payfast',
            'woocommerce-eway' => 'eWay',
            'woocommerce-authorize-net' => 'Authorize.Net',
            'woocommerce-2checkout' => '2Checkout',
            'woocommerce-trustpayments' => 'Trust Payments',
            'woocommerce-checkout-com' => 'Checkout.com',
            'woocommerce-gateway-worldpay' => 'Worldpay',
            'woocommerce-gateway-sagepay' => 'SagePay',
        ];

        $shippingSlugs = [
            'woocommerce-shipment-tracking' => 'Shipment Tracking',
            'table-rate-shipping' => 'Table Rate Shipping',
            'woocommerce-shipping' => 'WooCommerce Shipping',
            'woocommerce-ups' => 'UPS',
            'woocommerce-fedex' => 'FedEx',
            'woocommerce-services' => 'WooCommerce Services',
            'woocommerce-australia-post' => 'Australia Post',
            'woocommerce-canada-post' => 'Canada Post',
            'flexible-shipping' => 'Flexible Shipping',
            'flexible-shipping-woocommerce' => 'Flexible Shipping',
            'advanced-flat-rate-shipping' => 'Advanced Flat Rate',
            'woocommerce-local-pickup-plus' => 'Local Pickup Plus',
            'printful-shipping' => 'Printful',
            'printify' => 'Printify',
            'woocommerce-dpd' => 'DPD',
            'woocommerce-gls' => 'GLS',
            'woocommerce-posti' => 'Posti',
            'woocommerce-table-rate-shipping' => 'Table Rate',
        ];

        $paymentGateways = [];
        foreach ($pluginSlugs as $slug) {
            if (isset($paymentSlugs[$slug])) {
                $paymentGateways[] = $paymentSlugs[$slug];
            }
        }
        $paymentGateways = array_values(array_unique($paymentGateways));

        $shippingModules = [];
        foreach ($pluginSlugs as $slug) {
            if (isset($shippingSlugs[$slug])) {
                $shippingModules[] = $shippingSlugs[$slug];
            }
        }
        $shippingModules = array_values(array_unique($shippingModules));

        $urls = [
            'shop' => str_contains($lowerHtml, '/shop/') || str_contains($lowerHtml, '/product/'),
            'cart' => str_contains($lowerHtml, '/cart/'),
            'checkout' => str_contains($lowerHtml, '/checkout/'),
            'my_account' => str_contains($lowerHtml, '/my-account/'),
        ];

        return [
            'active' => true,
            'version' => $wooVersion,
            'payment_gateways' => $paymentGateways,
            'shipping_modules' => $shippingModules,
            'urls' => $urls,
        ];
    }

    private function detectWordPressTheme(string $html): ?array
    {
        $bodyClass = $this->extractBodyClass($html);
        $candidates = [];

        // 1. Most reliable — body class from WP core (`body_class()`):
        //    when a child theme is active, WP adds both `wp-theme-XXX` (parent)
        //    and `wp-child-theme-XXX` (active).
        if (preg_match('~wp-child-theme-([a-z0-9_-]+)~i', $bodyClass, $m)) {
            $slug = strtolower($m[1]);
            $candidates[$slug] = ($candidates[$slug] ?? 0) + 200; // top priority
        } elseif (preg_match('~wp-theme-([a-z0-9_-]+)~i', $bodyClass, $m)) {
            $slug = strtolower($m[1]);
            $candidates[$slug] = ($candidates[$slug] ?? 0) + 150;
        }

        // 2. Direct links to /wp-content/themes/SLUG/
        if (preg_match_all('~/wp-content/themes/([^/"\']+)/~i', $html, $matches)) {
            foreach ($matches[1] as $slug) {
                $slug = strtolower(trim($slug));
                if ($slug === '' || str_contains($slug, '..')) {
                    continue;
                }
                $candidates[$slug] = ($candidates[$slug] ?? 0) + 1;
            }
        }

        // 3. Try to get the active theme via /wp-json/ (some sites expose it)
        $apiBody = $this->httpGet($this->url . '/wp-json/', 6);
        if ($apiBody) {
            $api = json_decode($apiBody, true);
            if (is_array($api)) {
                foreach (['themes', 'active_theme', 'stylesheet'] as $key) {
                    if (!empty($api[$key]) && is_string($api[$key])) {
                        $slug = strtolower(trim($api[$key]));
                        if ($slug !== '') {
                            $candidates[$slug] = ($candidates[$slug] ?? 0) + 50;
                        }
                    }
                }
                if (!empty($api['themes']) && is_array($api['themes'])) {
                    foreach ($api['themes'] as $themeEntry) {
                        if (is_array($themeEntry) && !empty($themeEntry['stylesheet'])) {
                            $slug = strtolower(trim($themeEntry['stylesheet']));
                            $candidates[$slug] = ($candidates[$slug] ?? 0) + 50;
                        }
                    }
                }
            }
        }

        if (empty($candidates)) {
            return null;
        }

        arsort($candidates);
        $themeSlug = array_key_first($candidates);

        $info = ['slug' => $themeSlug];
        $styleCss = $this->httpGet($this->url . '/wp-content/themes/' . $themeSlug . '/style.css', 6);
        if ($styleCss) {
            $header = $this->parseWpThemeHeader($styleCss);
            if (!empty($header['name'])) {
                $info['name'] = $header['name'];
            }
            if (!empty($header['version'])) {
                $info['version'] = $header['version'];
            }
            if (!empty($header['author'])) {
                $info['author'] = $header['author'];
            }
            if (!empty($header['homepage'])) {
                $info['homepage'] = $header['homepage'];
            }
            if (!empty($header['description'])) {
                $info['description'] = $this->truncate($header['description'], 280);
            }
            if (!empty($header['testedUpTo'])) {
                $info['tested_up_to'] = $header['testedUpTo'];
            }
            if (!empty($header['requiresAtLeast'])) {
                $info['requires_at_least'] = $header['requiresAtLeast'];
            }
            if (!empty($header['template'])) {
                // "Template:" in the header points to the parent theme for a child theme
                $parentSlug = strtolower(trim($header['template']));
                if ($parentSlug !== '' && $parentSlug !== $themeSlug) {
                    $info['parent_slug'] = $parentSlug;
                }
            }
        }

        return $info;
    }

    /**
     * Load theme info (usually the parent) by its slug.
     */
    private function fetchThemeInfo(string $slug): ?array
    {
        $styleCss = $this->httpGet($this->url . '/wp-content/themes/' . $slug . '/style.css', 6);
        if (!$styleCss) {
            return null;
        }
        $info = ['slug' => $slug];
        $header = $this->parseWpThemeHeader($styleCss);
        if (!empty($header['name'])) {
            $info['name'] = $header['name'];
        } else {
            $info['name'] = ucwords(str_replace(['-', '_'], ' ', $slug));
        }
        if (!empty($header['version'])) {
            $info['version'] = $header['version'];
        }
        if (!empty($header['author'])) {
            $info['author'] = $header['author'];
        }
        if (!empty($header['homepage'])) {
            $info['homepage'] = $header['homepage'];
        }
        if (!empty($header['description'])) {
            $info['description'] = $this->truncate($header['description'], 280);
        }
        if (!empty($header['testedUpTo'])) {
            $info['tested_up_to'] = $header['testedUpTo'];
        }
        if (!empty($header['requiresAtLeast'])) {
            $info['requires_at_least'] = $header['requiresAtLeast'];
        }
        return $info;
    }

    /**
     * Extract the class attribute value from the <body> tag.
     */
    private function extractBodyClass(string $html): string
    {
        if (preg_match('~<body\b[^>]*\bclass\s*=\s*["\']([^"\']+)["\']~i', $html, $m)) {
            return $m[1];
        }
        return '';
    }

    /**
     * WordPress active plugin detection.
     * As in Wappalyzer: collect slugs from all asset URLs (/wp-content/plugins/SLUG/...)
     * and immediately take the version from ?ver= (no extra HTTP requests).
     * A ?ver= value repeated in ≥4 different plugins is dropped —
     * it is typically the WP core version that WP substitutes by default.
     */
    private function detectWordPressPlugins(string $html): array
    {
        $slugs = $this->extractPluginSlugs($html); // slug => ['count' => int, 'ver' => ?string]
        $this->dropSharedAssetVersions($slugs);

        // Subpage request: plugins like Kama SpamBlock are only loaded
        // where there is a comments form (a post page), not on the homepage.
        // Fresh post permalink via REST (1 request) + the page itself
        // (1 request, short timeout). On failure — silently skip.
        $subHtml = $this->fetchWordPressSubpageSample($html);
        if (is_string($subHtml) && $subHtml !== '') {
            foreach ($this->extractPluginSlugs($subHtml) as $slug => $meta) {
                if (!isset($slugs[$slug])) {
                    $slugs[$slug] = $meta;
                } elseif ($slugs[$slug]['ver'] === null && $meta['ver'] !== null) {
                    $slugs[$slug]['ver'] = $meta['ver']; // picked up the version from the subpage
                }
            }
            $this->dropSharedAssetVersions($slugs);
            $this->matchPluginMarkers(
                strtolower($this->stripNoiseForDetection($this->extractPluginSurface($subHtml))),
                $slugs
            );
        }

        $plugins = [];
        $resolvedSlugs = [];
        foreach ($slugs as $slug => $meta) {
            $entry = $this->resolveWpPlugin($slug, $meta['ver']);
            $entry['source'] = !empty($meta['marker']) ? 'marker' : ($meta['ver'] !== null ? 'asset' : 'asset-path');
            $plugins[] = $entry;
            $resolvedSlugs[$slug] = true;
        }

        // Markers without an asset path: plugins that do not attach CSS/JS on
        // the scanned pages but leave comments/attributes
        // (e.g. Rank Math only adds <!-- ... Rank Math ... -->).
        // The dictionary is in WP_PLUGIN_HTML_MARKERS.
        $surfaceLower = strtolower($this->stripNoiseForDetection($this->extractPluginSurface($html)));
        $this->matchPluginMarkers($surfaceLower, $slugs);
        foreach ($slugs as $slug => $meta) {
            if (isset($resolvedSlugs[$slug])) {
                continue;
            }
            // matchPluginMarkers added new slugs — resolve them as marker
            $entry = $this->resolveWpPlugin($slug, $meta['ver']);
            $entry['source'] = 'marker';
            $plugins[] = $entry;
        }

        // Sort by name
        usort($plugins, function ($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });

        return $plugins;
    }

    /**
     * Collect plugin slugs from asset URLs in HTML (paths + ?ver=).
     *
     * @return array<string, array{count: int, ver: ?string}>
     */
    private function extractPluginSlugs(string $html): array
    {
        $slugs = [];

        // a) Asset URLs with ?ver= — immediately record a version candidate.
        if (preg_match_all(
            '~/wp-content/plugins/([^/"\'?#\s]+)/[^"\'\s<>]*?[?&]ver=([A-Za-z0-9][A-Za-z0-9._-]*)~i',
            $html,
            $m,
            PREG_SET_ORDER
        )) {
            foreach ($m as $hit) {
                $slug = strtolower(trim($hit[1]));
                if (!$this->isValidPluginSlug($slug)) {
                    continue;
                }
                if (!isset($slugs[$slug])) {
                    $slugs[$slug] = ['count' => 0, 'ver' => null];
                }
                $slugs[$slug]['count']++;
                $ver = trim($hit[2], " \t\n\r\0\x0B\"'");
                if ($slugs[$slug]['ver'] === null && $this->isPlausibleAssetVersion($ver)) {
                    $slugs[$slug]['ver'] = $ver;
                }
            }
        }

        // b) Plain plugin path mentions (cover inline JSON, CSS @import, etc.).
        if (preg_match_all('~/wp-content/plugins/([^/"\'?#\s]+)/~i', $html, $matches)) {
            foreach ($matches[1] as $slug) {
                $slug = strtolower(trim($slug));
                if (!$this->isValidPluginSlug($slug)) {
                    continue;
                }
                if (!isset($slugs[$slug])) {
                    $slugs[$slug] = ['count' => 0, 'ver' => null];
                }
                $slugs[$slug]['count']++;
            }
        }

        // Filter out service/system paths that are not real plugins.
        foreach (['mu-plugins', 'languages', 'wp-content', 'plugin-dir'] as $bad) {
            unset($slugs[$bad]);
        }

        // c) Plugin-owned directories in uploads (Popup Maker keeps generated
        // styles in /wp-content/uploads/pum/, with no assets under /plugins/).
        foreach (self::WP_PLUGIN_UPLOADS_DIRS as $dir => $mappedSlug) {
            if (preg_match_all(
                '~/wp-content/uploads/' . preg_quote($dir, '~') . '/[^"\'\s<>]*?[?&]ver=([A-Za-z0-9][A-Za-z0-9._-]*)~i',
                $html,
                $m
            )) {
                foreach ($m[1] as $verRaw) {
                    $ver = trim($verRaw, " \t\n\r\0\x0B\"'");
                    if (!isset($slugs[$mappedSlug])) {
                        $slugs[$mappedSlug] = ['count' => 0, 'ver' => null];
                    }
                    $slugs[$mappedSlug]['count']++;
                    if ($slugs[$mappedSlug]['ver'] === null && $this->isPlausibleAssetVersion($ver)) {
                        $slugs[$mappedSlug]['ver'] = $ver;
                    }
                }
            } elseif (stripos($html, '/wp-content/uploads/' . $dir . '/') !== false) {
                if (!isset($slugs[$mappedSlug])) {
                    $slugs[$mappedSlug] = ['count' => 1, 'ver' => null];
                } else {
                    $slugs[$mappedSlug]['count']++;
                }
            }
        }

        return $slugs;
    }

    /**
     * Map "uploads directory → plugin slug" for plugins that generate
     * their files outside /plugins/ (and are thus invisible to the asset scan).
     */
    private const WP_PLUGIN_UPLOADS_DIRS = [
        'pum' => 'popup-maker',
    ];

    private function isValidPluginSlug(string $slug): bool
    {
        return $slug !== ''
            && !str_contains($slug, '..')
            && !str_contains($slug, '?')
            && (bool)preg_match('~^[a-z0-9][a-z0-9_-]*$~', $slug);
    }

    /**
     * Drop ?ver= values shared by ≥4 plugins — this is the WP core version
     * by default (wp_enqueue without $ver substitutes get_bloginfo('version')).
     *
     * @param array<string, array{count: int, ver: ?string}> $slugs
     */
    private function dropSharedAssetVersions(array &$slugs): void
    {
        $verFreq = [];
        foreach ($slugs as $meta) {
            if ($meta['ver'] !== null) {
                $verFreq[$meta['ver']] = ($verFreq[$meta['ver']] ?? 0) + 1;
            }
        }
        foreach ($verFreq as $ver => $cnt) {
            if ($cnt >= 4) {
                foreach ($slugs as $slug => $meta) {
                    if ($meta['ver'] === $ver) {
                        $slugs[$slug]['ver'] = null;
                    }
                }
            }
        }
    }

    /**
     * Look for WP_PLUGIN_HTML_MARKERS in the prepared surface
     * (lowercase, noise-free) and add found slugs into $slugs.
     *
     * @param array<string, array{count: int, ver: ?string}> $slugs
     */
    private function matchPluginMarkers(string $surfaceLower, array &$slugs): void
    {
        foreach (self::WP_PLUGIN_HTML_MARKERS as $slug => $markers) {
            if (isset($slugs[$slug])) {
                continue; // already found via asset path
            }
            foreach ($markers as $marker) {
                // Boundaries as in Wappalyzer: a marker must not be part of a longer
                // slug (e.g. class `tag-wordpress-elementor` from a blog tag —
                // this is NOT a sign of the Elementor plugin; while `elementor-widget` is).
                $pat = '~(?<![a-z0-9_-])' . preg_quote(strtolower($marker), '~') . '(?![a-z0-9_])~';
                if (preg_match($pat, $surfaceLower)) {
                    $slugs[$slug] = ['count' => 1, 'ver' => null, 'marker' => true];
                    break;
                }
            }
        }
    }

    /**
     * Return HTML of one subpage (a post page) to enrich the plugin list,
     * or null. Uses REST for a fresh post permalink.
     */
    private function fetchWordPressSubpageSample(string $html): ?string
    {
        // No point if the homepage already has a comments form — everything is visible there.
        if (preg_match('~comment-form|id="respond"|class="[^"]*comment-respond~i', $html)) {
            return null;
        }

        $postUrl = null;
        $rest = $this->httpGet($this->url . '/wp-json/wp/v2/posts?per_page=1&_fields=link', 5);
        if (is_string($rest) && $rest !== '') {
            $data = json_decode($rest, true);
            if (is_array($data) && isset($data[0]['link']) && is_string($data[0]['link'])
                && preg_match('~^https?://~i', $data[0]['link'])) {
                $postUrl = $data[0]['link'];
            }
        }
        if ($postUrl === null) {
            // Fallback: first internal link that looks like a post/page
            // (not pagination, not a tag/category, not a static file).
            $ownHost = strtolower(parse_url($this->url, PHP_URL_HOST) ?? '');
            if (preg_match_all('~href\s*=\s*["\']([^"\']+)["\']~i', $html, $m)) {
                foreach ($m[1] as $href) {
                    $href = html_entity_decode(trim($href), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    if (!preg_match('~^https?://~i', $href)) {
                        continue;
                    }
                    $parts = parse_url($href);
                    if (strtolower($parts['host'] ?? '') !== $ownHost) {
                        continue;
                    }
                    $path = strtolower($parts['path'] ?? '/');
                    if ($path === '/' || str_contains($path, '/page/')
                        || str_contains($path, '/tag/') || str_contains($path, '/category/')
                        || str_contains($path, '/author/')
                        || preg_match('~\.(css|js|jpg|jpeg|png|gif|webp|svg|pdf|zip|mp4)(?:[?#]|$)~', $path)) {
                        continue;
                    }
                    $postUrl = $href;
                    break;
                }
            }
        }
        if ($postUrl === null) {
            return null;
        }

        $body = $this->httpGet($postUrl, 8);
        if (!is_string($body) || $body === '' || stripos($body, '<html') === false) {
            return null;
        }
        return $body;
    }

    /**
     * Return the "surface" for plugin marker search: HTML comments +
     * tag attributes (src/href/class/id/...), WITHOUT page text content
     * and WITHOUT meta descriptions (except generator — AIOSEO-like tools write there).
     * Article/tag text like "Contact Form 7" or "Elementor" must not
     * count as a sign of an installed plugin.
     */
    private function extractPluginSurface(string $html): string
    {
        $parts = [];
        if (preg_match_all('~<!--(.*?)-->~s', $html, $m)) {
            $parts[] = implode("\n", $m[1]);
        }
        if (preg_match_all('~<([a-zA-Z][a-zA-Z0-9-]*)\b([^<>]*)>~', $html, $m, PREG_SET_ORDER)) {
            foreach ($m as $tag) {
                $tname = strtolower($tag[1]);
                $attrs = $tag[2];
                if ($tname === 'meta' && stripos($attrs, 'generator') === false) {
                    continue;
                }
                if ($tname === 'title' || $tname === 'a') {
                    // <a href="/tag/wordpress-elementor/"> is content navigation
                    // (tags/categories), not a plugin trace. Plugin assets live
                    // in script/link/img/form/input/div, not in links.
                    continue;
                }
                $parts[] = $attrs;
            }
        }
        return implode("\n", $parts);
    }

    /**
     * Non-asset traces of popular plugins: HTML comments, meta generator,
     * classes in markup. All markers are distinctive strings generated by the plugin itself
     * (as in Wappalyzer: dom/html/js patterns), not generic words.
     * slug => [markers]. All slugs must be in WP_PLUGIN_NAMES (no HTTP requests).
     */
    private const WP_PLUGIN_HTML_MARKERS = [
        'seo-by-rank-math' => ['rank math', 'rankmath'],
        'wordpress-seo' => ['yoast seo', '_yoast_wpseo_', 'yoast.com/wordpress/plugins/seo'],
        'all-in-one-seo-pack' => ['all in one seo', 'aioseo'],
        'seopress' => ['seopress'],
        'litespeed-cache' => ['litespeed cache'],
        'w3-total-cache' => ['w3 total cache'],
        'wp-rocket' => ['wp rocket'],
        'wp-super-cache' => ['wp-super-cache', 'wp super cache'],
        'autoptimize' => ['autoptimize'],
        'contact-form-7' => ['contact form 7', 'wpcf7'],
        'kama-spamblock' => ['kama_spamblock', 'kama spamblock'],
        'wordfence' => ['wordfence'],
        'ithemes-security' => ['ithemes security'],
        'sucuri-scanner' => ['sucuri security'],
        'really-simple-ssl' => ['really simple ssl'],
        'cookie-law-info' => ['cookie law info'],
        'complianz' => ['complianz'],
        'polylang' => ['polylang'],
        'sitepress-multilingual-cms' => ['sitepress', 'wpml-'],
        'jetpack' => ['jetpack'],
        'woocommerce' => ['woocommerce'],
        'elementor' => ['elementor'],
        'classic-editor' => ['classic editor'],
        'wpforms-lite' => ['wpforms'],
        'tablepress' => ['tablepress'],
        'nextgen-gallery' => ['nextgen gallery'],
    ];

    /**
     * Check whether a ?ver= value looks like a plugin version (not a timestamp/cache-buster).
     * Filters out unix timestamps (10+ digits), md5 hashes and non-numeric strings.
     */
    private function isPlausibleAssetVersion(string $ver): bool
    {
        if ($ver === '' || strlen($ver) > 24) {
            return false;
        }
        if (preg_match('~^[0-9]{10,}$~', $ver)) {
            return false; // timestamp
        }
        if (preg_match('~^[a-f0-9]{32}$~i', $ver)) {
            return false; // md5 cache-buster
        }
        return (bool)preg_match('~^\d+\.\d+~', $ver);
    }

    /**
     * Read a plugin's readme.txt and return the Stable tag (installed version),
     * or null (file closed / no tag / tag does not look like a version).
     */
    private function fetchPluginStableTag(string $slug): ?string
    {
        $readme = $this->httpGet($this->url . '/wp-content/plugins/' . $slug . '/readme.txt', 4);
        if (!is_string($readme) || $readme === '' || stripos($readme, '<html') !== false) {
            return null;
        }
        if (preg_match('~^[ \t*]*Stable tag:\s*([0-9][0-9A-Za-z._-]*)\s*$~im', $readme, $v)
            && preg_match('~^\d+\.\d+~', trim($v[1]))) {
            return trim($v[1]);
        }
        return null;
    }

    private function resolveWpPlugin(string $slug, ?string $assetVer = null): array
    {
        $info = ['slug' => $slug];

        if (isset(self::WP_PLUGIN_NAMES[$slug])) {
            $entry = self::WP_PLUGIN_NAMES[$slug];
            $info['name'] = $entry['name'];
            if (!empty($entry['site'])) {
                $info['site'] = $entry['site'];
            }
            if ($assetVer !== null) {
                $info['version'] = $assetVer;
                $info['version_source'] = 'asset-ver';
            } else {
                // The dictionary knows the name, but there is no version from assets (Polylang, Rank Math
                // etc. often attach nothing). Try readme.txt: the Stable tag
                // in the installed plugin's file is its installed version.
                $stable = $this->fetchPluginStableTag($slug);
                if ($stable !== null) {
                    $info['version'] = $stable;
                    $info['version_source'] = 'readme';
                }
            }
            return $info;
        }

        // Try reading the plugin readme.txt (Stable tag = release version).
        $readme = $this->httpGet($this->url . '/wp-content/plugins/' . $slug . '/readme.txt', 4);
        if (is_string($readme) && $readme !== '' && stripos($readme, '<html') === false
            && preg_match('~^[ \t*]*Plugin Name:\s*(.+?)\s*$~im', $readme, $m)) {
            $info['name'] = trim($m[1]);
            $version = null;
            $versionSource = null;
            if (preg_match('~^[ \t*]*Stable tag:\s*([0-9][0-9A-Za-z._-]*)\s*$~im', $readme, $v)
                && preg_match('~^\d+\.\d+~', trim($v[1]))) {
                $version = trim($v[1]);
                $versionSource = 'readme';
            } elseif ($assetVer !== null) {
                $version = $assetVer;
                $versionSource = 'asset-ver';
            }
            if ($version !== null) {
                $info['version'] = $version;
                $info['version_source'] = $versionSource;
            }
            return $info;
        }

        // Try reading the main PHP file header of the plugin.
        // index.php is deliberately skipped: in 99% it is a "Silence is golden" stub with no header.
        foreach ([$slug . '.php', 'plugin.php'] as $file) {
            $php = $this->httpGet($this->url . '/wp-content/plugins/' . $slug . '/' . $file, 4);
            if (!is_string($php) || $php === '' || stripos($php, '<html') !== false) {
                continue;
            }
            if (preg_match('~^[ \t*]*Plugin Name:\s*(.+?)\s*$~im', $php, $m)) {
                $info['name'] = trim($m[1]);
                $version = null;
                $versionSource = null;
                if (preg_match('~^[ \t*]*Version:\s*([0-9][0-9A-Za-z._-]*)\s*$~im', $php, $v)) {
                    $version = trim($v[1]);
                    $versionSource = 'plugin-header';
                } elseif ($assetVer !== null) {
                    $version = $assetVer;
                    $versionSource = 'asset-ver';
                }
                if ($version !== null) {
                    $info['version'] = $version;
                    $info['version_source'] = $versionSource;
                }
                return $info;
            }
        }

        // Fallback: prettify the slug; take the version from ?ver= if present.
        $info['name'] = ucwords(str_replace(['-', '_'], ' ', $slug));
        if ($assetVer !== null) {
            $info['version'] = $assetVer;
            $info['version_source'] = 'asset-ver';
        }
        return $info;
    }

    /**
     * Joomla details: core version, active template, third-party extensions, admin panel.
     * Stored in sections.cms[].joomla, rendered inside the CMS card.
     */
    private function detectJoomlaDetails(string $html, ?string $generator = null): ?array
    {
        $versionInfo = $this->detectJoomlaVersion($html, $generator);
        $template = $this->detectJoomlaTemplate($html);
        $extensions = $this->detectJoomlaExtensions($html);
        $adminInfo = $this->detectJoomlaAdminUrl();

        $hasAny = $versionInfo['version'] !== null
            || $template !== null
            || !empty($extensions)
            || ($adminInfo !== null && (!empty($adminInfo['url']) || !empty($adminInfo['is_hidden'])));

        if (!$hasAny) {
            return null;
        }

        return [
            'version' => $versionInfo['version'],
            'version_source' => $versionInfo['source'],
            'version_note' => $versionInfo['note'],
            'template' => $template,
            'extensions' => $extensions,
            'admin_url' => $adminInfo,
            'note' => 'Виявлено лише ті розширення, що лишили сліди на перевірених '
                . 'сторінках (asset-шляхи, коментарі). Системні плагіни без слідів '
                . 'дистанційно не видно.',
        ];
    }

    /**
     * Joomla version by priority:
     *  1. meta generator (dynamic, most accurate);
     *  2. /administrator/manifests/files/joomla.xml <version> (core file);
     *  3. /language/en-GB/en-GB.xml <version> (core language pack version).
     */
    private function detectJoomlaVersion(string $html, ?string $generator = null): array
    {
        $result = ['version' => null, 'source' => 'hidden', 'note' => null];

        $gen = $generator ?? $this->extractMeta($html, 'generator');
        if (is_string($gen) && $gen !== ''
            && preg_match('~Joomla!?(?:\s*-\s*Open Source Content Management)?\s*-?\s*Version\s+([0-9][0-9.]*)~i', $gen, $m)) {
            $result['version'] = $m[1];
            $result['source'] = 'generator';
            return $result;
        }

        $manifest = $this->httpGet($this->url . '/administrator/manifests/files/joomla.xml', 5);
        if (is_string($manifest) && $manifest !== '' && stripos($manifest, '<html') === false
            && preg_match('~<version>\s*([0-9][0-9.]*)\s*</version>~i', $manifest, $m)) {
            $result['version'] = $m[1];
            $result['source'] = 'manifest';
            return $result;
        }

        $lang = $this->httpGet($this->url . '/language/en-GB/en-GB.xml', 5);
        if (is_string($lang) && $lang !== '' && stripos($lang, '<html') === false
            && preg_match('~<version>\s*([0-9][0-9.]*)\s*</version>~i', $lang, $m)) {
            $result['version'] = $m[1];
            $result['source'] = 'language';
            $result['note'] = 'Версія мовного пакета ядра en-GB — зазвичай збігається з версією Joomla.';
            return $result;
        }

        return $result;
    }

    /**
     * Active Joomla template: most frequent slug in /templates/SLUG/ (+ templateDetails.xml).
     * The service 'system' (error pages) is ignored.
     */
    private function detectJoomlaTemplate(string $html): ?array
    {
        $candidates = [];
        if (preg_match_all('~/templates/([^/"\'?#\s]+)/~i', $html, $matches)) {
            foreach ($matches[1] as $slug) {
                $slug = strtolower(trim($slug));
                if ($slug === '' || $slug === 'system' || str_contains($slug, '..')) {
                    continue;
                }
                $candidates[$slug] = ($candidates[$slug] ?? 0) + 1;
            }
        }
        if (empty($candidates)) {
            return null;
        }
        arsort($candidates);
        $slug = (string)array_key_first($candidates);

        $info = ['slug' => $slug];
        $xml = $this->httpGet($this->url . '/templates/' . $slug . '/templateDetails.xml', 5);
        if (is_string($xml) && $xml !== '' && stripos($xml, '<html') === false
            && stripos($xml, '<extension') !== false) {
            foreach (['name' => 'name', 'version' => 'version', 'author' => 'author', 'description' => 'description'] as $tag => $key) {
                if (preg_match('~<' . $tag . '>\s*(.+?)\s*</' . $tag . '>~is', $xml, $m)) {
                    $val = trim(strip_tags(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8')));
                    if ($val !== '') {
                        $info[$key] = $key === 'description' ? $this->truncate($val, 280) : $val;
                    }
                }
            }
        }
        if (empty($info['name'])) {
            $info['name'] = ucwords(str_replace(['-', '_'], ' ', $slug));
        }
        return $info;
    }

    /**
     * Third-party Joomla extensions from HTML traces:
     * - components: option=com_X / /component/X / /components/com_X (except core);
     * - modules: /modules/mod_X, /media/mod_X;
     * - plugins: /plugins/GROUP/NAME;
     * - comments: JOOMLA_HTML_MARKERS (Modules Anywhere, Unite Gallery +version…).
     */
    private function detectJoomlaExtensions(string $html): array
    {
        $found = []; // key => ['name'=>..., 'version'=>?string, 'source'=>...]

        // Components from URLs/forms
        $comSlugs = [];
        if (preg_match_all('~option=(com_[a-z0-9_]+)~i', $html, $m)) {
            foreach ($m[1] as $s) {
                $comSlugs[strtolower($s)] = true;
            }
        }
        if (preg_match_all('~/(?:component|components)/([a-zA-Z0-9_]+)/?~', $html, $m)) {
            foreach ($m[1] as $s) {
                $s = strtolower($s);
                $comSlugs[str_starts_with($s, 'com_') ? $s : 'com_' . $s] = true;
            }
        }
        $coreCom = ['com_content', 'com_users', 'com_user', 'com_menu', 'com_menus', 'com_login',
            'com_config', 'com_ajax', 'com_admin', 'com_cache', 'com_checkin', 'com_finder',
            'com_search', 'com_tags', 'com_contact', 'com_newsfeeds', 'com_weblinks',
            'com_wrapper', 'com_mailto', 'com_media', 'com_modules', 'com_plugins',
            'com_templates', 'com_languages', 'com_installer', 'com_joomlaupdate', 'com_postinstall'];
        foreach (array_keys($comSlugs) as $slug) {
            if (in_array($slug, $coreCom, true)) {
                continue;
            }
            $found['com:' . $slug] = [
                'name' => $this->prettifyJoomlaSlug($slug),
                'version' => null,
                'source' => 'component-url',
            ];
        }

        // Modules from asset paths
        if (preg_match_all('~/(?:modules|media)/(mod_[a-z0-9_]+)/~i', $html, $m)) {
            foreach ($m[1] as $s) {
                $slug = strtolower($s);
                $found['mod:' . $slug] = [
                    'name' => $this->prettifyJoomlaSlug($slug),
                    'version' => null,
                    'source' => 'asset-path',
                ];
            }
        }

        // Plugins from /plugins/GROUP/NAME/ asset paths
        if (preg_match_all('~/plugins/([a-z0-9_]+)/([a-z0-9_-]+)/~i', $html, $m, PREG_SET_ORDER)) {
            foreach ($m as $hit) {
                $key = 'plg:' . strtolower($hit[1]) . '/' . strtolower($hit[2]);
                if (!isset($found[$key])) {
                    $base = $this->prettifyJoomlaSlug($hit[2]);
                    $group = strtolower($hit[1]);
                    $found[$key] = [
                        'name' => strtolower($base) === $group ? $base : $base . ' (' . $group . ')',
                        'version' => null,
                        'source' => 'asset-path',
                    ];
                }
            }
        }

        // Markers in comments/attributes (surface as in WP plugins).
        $surfaceLower = strtolower($this->stripNoiseForDetection($this->extractPluginSurface($html)));
        foreach (self::JOOMLA_HTML_MARKERS as $key => $cfg) {
            if (isset($found[$key])) {
                continue;
            }
            foreach ($cfg['markers'] as $marker) {
                $pat = '~(?<![a-z0-9_-])' . preg_quote(strtolower($marker), '~') . '(?![a-z0-9_])~';
                if (preg_match($pat, $surfaceLower)) {
                    $ver = null;
                    if (!empty($cfg['version_re']) && preg_match($cfg['version_re'] . 'i', $html, $vm)
                        && preg_match('~^\d+\.\d+~', $vm[1])) {
                        $ver = $vm[1];
                    }
                    $found[$key] = [
                        'name' => $cfg['name'],
                        'version' => $ver,
                        'source' => 'marker',
                    ];
                    break;
                }
            }
        }

        $extensions = array_values($found);
        // Deduplicate by name: the same component may show up
        // both in a URL (option=com_x) and in an asset path — keep the stronger evidence
        // (with a version > asset-path > component-url > marker).
        $rank = ['marker' => 0, 'component-url' => 1, 'asset-path' => 2];
        $byName = [];
        foreach ($extensions as $e) {
            $k = mb_strtolower($e['name']);
            $score = ($e['version'] !== null ? 10 : 0) + ($rank[$e['source']] ?? 0);
            if (!isset($byName[$k]) || $score > $byName[$k]['score']) {
                $byName[$k] = ['e' => $e, 'score' => $score];
            }
        }
        $extensions = array_map(static fn($v) => $v['e'], array_values($byName));
        usort($extensions, static fn($a, $b) => strcasecmp($a['name'], $b['name']));
        return $extensions;
    }

    private function prettifyJoomlaSlug(string $slug): string
    {
        $slug = (string)preg_replace('~^(com|mod|plg)_~i', '', $slug);
        return ucwords(str_replace(['-', '_'], ' ', $slug));
    }

    /**
     * Joomla extension markers in comments/attributes (key has a com:/mod:/plg:/ext: prefix).
     */
    private const JOOMLA_HTML_MARKERS = [
        'ext:modules-anywhere' => [
            'name' => 'Modules Anywhere (Regular Labs)',
            'markers' => ['modules anywhere'],
        ],
        'ext:sourcerer' => [
            'name' => 'Sourcerer (Regular Labs)',
            'markers' => ['sourcerer'],
        ],
        'ext:advanced-module-manager' => [
            'name' => 'Advanced Module Manager (Regular Labs)',
            'markers' => ['advanced module manager'],
        ],
        'ext:unite-gallery' => [
            'name' => 'Unite Gallery',
            'markers' => ['unite gallery', 'unitegallery'],
            'version_re' => '~unite gallery ([0-9][0-9a-zA-Z._-]*)~',
        ],
        'ext:unite-revolution' => [
            'name' => 'Unite Revolution Slider',
            'markers' => ['unite revolution', 'revslider'],
            'version_re' => '~revolution slider ([0-9][0-9a-zA-Z._-]*)~',
        ],
        'ext:joomlatools' => [
            'name' => 'Joomlatools',
            'markers' => ['joomlatools'],
        ],
        'ext:akeeba' => [
            'name' => 'Akeeba Backup',
            'markers' => ['akeeba'],
        ],
        'ext:sh404sef' => [
            'name' => 'sh404SEF',
            'markers' => ['sh404sef'],
        ],
        'ext:jsn' => [
            'name' => 'JSN Framework (JoomlaShine)',
            'markers' => ['jsn-', 'jsn_'],
        ],
        'ext:gantry' => [
            'name' => 'Gantry Framework',
            'markers' => ['gantry'],
        ],
        'ext:t3' => [
            'name' => 'T3 Framework',
            'markers' => ['t3-framework', 't3 framework'],
        ],
    ];

    /**
     * Joomla admin panel: standard /administrator/ with a login form, or hidden.
     */
    private function detectJoomlaAdminUrl(): array
    {
        $base = rtrim($this->url, '/');
        $body = $this->httpGet($base . '/administrator/', 6);
        if (is_string($body) && $body !== '' && stripos($body, '<html') !== false) {
            $low = strtolower($body);
            $isLogin = (str_contains($low, 'com_login') && (str_contains($low, 'passwd') || str_contains($low, 'password')))
                || (str_contains($low, 'id="form-login"') && str_contains($low, 'joomla'));
            if ($isLogin) {
                return [
                    'url' => $base . '/administrator/',
                    'path' => '/administrator/',
                    'is_default' => true,
                    'is_hidden' => false,
                    'note' => 'Стандартна адреса панелі керування доступна.',
                ];
            }
        }
        return [
            'url' => null,
            'path' => null,
            'is_default' => false,
            'is_hidden' => true,
            'note' => 'Стандартна адреса /administrator/ не відповідає сторінкою входу — '
                . 'ймовірно, її перейменовано/закрито засобами безпеки.',
        ];
    }

    /**
     * Drupal details: core version, active theme, third-party modules, login.
     * Stored in sections.cms[].drupal, rendered inside the CMS card.
     */
    private function detectDrupalDetails(string $html, ?string $generator, array $headers): ?array
    {
        $versionInfo = $this->detectDrupalVersion($html, $generator, $headers);
        $theme = $this->detectDrupalTheme($html);
        $modules = $this->detectDrupalModules($html);
        $loginInfo = $this->detectDrupalLoginUrl();

        $hasAny = $versionInfo['version'] !== null
            || $theme !== null
            || !empty($modules)
            || ($loginInfo !== null && (!empty($loginInfo['url']) || !empty($loginInfo['is_hidden'])));

        if (!$hasAny) {
            return null;
        }

        return [
            'version' => $versionInfo['version'],
            'version_source' => $versionInfo['source'],
            'version_note' => $versionInfo['note'],
            'theme' => $theme,
            'modules' => $modules,
            'login_url' => $loginInfo,
            'note' => 'Виявлено лише ті модулі, що лишили сліди на перевіреній сторінці '
                . '(asset-шляхи). Версії тем/модулів дистанційно не видно — .info.yml '
                . 'зазвичай закриті; показано імена.',
        ];
    }

    /**
     * Drupal version by priority:
     *  1. /core/CHANGELOG.txt — first line with "Drupal X.Y.Z" (exact, if the file is open);
     *  2. meta Generator / X-Generator ("Drupal 10" — major branch only).
     */
    private function detectDrupalVersion(string $html, ?string $generator, array $headers): array
    {
        $result = ['version' => null, 'source' => 'hidden', 'note' => null];

        $changelog = $this->httpGet($this->url . '/core/CHANGELOG.txt', 5);
        if (is_string($changelog) && $changelog !== '' && stripos($changelog, '<html') === false
            && preg_match('~^\s*Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b~im', mb_substr($changelog, 0, 2000), $m)) {
            $result['version'] = $m[1];
            $result['source'] = 'changelog';
            return $result;
        }

        $gen = $generator ?? $this->extractMeta($html, 'generator');
        if (is_string($gen) && $gen !== '' && preg_match('~Drupal\s+([0-9]+(?:\.[0-9]+){0,2})~i', $gen, $m)) {
            $result['version'] = $m[1];
            $result['source'] = 'meta-generator';
            if (substr_count($m[1], '.') < 2) {
                $result['note'] = 'Відома лише мажорна гілка — точну версію сайт приховує.';
            }
            return $result;
        }
        foreach ($headers as $h) {
            if (stripos($h, 'X-Generator:') === 0
                && preg_match('~Drupal\s+([0-9]+(?:\.[0-9]+){0,2})~i', trim(substr($h, 12)), $m)) {
                $result['version'] = $m[1];
                $result['source'] = 'header-x-generator';
                if (substr_count($m[1], '.') < 2) {
                    $result['note'] = 'Відома лише мажорна гілка — точну версію сайт приховує.';
                }
                return $result;
            }
        }

        return $result;
    }

    /**
     * Active Drupal theme: most frequent slug in /sites/…/themes/SLUG/ and /themes/…/SLUG/.
     * Tries to read .info.yml at the observed base path (often 403 — then without details).
     *
     * @return array{slug: string, name?: string, version?: string, description?: string, base?: string}|null
     */
    private function detectDrupalTheme(string $html): ?array
    {
        $candidates = []; // slug => ['count'=>int, 'base'=>string]
        // Left context ["'(\s= — filters out RDF namespaces like
        // purl.org/rss/1.0/modules/content/ in <html prefix="...">.
        if (preg_match_all('~(?<=["\'\(\\s=])(/sites/(?:default|all)/themes/|/themes/(?:custom/|contrib/)?|/core/themes/)([a-z0-9_-]+)/~i', $html, $m, PREG_SET_ORDER)) {
            foreach ($m as $hit) {
                $slug = strtolower($hit[2]);
                if ($slug === '' || $slug === 'custom' || $slug === 'contrib' || str_contains($slug, '..')) {
                    continue;
                }
                if (!isset($candidates[$slug])) {
                    $candidates[$slug] = ['count' => 0, 'base' => $hit[1] . $hit[2] . '/'];
                }
                $candidates[$slug]['count']++;
            }
        }
        if (empty($candidates)) {
            return null;
        }
        uasort($candidates, static fn($a, $b) => $b['count'] <=> $a['count']);
        $slug = (string)array_key_first($candidates);
        $base = $candidates[$slug]['base'];

        $info = ['slug' => $slug, 'base' => $base];
        $yml = $this->httpGet($this->url . $base . $slug . '.info.yml', 5);
        if (is_string($yml) && $yml !== '' && stripos($yml, '<html') === false) {
            foreach (['name' => 'name', 'version' => 'version', 'description' => 'description', 'core_version_requirement' => 'core'] as $field => $key) {
                if (preg_match('~^' . preg_quote($field, '~') . ':\s*[\'"]?(.+?)[\'"]?\s*$~im', $yml, $mm)) {
                    $val = trim($mm[1]);
                    if ($val !== '') {
                        $info[$key] = $key === 'description' ? $this->truncate($val, 280) : $val;
                    }
                }
            }
        }
        if (empty($info['name'])) {
            $info['name'] = ucwords(str_replace(['-', '_'], ' ', $slug));
        }
        return $info;
    }

    /**
     * Third-party Drupal modules by asset paths:
     * /sites/…/modules[/contrib]/SLUG/, /modules[/contrib]/SLUG/.
     * Core (/core/modules/…) is skipped — it is not a "detection", just noise.
     */
    private function detectDrupalModules(string $html): array
    {
        $found = [];
        if (preg_match_all('~(?<=["\'\(\\s=])/(?:sites/(?:default|all)/)?modules/(?:contrib/)?([a-z0-9_-]+)/~i', $html, $m)) {
            foreach ($m[1] as $s) {
                $slug = strtolower($s);
                if ($slug === '' || in_array($slug, self::DRUPAL_CORE_MODULES, true)) {
                    continue;
                }
                $found[$slug] = [
                    'name' => ucwords(str_replace(['-', '_'], ' ', $slug)),
                    'version' => null,
                ];
            }
        }
        $modules = array_values($found);
        usort($modules, static fn($a, $b) => strcasecmp($a['name'], $b['name']));
        return $modules;
    }

    /** Machine names of Drupal core modules — do not show as "detected". */
    private const DRUPAL_CORE_MODULES = [
        'views', 'views_ui', 'block', 'block_content', 'node', 'user', 'system',
        'field', 'field_ui', 'filter', 'text', 'options', 'taxonomy', 'image',
        'file', 'responsive_image', 'breakpoint', 'ckeditor5', 'ckeditor',
        'contextual', 'toolbar', 'help', 'history', 'search', 'shortcut',
        'menu_ui', 'menu_link_content', 'path', 'path_alias', 'language',
        'locale', 'content_translation', 'config_translation', 'update',
        'dblog', 'syslog', 'comment', 'contact', 'forum', 'book', 'statistics',
        'aggregator', 'ban', 'color', 'dashboard', 'overlay', 'rdf', 'tracker',
        'trigger', 'profile', 'poll', 'openid', 'phone', 'overlay',
    ];

    /**
     * Drupal login: standard /user/login with a form, or hidden.
     */
    private function detectDrupalLoginUrl(): array
    {
        $base = rtrim($this->url, '/');
        $body = $this->httpGet($base . '/user/login', 6);
        if (is_string($body) && $body !== '' && stripos($body, '<html') !== false) {
            $low = strtolower($body);
            $hasPass = str_contains($low, 'name="pass"') || str_contains($low, 'name="password"');
            $isLogin = ((str_contains($low, 'id="user-login-form"') || str_contains($low, 'user-login-form')) && $hasPass)
                || ($hasPass && str_contains($low, 'action="/user/login"'));
            if ($isLogin) {
                return [
                    'url' => $base . '/user/login',
                    'path' => '/user/login',
                    'is_default' => true,
                    'is_hidden' => false,
                    'note' => 'Стандартна адреса входу доступна.',
                ];
            }
        }
        return [
            'url' => null,
            'path' => null,
            'is_default' => false,
            'is_hidden' => true,
            'note' => 'Стандартна адреса /user/login не відповідає формою входу — '
                . 'ймовірно, вхід перенесено/закрито (модулі Rename Admin Paths, Shield тощо).',
        ];
    }

    private function parseWpThemeHeader(string $css): array
    {
        $info = [];
        $fields = [
            'Theme Name' => 'name',
            'Theme URI' => 'homepage',
            'Author' => 'author',
            'Author URI' => 'authorUri',
            'Version' => 'version',
            'Description' => 'description',
            'Tags' => 'tags',
            'License' => 'license',
            'Text Domain' => 'textDomain',
            'Template' => 'template',
            'Tested up to' => 'testedUpTo',
            'Requires at least' => 'requiresAtLeast',
        ];
        foreach ($fields as $field => $key) {
            // Allow both the plain format ("Theme Name: ..."),
            // and the WP-comment format (" * Theme Name: ...")
            if (preg_match('~^\s*\*?\s*' . preg_quote($field, '~') . '\s*:\s*(.+?)\s*(?:\*/)?$~im', $css, $m)) {
                $info[$key] = trim($m[1]);
            }
        }
        return $info;
    }

    private function truncate(string $text, int $max): string
    {
        if (mb_strlen($text) <= $max) {
            return $text;
        }
        return mb_substr($text, 0, $max - 1) . '…';
    }

    /**
     * Known WordPress plugin dictionary: slug => [name, site].
     */
    private const WP_PLUGIN_NAMES = [
        'akismet' => ['name' => 'Akismet Anti-Spam', 'site' => 'https://akismet.com'],
        'akismet-anti-spam' => ['name' => 'Akismet Anti-Spam', 'site' => 'https://akismet.com'],
        'contact-form-7' => ['name' => 'Contact Form 7', 'site' => 'https://contactform7.com'],
        'contact-form-7-honeypot' => ['name' => 'Contact Form 7 Honeypot', 'site' => 'https://wordpress.org/plugins/contact-form-7-honeypot'],
        'kama-spamblock' => ['name' => 'Kama SpamBlock', 'site' => 'https://wordpress.org/plugins/kama-spamblock'],
        'flamingo' => ['name' => 'Flamingo', 'site' => 'https://contactform7.com/flamingo'],
        'woocommerce' => ['name' => 'WooCommerce', 'site' => 'https://woocommerce.com'],
        'woocommerce-payments' => ['name' => 'WooCommerce Payments', 'site' => 'https://woocommerce.com/payments'],
        'woocommerce-services' => ['name' => 'WooCommerce Services', 'site' => 'https://woocommerce.com'],
        'jetpack' => ['name' => 'Jetpack', 'site' => 'https://jetpack.com'],
        'jetpack-boost' => ['name' => 'Jetpack Boost', 'site' => 'https://jetpack.com/boost'],
        'wordpress-seo' => ['name' => 'Yoast SEO', 'site' => 'https://yoast.com/wordpress/plugins/seo'],
        'yoast-seo-news' => ['name' => 'Yoast SEO: News', 'site' => 'https://yoast.com'],
        'google-analytics-for-wordpress' => ['name' => 'MonsterInsights', 'site' => 'https://www.monsterinsights.com'],
        'exactmetrics' => ['name' => 'ExactMetrics', 'site' => 'https://exactmetrics.com'],
        'google-analytics-dashboard-for-wp' => ['name' => 'ExactMetrics', 'site' => 'https://exactmetrics.com'],
        'seo-by-rank-math' => ['name' => 'Rank Math SEO', 'site' => 'https://rankmath.com'],
        'seopress' => ['name' => 'SEOPress', 'site' => 'https://www.seopress.org'],
        'all-in-one-seo-pack' => ['name' => 'All in One SEO Pack', 'site' => 'https://semperplugins.com'],
        'all-in-one-wp-migration' => ['name' => 'All-in-One WP Migration', 'site' => 'https://servmask.com'],
        'wordfence' => ['name' => 'Wordfence Security', 'site' => 'https://www.wordfence.com'],
        'ithemes-security' => ['name' => 'iThemes Security', 'site' => 'https://ithemes.com/security'],
        'ithemes-security-pro' => ['name' => 'iThemes Security Pro', 'site' => 'https://ithemes.com/security'],
        'sucuri-scanner' => ['name' => 'Sucuri Security', 'site' => 'https://wordpress.org/plugins/sucuri-scanner'],
        'limit-login-attempts-reloaded' => ['name' => 'Limit Login Attempts Reloaded', 'site' => 'https://wordpress.org/plugins/limit-login-attempts-reloaded'],
        'wpforms-lite' => ['name' => 'WPForms Lite', 'site' => 'https://wpforms.com'],
        'wpforms' => ['name' => 'WPForms Pro', 'site' => 'https://wpforms.com'],
        'formidable' => ['name' => 'Formidable Forms', 'site' => 'https://formidableforms.com'],
        'ninja-forms' => ['name' => 'Ninja Forms', 'site' => 'https://ninjaforms.com'],
        'gravityforms' => ['name' => 'Gravity Forms', 'site' => 'https://www.gravityforms.com'],
        'everest-forms' => ['name' => 'Everest Forms', 'site' => 'https://everestforms.net'],
        'elementor' => ['name' => 'Elementor', 'site' => 'https://elementor.com'],
        'elementor-pro' => ['name' => 'Elementor Pro', 'site' => 'https://elementor.com'],
        'wp-super-cache' => ['name' => 'WP Super Cache', 'site' => 'https://wordpress.org/plugins/wp-super-cache'],
        'w3-total-cache' => ['name' => 'W3 Total Cache', 'site' => 'https://www.boldgrid.com/w3-total-cache'],
        'wp-fastest-cache' => ['name' => 'WP Fastest Cache', 'site' => 'https://www.wpfastestcache.com'],
        'litespeed-cache' => ['name' => 'LiteSpeed Cache', 'site' => 'https://wordpress.org/plugins/litespeed-cache'],
        'wp-rocket' => ['name' => 'WP Rocket', 'site' => 'https://wp-rocket.me'],
        'autoptimize' => ['name' => 'Autoptimize', 'site' => 'https://autoptimize.com'],
        'wp-smushit' => ['name' => 'Smush', 'site' => 'https://wordpress.org/plugins/wp-smushit'],
        'smush' => ['name' => 'Smush', 'site' => 'https://wordpress.org/plugins/wp-smushit'],
        'ewww-image-optimizer' => ['name' => 'EWWW Image Optimizer', 'site' => 'https://ewww.io'],
        'imagify' => ['name' => 'Imagify', 'site' => 'https://imagify.io'],
        'shortpixel-image-optimiser' => ['name' => 'ShortPixel Image Optimizer', 'site' => 'https://shortpixel.com'],
        'updraftplus' => ['name' => 'UpdraftPlus', 'site' => 'https://updraftplus.com'],
        'backwpup' => ['name' => 'BackWPup', 'site' => 'https://backwpup.com'],
        'duplicator' => ['name' => 'Duplicator', 'site' => 'https://duplicator.com'],
        'duplicate-post' => ['name' => 'Duplicate Post', 'site' => 'https://duplicate-post.uk'],
        'duplicate-page' => ['name' => 'Duplicate Page', 'site' => 'https://wordpress.org/plugins/duplicate-page'],
        'sitepress-multilingual-cms' => ['name' => 'WPML Multilingual CMS', 'site' => 'https://wpml.org'],
        'wpml-string-translation' => ['name' => 'WPML String Translation', 'site' => 'https://wpml.org'],
        'wpml-translation-management' => ['name' => 'WPML Translation Management', 'site' => 'https://wpml.org'],
        'revslider' => ['name' => 'Slider Revolution', 'site' => 'https://www.sliderrevolution.com'],
        'layerslider' => ['name' => 'LayerSlider', 'site' => 'https://layerslider.com'],
        'smart-slider-3' => ['name' => 'Smart Slider 3', 'site' => 'https://smartslider3.com'],
        'ml-slider' => ['name' => 'MetaSlider', 'site' => 'https://www.metaslider.com'],
        'instagram-feed' => ['name' => 'Smash Balloon Instagram Feed', 'site' => 'https://smashballoon.com/instagram-feed'],
        'custom-facebook-feed' => ['name' => 'Smash Balloon Facebook Feed', 'site' => 'https://smashballoon.com/facebook-feed'],
        'google-site-kit' => ['name' => 'Site Kit by Google', 'site' => 'https://sitekit.withgoogle.com'],
        'sg-cachepress' => ['name' => 'SiteGround Optimizer', 'site' => 'https://www.siteground.com'],
        'wp-optimize' => ['name' => 'WP-Optimize', 'site' => 'https://getwpo.com'],
        'nitropack' => ['name' => 'NitroPack', 'site' => 'https://nitropack.io'],
        'perfmatters' => ['name' => 'Perfmatters', 'site' => 'https://perfmatters.io'],
        'borlabs-cookie' => ['name' => 'Borlabs Cookie', 'site' => 'https://borlabs.io'],
        'cookieyes' => ['name' => 'CookieYes', 'site' => 'https://www.cookieyes.com'],
        'omgf' => ['name' => 'OMGF | Host Google Fonts Locally', 'site' => 'https://wordpress.org/plugins/host-webfonts-local'],
        'flying-press' => ['name' => 'FlyingPress', 'site' => 'https://flying-press.com'],
        'heartbeat-control' => ['name' => 'Heartbeat Control', 'site' => 'https://wordpress.org/plugins/heartbeat-control'],
        'really-simple-ssl' => ['name' => 'Really Simple SSL', 'site' => 'https://really-simple-ssl.com'],
        'classic-editor' => ['name' => 'Classic Editor', 'site' => 'https://wordpress.org/plugins/classic-editor'],
        'classic-widgets' => ['name' => 'Classic Widgets', 'site' => 'https://wordpress.org/plugins/classic-widgets'],
        'classic-block' => ['name' => 'Classic Block', 'site' => 'https://wordpress.org/plugins/classic-block'],
        'disable-comments' => ['name' => 'Disable Comments', 'site' => 'https://wordpress.org/plugins/disable-comments'],
        'disable-gutenberg' => ['name' => 'Disable Gutenberg', 'site' => 'https://wordpress.org/plugins/disable-gutenberg'],
        'advanced-custom-fields' => ['name' => 'Advanced Custom Fields', 'site' => 'https://www.advancedcustomfields.com'],
        'acf' => ['name' => 'Advanced Custom Fields', 'site' => 'https://www.advancedcustomfields.com'],
        'pods' => ['name' => 'Pods', 'site' => 'https://pods.io'],
        'meta-box' => ['name' => 'Meta Box', 'site' => 'https://metabox.io'],
        'custom-post-type-ui' => ['name' => 'Custom Post Type UI', 'site' => 'https://webdevstudios.com'],
        'custom-taxonomies' => ['name' => 'Custom Taxonomies', 'site' => 'https://wordpress.org/plugins/custom-taxonomies'],
        'tinymce-advanced' => ['name' => 'TinyMCE Advanced', 'site' => 'https://wordpress.org/plugins/tinymce-advanced'],
        'regenerate-thumbnails' => ['name' => 'Regenerate Thumbnails', 'site' => 'https://wordpress.org/plugins/regenerate-thumbnails'],
        'user-role-editor' => ['name' => 'User Role Editor', 'site' => 'https://www.role-editor.com'],
        'members' => ['name' => 'Members', 'site' => 'https://wordpress.org/plugins/members'],
        'user-switching' => ['name' => 'User Switching', 'site' => 'https://johnblackbourn.com/wordpress/user-switching'],
        'redirection' => ['name' => 'Redirection', 'site' => 'https://redirection.me'],
        'broken-link-checker' => ['name' => 'Broken Link Checker', 'site' => 'https://wordpress.org/plugins/broken-link-checker'],
        'mailchimp-for-wp' => ['name' => 'Mailchimp for WP', 'site' => 'https://www.mc4wp.com'],
        'popup-builder' => ['name' => 'Popup Builder', 'site' => 'https://wordpress.org/plugins/popup-builder'],
        'popup-maker' => ['name' => 'Popup Maker', 'site' => 'https://wppopupmaker.com'],
        'tablepress' => ['name' => 'TablePress', 'site' => 'https://tablepress.org'],
        'polylang' => ['name' => 'Polylang', 'site' => 'https://polylang.pro'],
        'weglot' => ['name' => 'Weglot', 'site' => 'https://weglot.com'],
        'wpml' => ['name' => 'WPML', 'site' => 'https://wpml.org'],
        'translatepress-multilingual' => ['name' => 'TranslatePress', 'site' => 'https://translatepress.com'],
        'simple-tags' => ['name' => 'Simple Tags', 'site' => 'https://wordpress.org/plugins/simple-tags'],
        'cookie-notice' => ['name' => 'Cookie Notice', 'site' => 'https://hu-manity.co'],
        'cookie-law-info' => ['name' => 'Cookie Law Info', 'site' => 'https://cookie-law-info.com'],
        'complianz' => ['name' => 'Complianz', 'site' => 'https://complianz.io'],
        'wp-mail-smtp' => ['name' => 'WP Mail SMTP', 'site' => 'https://wpmailsmtp.com'],
        'post-smtp' => ['name' => 'Post SMTP', 'site' => 'https://wordpress.org/plugins/post-smtp'],
        'smtp-mailer' => ['name' => 'SMTP Mailer', 'site' => 'https://wordpress.org/plugins/smtp-mailer'],
        'nextgen-gallery' => ['name' => 'NextGEN Gallery', 'site' => 'https://www.imagely.com/nextgen-gallery'],
        'modula-best-grid-gallery' => ['name' => 'Modula Gallery', 'site' => 'https://wp-modula.com'],
        'envira-gallery-lite' => ['name' => 'Envira Gallery Lite', 'site' => 'https://enviragallery.com'],
        'query-monitor' => ['name' => 'Query Monitor', 'site' => 'https://querymonitor.com'],
        'debug-bar' => ['name' => 'Debug Bar', 'site' => 'https://wordpress.org/plugins/debug-bar'],
        'simple-history' => ['name' => 'Simple History', 'site' => 'https://simple-history.com'],
        'wp-statistics' => ['name' => 'WP Statistics', 'site' => 'https://wp-statistics.com'],
        'google-analytics' => ['name' => 'Google Analytics', 'site' => 'https://wordpress.org/plugins/google-analytics'],
        'hello-dolly' => ['name' => 'Hello Dolly', 'site' => 'https://wordpress.org/plugins/hello-dolly'],
        'hello' => ['name' => 'Hello Dolly', 'site' => 'https://wordpress.org/plugins/hello-dolly'],
        'wordpress-beta-tester' => ['name' => 'WordPress Beta Tester', 'site' => 'https://wordpress.org/plugins/wordpress-beta-tester'],
        'wordpress-importer' => ['name' => 'WordPress Importer', 'site' => 'https://wordpress.org/plugins/wordpress-importer'],
        'wp-reset' => ['name' => 'WP Reset', 'site' => 'https://wpreset.com'],
        'wp-migrate-db' => ['name' => 'WP Migrate DB', 'site' => 'https://wordpress.org/plugins/wp-migrate-db'],
        'elementor' => ['name' => 'Elementor', 'site' => 'https://elementor.com'],
        'elementor-pro' => ['name' => 'Elementor Pro', 'site' => 'https://elementor.com'],
        'beaver-builder-lite-version' => ['name' => 'Beaver Builder Lite', 'site' => 'https://www.wpbeaverbuilder.com'],
        'beaver-builder' => ['name' => 'Beaver Builder Pro', 'site' => 'https://www.wpbeaverbuilder.com'],
        'bb-plugin' => ['name' => 'Beaver Builder Plugin (Pro)', 'site' => 'https://www.wpbeaverbuilder.com'],
        'js_composer' => ['name' => 'WPBakery Page Builder (Visual Composer)', 'site' => 'https://wpbakery.com'],
        'siteorigin-panels' => ['name' => 'SiteOrigin Page Builder', 'site' => 'https://siteorigin.com'],
        'thrive-visual-editor' => ['name' => 'Thrive Architect', 'site' => 'https://thrivethemes.com/architect'],
        'oxygen' => ['name' => 'Oxygen Builder', 'site' => 'https://oxygenbuilder.com'],
        'fusion-builder' => ['name' => 'Fusion Builder (Avada)', 'site' => 'https://avada.theme-fusion.com'],
        'fusion-core' => ['name' => 'Fusion Core (Avada)', 'site' => 'https://avada.theme-fusion.com'],
        'live-composer-page-builder' => ['name' => 'Live Composer', 'site' => 'https://livecomposerplugin.com'],
        'gutenberg' => ['name' => 'Gutenberg', 'site' => 'https://wordpress.org/plugins/gutenberg'],
        'woocommerce-gateway-stripe' => ['name' => 'WooCommerce Stripe Gateway', 'site' => 'https://wordpress.org/plugins/woocommerce-gateway-stripe'],
        'woocommerce-stripe-gateway' => ['name' => 'WooCommerce Stripe Gateway', 'site' => 'https://wordpress.org/plugins/woocommerce-gateway-stripe'],
        'woocommerce-paypal-payments' => ['name' => 'WooCommerce PayPal Payments', 'site' => 'https://wordpress.org/plugins/woocommerce-paypal-payments'],
        'paypal-for-woocommerce' => ['name' => 'PayPal for WooCommerce', 'site' => 'https://wordpress.org/plugins/paypal-for-woocommerce'],
        'woocommerce-square' => ['name' => 'WooCommerce Square', 'site' => 'https://wordpress.org/plugins/woocommerce-square'],
        'woocommerce-braintree' => ['name' => 'WooCommerce Braintree', 'site' => 'https://wordpress.org/plugins/woocommerce-braintree'],
        'braintree-payments' => ['name' => 'Braintree Payments for WooCommerce', 'site' => 'https://wordpress.org/plugins/braintree-payments'],
        'mollie-payments-for-woocommerce' => ['name' => 'Mollie Payments for WooCommerce', 'site' => 'https://wordpress.org/plugins/mollie-payments-for-woocommerce'],
        'woocommerce-adyen' => ['name' => 'WooCommerce Adyen', 'site' => 'https://wordpress.org/plugins/woocommerce-adyen'],
        'razorpay-for-woocommerce' => ['name' => 'Razorpay for WooCommerce', 'site' => 'https://wordpress.org/plugins/razorpay-for-woocommerce'],
        'amazon-pay' => ['name' => 'Amazon Pay for WooCommerce', 'site' => 'https://wordpress.org/plugins/amazon-pay'],
        'klarna-payments-for-woocommerce' => ['name' => 'Klarna Payments for WooCommerce', 'site' => 'https://wordpress.org/plugins/klarna-payments-for-woocommerce'],
        'klarna-checkout-for-woocommerce' => ['name' => 'Klarna Checkout for WooCommerce', 'site' => 'https://wordpress.org/plugins/klarna-checkout-for-woocommerce'],
        'afterpay-for-woocommerce' => ['name' => 'Afterpay for WooCommerce', 'site' => 'https://wordpress.org/plugins/afterpay-for-woocommerce'],
        'payfast-for-woocommerce' => ['name' => 'Payfast for WooCommerce', 'site' => 'https://wordpress.org/plugins/payfast-for-woocommerce'],
        'woocommerce-shipment-tracking' => ['name' => 'Shipment Tracking for WooCommerce', 'site' => 'https://wordpress.org/plugins/woocommerce-shipment-tracking'],
        'table-rate-shipping' => ['name' => 'Table Rate Shipping', 'site' => 'https://wordpress.org/plugins/table-rate-shipping'],
        'woocommerce-ups' => ['name' => 'WooCommerce UPS', 'site' => 'https://woocommerce.com/products/ups'],
        'woocommerce-fedex' => ['name' => 'WooCommerce FedEx', 'site' => 'https://woocommerce.com/products/fedex'],
        'woocommerce-australia-post' => ['name' => 'WooCommerce Australia Post', 'site' => 'https://woocommerce.com/products/australia-post'],
        'woocommerce-canada-post' => ['name' => 'WooCommerce Canada Post', 'site' => 'https://woocommerce.com/products/canada-post'],
        'flexible-shipping' => ['name' => 'Flexible Shipping', 'site' => 'https://wordpress.org/plugins/flexible-shipping'],
        'flexible-shipping-woocommerce' => ['name' => 'Flexible Shipping', 'site' => 'https://wordpress.org/plugins/flexible-shipping'],
        'advanced-flat-rate-shipping' => ['name' => 'Advanced Flat Rate Shipping', 'site' => 'https://wordpress.org/plugins/advanced-flat-rate-shipping'],
        'printful-shipping' => ['name' => 'Printful Integration', 'site' => 'https://wordpress.org/plugins/printful-shipping'],
        'printify' => ['name' => 'Printify', 'site' => 'https://wordpress.org/plugins/printify'],
        'bb-theme-builder' => ['name' => 'Beaver Themer', 'site' => 'https://www.wpbeaverbuilder.com'],
        'ultimate-addons-for-beaver-builder' => ['name' => 'Ultimate Addons for Beaver Builder', 'site' => 'https://www.ultimatebeaver.com'],
    ];

    /**
     * CMS, framework and technology signatures.
     */
    private function loadSignatures(): array
    {
        return [
            'cms' => [
                'WordPress' => [
                    'signs' => ['/wp-content/', '/wp-includes/', '/wp-json', 'wp-json/', '/wp-admin'],
                    'generators' => ['WordPress'],
                    'confidence' => 'high',
                    'description' => 'Найпопулярніша CMS у світі з відкритим кодом.',
                    'site' => 'https://wordpress.org',
                ],
                'Joomla' => [
                    'strong' => ['/components/com_', 'Joomla!'],
                    'weak' => ['/administrator/', '/templates/beez', 'com_content'],
                    'generators' => ['Joomla'],
                    'confidence' => 'high',
                    'description' => 'CMS для сайтів, порталів та інтернет-магазинів.',
                    'site' => 'https://www.joomla.org',
                ],
                'Drupal' => [
                    'signs' => ['/sites/default/', '/sites/all/', '/core/misc/drupal.js', 'Drupal.settings', 'drupal.org'],
                    'generators' => ['Drupal'],
                    'confidence' => 'high',
                    'description' => 'Гнучка CMS для складних веб-проєктів.',
                    'site' => 'https://www.drupal.org',
                ],
                'OpenCart' => [
                    'signs' => ['/catalog/view/javascript', 'index.php?route=', 'opencart', '/catalog/view/theme'],
                    'generators' => ['OpenCart'],
                    'confidence' => 'high',
                    'description' => 'CMS для інтернет-магазинів.',
                    'site' => 'https://www.opencart.com',
                ],
                'PrestaShop' => [
                    'signs' => ['prestashop', '/modules/ps_', 'prestashop.com'],
                    'generators' => ['PrestaShop'],
                    'confidence' => 'high',
                    'description' => 'Open-source CMS для e-commerce.',
                    'site' => 'https://www.prestashop.com',
                ],
                'Magento' => [
                    'strong' => ['/skin/frontend/', 'mage/cookies.js', '/static/frontend/', 'Mage.Cookies', 'text/x-magento-init'],
                    'weak' => ['magento'],
                    'generators' => ['Magento'],
                    'confidence' => 'high',
                    'description' => 'Потужна платформа для електронної комерції.',
                    'site' => 'https://magento.com',
                ],
                '1С-Бітрікс' => [
                    'strong' => ['/bitrix/', 'bitrix24', 'bx-core', 'BX.message', '/bitrix/js/'],
                    'weak' => ['bitrix'],
                    'generators' => ['Bitrix', '1С-Битрикс'],
                    'confidence' => 'high',
                    'description' => 'Популярна українська/російська CMS.',
                    'site' => 'https://www.1c-bitrix.ru',
                ],
                'MODX' => [
                    'strong' => ['/assets/components/modx', 'MODX_', 'modxrevolution', 'manager/templates/', 'assets/snippets/', 'modx-'],
                    'weak' => ['/assets/components/'],
                    'generators' => ['MODX'],
                    'confidence' => 'high',
                    'description' => 'Гнучка CMS з відкритим кодом.',
                    'site' => 'https://modx.com',
                ],
                'Shopify' => [
                    'signs' => ['cdn.shopify.com', 'shopify.com/s/', 'myshopify.com'],
                    'generators' => ['Shopify'],
                    'confidence' => 'high',
                    'description' => 'SaaS-платформа для інтернет-магазинів.',
                    'site' => 'https://www.shopify.com',
                ],
                'Wix' => [
                    'signs' => ['wix.com', '_wixcidx', 'wixstatic.com', 'wix-viewer'],
                    'generators' => ['Wix'],
                    'confidence' => 'high',
                    'description' => 'Конструктор сайтів.',
                    'site' => 'https://www.wix.com',
                ],
                'Tilda' => [
                    'signs' => ['tilda.ws', 'tildacdn', 'tildaapi', 'project1702'],
                    'generators' => ['Tilda'],
                    'confidence' => 'high',
                    'description' => 'Популярний конструктор сайтів.',
                    'site' => 'https://tilda.cc',
                ],
                'Squarespace' => [
                    'strong' => ['squarespace.com', 'squarespace-cdn', 'static.squarespace', 'sqsp-cdn'],
                    'weak' => ['squarespace'],
                    'generators' => ['Squarespace'],
                    'confidence' => 'high',
                    'description' => 'Конструктор сайтів із шаблонами.',
                    'site' => 'https://www.squarespace.com',
                ],
                'Ghost' => [
                    'strong' => ['ghost.io', 'ghost.min.js', 'ghost-script'],
                    'weak' => ['content-api'],
                    'generators' => ['Ghost'],
                    'confidence' => 'high',
                    'description' => 'Платформа для блогів та публікацій.',
                    'site' => 'https://ghost.org',
                ],
                'phpBB' => [
                    'strong' => ['/styles/prosilver/'],
                    'weak' => ['phpBB'],
                    'generators' => ['phpBB'],
                    'confidence' => 'high',
                    'description' => 'Форумний двигун на PHP.',
                    'site' => 'https://www.phpbb.com',
                ],
                'vBulletin' => [
                    'strong' => ['vbulletin.css', 'vbulletin-core'],
                    'weak' => ['vbulletin'],
                    'generators' => ['vBulletin'],
                    'confidence' => 'medium',
                    'description' => 'Форумний двигун.',
                    'site' => 'https://www.vbulletin.com',
                ],
                'WordPress.com' => [
                    'signs' => ['wp.com', 'wp-themes.com'],
                    'generators' => [],
                    'confidence' => 'medium',
                    'description' => 'Хостинговий варіант WordPress.',
                    'site' => 'https://wordpress.com',
                ],
            ],
            'frameworks' => [
                'Laravel' => [
                    'type' => 'PHP-фреймворк',
                    'strong' => ['laravel', 'laravel_session'],
                    'weak' => ['csrf-token'],
                    'headers' => ['Set-Cookie: laravel_session'],
                    'description' => 'Популярний PHP-фреймворк з елегантним синтаксисом.',
                    'site' => 'https://laravel.com',
                ],
                'Symfony' => [
                    'type' => 'PHP-фреймворк',
                    'strong' => ['symfony', '_sf2_'],
                    'weak' => ['/bundles/'],
                    'headers' => ['X-Debug-Token', 'Set-Cookie: phpsession'],
                    'description' => 'Потужний PHP-фреймворк для великих проєктів.',
                    'site' => 'https://symfony.com',
                ],
                'Yii' => [
                    'type' => 'PHP-фреймворк',
                    'signs' => ['yii.js', 'yiiframework.com', 'yii\\web\\', 'yii\\base\\'],
                    'description' => 'Високопродуктивний PHP-фреймворк.',
                    'site' => 'https://www.yiiframework.com',
                ],
                'CodeIgniter' => [
                    'type' => 'PHP-фреймворк',
                    'signs' => ['codeigniter', 'ci_session'],
                    'description' => 'Легкий PHP-фреймворк.',
                    'site' => 'https://codeigniter.com',
                ],
                'CakePHP' => [
                    'type' => 'PHP-фреймворк',
                    'signs' => ['cakephp', 'CAKEPHP'],
                    'description' => 'PHP-фреймворк з конвенціями.',
                    'site' => 'https://cakephp.org',
                ],
                'React' => [
                    'type' => 'JavaScript-фреймворк',
                    'signs' => [
                        'react.development.js',
                        'react.production.min.js',
                        'react-dom.development.js',
                        'react-dom.production.min.js',
                        '_reactrootcontainer',
                        '__reactfiber',
                        'react-refresh',
                        'data-reactroot',
                        'data-react-helmet',
                    ],
                    'description' => 'Бібліотека для побудови інтерфейсів від Meta.',
                    'site' => 'https://react.dev',
                ],
                'Vue.js' => [
                    'type' => 'JavaScript-фреймворк',
                    'strong' => [
                        'vue.global.js',
                        'vue.runtime.global.js',
                        'vue.esm-browser.js',
                        'vue.esm-bundler.js',
                        'v-cloak',
                        '__vue_app__',
                        '__vue_component__',
                        'data-v-',
                    ],
                    'weak' => ['createapp('],
                    'description' => 'Прогресивний JS-фреймворк.',
                    'site' => 'https://vuejs.org',
                ],
                'Angular' => [
                    'type' => 'JavaScript-фреймворк',
                    'signs' => ['ng-version', 'ng-app=', 'ng-controller=', 'angular.min.js', 'angular-route'],
                    'description' => 'Платформа від Google для SPA.',
                    'site' => 'https://angular.io',
                ],
                'Next.js' => [
                    'type' => 'JavaScript-фреймворк',
                    'signs' => ['__next_data__', '/_next/static', '_next/image'],
                    'description' => 'React-фреймворк із SSR.',
                    'site' => 'https://nextjs.org',
                ],
                'Nuxt.js' => [
                    'type' => 'JavaScript-фреймворк',
                    'signs' => ['__nuxt__', '/_nuxt/'],
                    'description' => 'Vue-фреймворк із SSR.',
                    'site' => 'https://nuxt.com',
                ],
                'Svelte' => [
                    'type' => 'JavaScript-фреймворк',
                    'signs' => ['svelte/internal', 'sveltekit'],
                    'description' => 'Компілятор для створення реактивних інтерфейсів.',
                    'site' => 'https://svelte.dev',
                ],
                'Astro' => [
                    'type' => 'JavaScript-фреймворк',
                    'signs' => ['data-astro-cid-', 'data-astro-source-file', 'astro-island'],
                    'description' => 'Фреймворк для швидких статичних сайтів.',
                    'site' => 'https://astro.build',
                ],
                'Express' => [
                    'type' => 'Node.js-фреймворк',
                    'strong' => [],
                    'weak' => [],
                    'headers' => ['X-Powered-By: Express'],
                    'description' => 'Мінімалістичний Node.js-фреймворк.',
                    'site' => 'https://expressjs.com',
                ],
                'Django' => [
                    'type' => 'Python-фреймворк',
                    'strong' => ['csrfmiddlewaretoken', 'django'],
                    'weak' => [],
                    'description' => 'Python-фреймворк для швидкої розробки.',
                    'site' => 'https://www.djangoproject.com',
                ],
                'Flask' => [
                    'type' => 'Python-фреймворк',
                    'strong' => ['flask'],
                    'weak' => [],
                    'description' => 'Мікрофреймворк для Python.',
                    'site' => 'https://flask.palletsprojects.com',
                ],
                'ASP.NET' => [
                    'type' => '.NET-фреймворк',
                    'strong' => ['asp.net', '__viewstate', '.aspx'],
                    'weak' => [],
                    'headers' => ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
                    'description' => 'Фреймворк від Microsoft.',
                    'site' => 'https://dotnet.microsoft.com/apps/aspnet',
                ],
            ],
            'technologies' => [
                'jQuery' => [
                    'category' => 'JavaScript-бібліотека',
                    'signs' => ['jquery.min.js', 'jquery.js', 'jquery-'],
                    'description' => 'Популярна JS-бібліотека.',
                    'site' => 'https://jquery.com',
                ],
                'Bootstrap' => [
                    'category' => 'CSS-фреймворк',
                    'signs' => ['bootstrap.min.css', 'bootstrap.css', 'bootstrap.bundle', 'class="container"', 'class="row"'],
                    'description' => 'CSS-фреймворк для адаптивних сайтів.',
                    'site' => 'https://getbootstrap.com',
                ],
                'Tailwind CSS' => [
                    'category' => 'CSS-фреймворк',
                    'signs' => ['tailwindcss', 'tailwind.min.css', 'tw-'],
                    'description' => 'Утилітарний CSS-фреймворк.',
                    'site' => 'https://tailwindcss.com',
                ],
                'Foundation' => [
                    'category' => 'CSS-фреймворк',
                    'signs' => ['foundation.min.css', 'foundation.css'],
                    'description' => 'Адаптивний CSS-фреймворк.',
                    'site' => 'https://get.foundation',
                ],
                'Bulma' => [
                    'category' => 'CSS-фреймворк',
                    'signs' => ['bulma.min.css', 'bulma.css'],
                    'description' => 'Сучасний CSS-фреймворк на Flexbox.',
                    'site' => 'https://bulma.io',
                ],
                'Font Awesome' => [
                    'category' => 'Іконки',
                    'signs' => ['fontawesome', 'fa-', 'font-awesome'],
                    'description' => 'Бібліотека іконок.',
                    'site' => 'https://fontawesome.com',
                ],
                'Google Analytics' => [
                    'category' => 'Аналітика',
                    'signs' => ['google-analytics.com', 'gtag(', 'ga(\'create\'', 'gtag.js'],
                    'description' => 'Сервіс аналітики від Google.',
                    'site' => 'https://analytics.google.com',
                ],
                'Google Tag Manager' => [
                    'category' => 'Тег-менеджер',
                    'signs' => ['googletagmanager.com', 'gtm.js'],
                    'description' => 'Система керування тегами.',
                    'site' => 'https://tagmanager.google.com',
                ],
                'Facebook Pixel' => [
                    'category' => 'Маркетинг',
                    'signs' => ['connect.facebook.net', 'fbq(', 'facebook.com/tr'],
                    'description' => 'Інструмент відстеження конверсій Meta.',
                    'site' => 'https://www.facebook.com/business/tools/meta-pixel',
                ],
                'Yandex.Metrika' => [
                    'category' => 'Аналітика',
                    'signs' => ['mc.yandex.ru', 'yandex.ru/metrika'],
                    'description' => 'Аналітика від Яндекс.',
                    'site' => 'https://metrika.yandex.com.ua',
                ],
                'Cloudflare' => [
                    'category' => 'CDN / Захист',
                    'signs' => ['cloudflare.com/cdn', '__cf_bm', 'cf-ray'],
                    'headers' => ['Server: cloudflare', 'CF-RAY:'],
                    'description' => 'CDN і захист від DDoS.',
                    'site' => 'https://www.cloudflare.com',
                ],
                'Amazon CloudFront' => [
                    'category' => 'CDN',
                    'signs' => ['cloudfront.net', 'x-amz-cf-id'],
                    'headers' => ['Via: CloudFront', 'X-Amz-Cf-Id'],
                    'description' => 'CDN від Amazon.',
                    'site' => 'https://aws.amazon.com/cloudfront',
                ],
                'reCAPTCHA' => [
                    'category' => 'Захист',
                    'signs' => ['google.com/recaptcha', 'grecaptcha'],
                    'description' => 'Захист від ботів від Google.',
                    'site' => 'https://www.google.com/recaptcha',
                ],
                'hCaptcha' => [
                    'category' => 'Захист',
                    'signs' => ['hcaptcha.com', 'h-captcha'],
                    'description' => 'Захист від ботів.',
                    'site' => 'https://www.hcaptcha.com',
                ],
                'Hotjar' => [
                    'category' => 'Аналітика',
                    'signs' => ['static.hotjar.com', 'hjid'],
                    'description' => 'Аналітика поведінки користувачів.',
                    'site' => 'https://www.hotjar.com',
                ],
                'PHP' => [
                    'category' => 'Мова програмування',
                    'signs' => [],
                    'headers' => ['X-Powered-By: PHP'],
                    'description' => 'Серверна мова програмування.',
                    'site' => 'https://www.php.net',
                ],
                'Nginx' => [
                    'category' => 'Веб-сервер',
                    'signs' => [],
                    'headers' => ['Server: nginx'],
                    'description' => 'Високопродуктивний веб-сервер.',
                    'site' => 'https://nginx.org',
                ],
                'Apache' => [
                    'category' => 'Веб-сервер',
                    'signs' => [],
                    'headers' => ['Server: Apache'],
                    'description' => 'Популярний веб-сервер.',
                    'site' => 'https://httpd.apache.org',
                ],
                'IIS' => [
                    'category' => 'Веб-сервер',
                    'signs' => [],
                    'headers' => ['Server: Microsoft-IIS'],
                    'description' => 'Веб-сервер від Microsoft.',
                    'site' => 'https://www.iis.net',
                ],
                'LiteSpeed' => [
                    'category' => 'Веб-сервер',
                    'signs' => [],
                    'headers' => ['Server: LiteSpeed'],
                    'description' => 'Швидкий веб-сервер.',
                    'site' => 'https://www.litespeedtech.com',
                ],
                'Varnish' => [
                    'category' => 'Кешування',
                    'signs' => [],
                    'headers' => ['Via: varnish', 'X-Varnish'],
                    'description' => 'HTTP-акселератор і кеш.',
                    'site' => 'https://varnish-cache.org',
                ],
                'YouTube' => [
                    'category' => 'Відео',
                    'signs' => ['youtube.com/embed', 'youtube.com/iframe_api', 'ytplayer'],
                    'description' => 'Відео-плеєр YouTube.',
                    'site' => 'https://www.youtube.com',
                ],
                'Vimeo' => [
                    'category' => 'Відео',
                    'signs' => ['player.vimeo.com', 'vimeo.com/video'],
                    'description' => 'Відео-плеєр Vimeo.',
                    'site' => 'https://vimeo.com',
                ],
            ],
        ];
    }
}
