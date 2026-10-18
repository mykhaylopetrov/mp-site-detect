<?php

declare(strict_types=1);

namespace App;

use RuntimeException;

/**
 * Клас виявлення інформації про сайт:
 * IP-адреса, геолокація, хостинг, WHOIS, CMS, фреймворки та інші технології.
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
     * Виконати повний аналіз сайту.
     */
    public function analyze(): array
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
        });

        return $result;
    }

    /**
     * Виконати аналіз із поступовим сповіщенням про кожен модуль.
     * Викликає $emit($sectionName, $sectionData) одразу після кожного завершеного кроку.
     * Дозволяє реалізувати потокову (SSE) віддачу результатів у реальному часі.
     *
     * @param callable(string, mixed): void $emit
     */
    public function analyzeWithCallback(callable $emit): array
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
        });

        $emit('complete', $result);
        return $result;
    }

    /**
     * Внутрішній послідовний обхід усіх кроків аналізу.
     * Викликає $onSection($name, $data) після кожного завершеного кроку.
     * Назва секції 'meta' використовується для базової інформації (domain, ip, url, checked_at).
     *
     * @param callable(string, mixed): void $onSection
     */
    private function runAnalysis(callable $onSection): void
    {
        $ip = $this->resolveIp($this->domain);

        $onSection('meta', [
            'domain' => $this->domain,
            'url' => $this->url,
            'ip' => $ip,
            'checked_at' => date('c'),
        ]);

        if ($ip !== null) {
            $geo = $this->lookupGeo($ip);
            if ($geo !== null) {
                $onSection('location', $geo['location']);
                $onSection('hosting', $geo['hosting']);
            }
        }

        $whois = $this->lookupWhois($this->domain);
        if ($whois !== null) {
            $onSection('whois', $whois);
        }

        $html = $this->fetchHtml();
        $cms = [];
        $frameworks = [];
        $serverInfo = null;
        if ($html !== null) {
            $generator = $this->extractMeta($html, 'generator');
            $cms = $this->detectCms($html, $generator);
            // Fallback: якщо HTML — сторінка-заглушка Hostia/bot challenge без wp-маркерів,
            // але сайт все одно на WordPress — перевіряємо прямими запитами до відомих WP-ендпоінтів.
            if (empty($cms)) {
                $probed = $this->probeCmsViaEndpoints();
                if (!empty($probed)) {
                    $cms = $probed;
                }
            }
            if (!empty($cms)) {
                // Якщо знайдено WordPress — вбудовуємо його деталі прямо в елемент CMS
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
                $onSection('cms', $cms);
            }

            $frameworks = $this->detectFrameworks($html, $this->httpHeaders);
            if (!empty($frameworks)) {
                $onSection('frameworks', $frameworks);
            }

            $serverInfo = $this->detectWebServer($this->httpHeaders);
            $cdn = $this->detectCdn($this->httpHeaders, $html);
            $dbInfo = $this->detectDatabase($this->httpHeaders, $html, $cms, $frameworks, []);
            $nodeInfo = $this->detectNodeJs($this->httpHeaders, $html);
            $pythonInfo = $this->detectPython($this->httpHeaders, $html, $frameworks);
            $unified = $this->buildUnifiedServer($serverInfo, $cdn, $dbInfo, $nodeInfo, $pythonInfo);
            $onSection('server', $unified);
        } else {
            // Навіть якщо HTML не завантажився, пробуємо визначити сервер за заголовками (можуть бути з редиректу)
            if (!empty($this->httpHeaders)) {
                $serverInfo = $this->detectWebServer($this->httpHeaders);
            } else {
                $serverInfo = ['name' => 'невідомо', 'version' => null, 'raw' => null, 'powered_by' => null, 'security_headers' => [], 'note' => 'Server-заголовок відсутній'];
            }
            $cdn = null;
            $dbInfo = $this->detectDatabase($this->httpHeaders, $html, $cms, $frameworks, []);
            $nodeInfo = $this->detectNodeJs($this->httpHeaders, $html);
            $pythonInfo = $this->detectPython($this->httpHeaders, $html, $frameworks);
            $unified = $this->buildUnifiedServer($serverInfo, $cdn, $dbInfo, $nodeInfo, $pythonInfo);
            $onSection('server', $unified);
        }
    }

    /**
     * Форматує значення error_reporting() у людино-зрозумілий рядок.
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
        // E_STRICT застаріло з PHP 8.4 — перевіряємо версію, щоб не викликати
        // deprecation notice в нових версіях.
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

        // Якщо RDAP-відповідь коректна — парсимо її (основний шлях)
        if (is_array($data) && !isset($data['error'])) {
            $domainName = is_string($data['domain'] ?? null) ? $data['domain'] : $domain;
            if (!empty($data['isRegistered']) && $data['isRegistered'] === false) {
                return [
                    'Домен' => $domainName,
                    'Статус' => 'Домен не зареєстрований',
                ];
            }
            // Якщо є дані реєстратора/дат — повертаємо результат
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
                // Якщо після очищення залишився хоча б домен + ще одне поле — вважаємо валідним
                if (count($cleaned) > 1) {
                    return $cleaned;
                }
            }
            // Інакше — можливо домен делегованої зони (.lviv.ua тощо), де hostmaster RDAP дає 501.
            // Пробуємо fallback через TCP WHOIS.
        }

        // Fallback 1: TCP WHOIS через whois.ua (автоматично редіректить на whois.lviv.ua / whois.uar.net)
        $fallback = $this->lookupWhoisViaTcp($domain);
        if ($fallback !== null) {
            return $fallback;
        }

        // Fallback 2: якщо RDAP повернув явну помилку, але TCP теж не спрацював — показуємо
        // інформативний блок замість приховування секції, щоб користувач бачив причину.
        if (is_array($data) && isset($data['error'])) {
            $detail = $data['error']['detail'] ?? $data['error']['message'] ?? '';
            // Для делегованих зон rdap.hostmaster.ua часто дає 501 — це не означає відсутність WHOIS
            return $this->cleanFields([
                'Домен' => $domain,
                'Примітка' => 'WHOIS через RDAP тимчасово недоступний для цієї зони (registry error 501). Спробуйте оновити пізніше — дані буде отримано через резервний WHOIS.',
                'Деталі' => $detail ?: null,
            ]);
        }

        // Якщо первинний HTTP-запит взагалі не відповів — пробуємо ще раз через TCP, і якщо й він пустий — повертаємо null
        // (секція не покажеться, але це вже крайній випадок коли мережа недоступна).
        return null;
    }

    /**
     * Резервний WHOIS через TCP (порт 43) для делегованих зон .ua (lviv.ua, kharkiv.ua тощо).
     * Використовує whois.ua, який автоматично редіректить на whois.lviv.ua / whois.uar.net.
     */
    private function lookupWhoisViaTcp(string $domain): ?array
    {
        // Пробуємо кілька серверів по черзі — перший успішний результат парсимо
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
     * Виконує TCP-запит до WHOIS-сервера.
     */
    private function whoisTcpQuery(string $domain, string $server, int $timeout = 5): ?string
    {
        $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);
        if ($fp === false || $fp === null) {
            return null;
        }
        // Таймаут читання
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
     * Парсить сирий WHOIS-текст (формат UARNet / whois.ua redirect) у структуру для відображення.
     */
    private function parseWhoisTcp(string $raw, string $domain): ?array
    {
        // Відсікаємо випадки "No match" / домен не знайдено
        $lower = strtolower($raw);
        if (str_contains($lower, 'no match') || str_contains($lower, 'no entries found') || str_contains($lower, 'not found') && str_contains($lower, 'no data')) {
            // Перевіряємо чи точно це повідомлення про відсутність домену, а не просто "status: not found"
            if (preg_match('~no match for|no entries found for|domain not found~i', $raw)) {
                return [
                    'Домен' => $domain,
                    'Статус' => 'Домен не зареєстрований',
                ];
            }
        }
        // Для UARNet формат відрізняється: поля "Domain Name:", "Registrar:", "Creation Date:" тощо
        // Також підтримуємо формат hostmaster.ua "% Domain:" / "domain:".
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

        // Розбиваємо на рядки та парсимо "Key: value"
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

            // DNS-сервери — може бути кілька рядків "Name Server:" / "nserver:" / "nameserver"
            if (in_array($keyLower, ['name server', 'nserver', 'nameserver', 'name servers'], true)) {
                // Значення може бути "dns1.hostiq.ua" або "dns1.hostiq.ua 185.68.16.16"
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
                // Формат "ok https://icann.org/epp#ok" — беремо перше слово
                $statusList[] = $value;
                continue;
            }

            foreach ($map as $uaKey => $aliases) {
                foreach ($aliases as $alias) {
                    if (strtolower($alias) === $keyLower) {
                        // Не перезаписуємо якщо вже є
                        if (!isset($result[$uaKey]) || $result[$uaKey] === null) {
                            // Дати форматуємо
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
            // Нормалізуємо статуси: "ok https://..." -> "ok"
            $norm = array_map(static fn($s) => trim(explode(' ', $s)[0]), $statusList);
            $result['Статуси домену'] = implode(', ', array_unique($norm));
        }

        // Якщо вдалося витягнути хоча б реєстратора або дати — вважаємо валідним
        $hasData = isset($result['Реєстратор']) || isset($result['Дата створення']) || isset($result['Дата закінчення']) || isset($result['DNS-сервери']);
        if (!$hasData) {
            return null;
        }

        // Додаємо примітку про джерело для делегованих зон
        // Не додаємо як окреме поле щоб не засмічувати, але можна залишити для дебагу
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

        // Спочатку намагаємось через cURL — він надійніше повертає заголовки
        // ($http_response_header на деяких хостингах спорожнюється після
        // кількох file_get_contents-підряд — наприклад, коли викликаються
        // DNS-WHOIS, ip-api, потім HTML. cURL ізольований для кожного запиту).
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

        // Фолбек через file_get_contents (якщо cURL недоступний)
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
     * Завантаження сторінки через cURL.
     * Повертає масив ['headers' => [...], 'body' => '...'] або null при помилці.
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
            CURLOPT_HEADER => true,           // повернути заголовки в тілі відповіді
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
            CURLOPT_ENCODING => '',          // підтримка gzip/deflate
        ]);
        $response = curl_exec($ch);
        if ($response === false) {
            // PHP 8.0+ не потребує curl_close (no-op), але викликаємо для сумісності
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            return null;
        }
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }

        $rawHeaders = substr((string)$response, 0, (int)$headerSize);
        $body = substr((string)$response, (int)$headerSize);

        $headers = $this->parseRawHeaders($rawHeaders);
        return ['headers' => $headers, 'body' => $body];
    }

    /**
     * Парсер сирих HTTP-заголовків (формат "Name: value\r\n") у масив рядків.
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
        $found = [];

        $lower = strtolower($html);
        if ($generator) {
            $gen = strtolower($generator);
            foreach ($candidates as $name => $info) {
                foreach ($info['generators'] ?? [] as $g) {
                    if (str_contains($gen, strtolower($g))) {
                        $found[$name] = $info;
                        break;
                    }
                }
            }
        }

        foreach ($candidates as $name => $info) {
            if (isset($found[$name])) {
                continue;
            }
            foreach ($info['signs'] ?? [] as $sign) {
                if (str_contains($lower, strtolower($sign))) {
                    $found[$name] = $info;
                    break;
                }
            }
        }

        $result = [];
        foreach ($found as $name => $info) {
            $result[] = [
                'name' => $name,
                'confidence' => $info['confidence'] ?? 'medium',
                'description' => $info['description'] ?? '',
                'site' => $info['site'] ?? null,
            ];
        }
        return $result;
    }

    /**
     * Резервна перевірка CMS через прямі запити, коли HTML — антибот-заглушка.
     * Повертає масив у форматі detectCms або порожній.
     */
    private function probeCmsViaEndpoints(): array
    {
        // Перевіряємо кілька характерних WP-ендпоінтів
        $checks = [
            $this->url . '/wp-json/' => function(string $body): bool {
                if ($body === '') return false;
                $data = json_decode($body, true);
                if (!is_array($data)) return false;
                // Наявність routes з wp/v2 — явна ознака WP REST API
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
                // Сторінка логіну WP містить loginform
                return stripos($body, 'loginform') !== false || stripos($body, 'wp-submit') !== false;
            },
            $this->url . '/wp-includes/js/wp-emoji-release.min.js' => function(string $body): bool {
                // SPA-сайти (Angular/React) віддають головну сторінку на будь-який невідомий шлях.
                // Тому перевіряємо, що це справді JS-файл, а не HTML-фолбек, і що в ньому є twemoji.
                if (stripos($body, '<!DOCTYPE') !== false || stripos($body, '<html') !== false) {
                    return false;
                }
                return stripos($body, 'twemoji') !== false;
            },
        ];

        foreach ($checks as $url => $validator) {
            $body = $this->httpGet($url, 5);
            if ($body === null || $body === '') continue;
            // Якщо це антибот-заглушка Hostia — пропускаємо (перевіряємо характерний маркер)
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
        $found = [];
        $lower = strtolower($html);

        foreach ($this->signatures['frameworks'] as $name => $info) {
            $matched = false;
            foreach ($info['signs'] ?? [] as $sign) {
                if (str_contains($lower, strtolower($sign))) {
                    $matched = true;
                    break;
                }
            }
            if (!$matched) {
                foreach ($info['headers'] ?? [] as $h) {
                    foreach ($headers as $header) {
                        if (stripos($header, $h) !== false) {
                            $matched = true;
                            break 2;
                        }
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
     * Конфігурація розпізнавання CDN.
     * Кожен запис: ['name' => ..., 'headers' => [...], 'server_match' => ..., 'via_match' => ..., 'html_signs' => [...]]
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
     * Визначення веб-сервера за HTTP-заголовками.
     *
     * Повертає структуру:
     *   [
     *     'name'             => string  — назва (nginx, Apache, LiteSpeed, IIS, Caddy, cloudflare тощо)
     *     'version'          => string|null  — версія, якщо її розкрито
     *     'powered_by'       => string|null  — X-Powered-By
     *     'security_headers' => array        — X-Frame-Options, HSTS, CSP тощо
     *     'note'             => string|null  — пояснення, якщо сервер прихований
     *     'raw'              => string|null  — необроблене значення Server-заголовка
     *   ]
     */
    private function detectWebServer(array $headers): array
    {
        $result = [
            'name' => 'невідомо',
            'version' => null,
            'powered_by' => null,
            'php_version' => null,
            'php_version_source' => null,
            'security_headers' => [],
            'note' => null,
            'raw' => null,
        ];

        $rawPoweredBy = null;
        $serverMatched = false;

        foreach ($headers as $h) {
            $colon = strpos($h, ':');
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($h, 0, $colon)));
            $value = trim(substr($h, $colon + 1));

            switch ($name) {
                case 'server':
                    $result['raw'] = $value;
                    $parsed = $this->parseServerHeader($value);
                    if ($parsed !== null) {
                        $result['name'] = $parsed['name'];
                        $result['version'] = $parsed['version'];
                        $serverMatched = true;
                    } else {
                        // Невідомий формат — все одно показуємо як є
                        $result['name'] = $value !== '' ? $value : 'невідомо';
                        $serverMatched = $value !== '';
                    }
                    break;
                case 'x-powered-by':
                    $rawPoweredBy = $value;
                    $result['powered_by'] = $value;
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
            // Server-заголовок відсутній. Спробуємо визначити за X-Powered-By
            // та іншими непрямими ознаками.
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
            } elseif (in_array($lowerName, ['cloudfront', 'amazons3', 's3', 'akamai', 'akamaighost', 'netdna-cache'], true)) {
                $result['note'] = 'Реальний веб-сервер прихований за CDN (потрібно дивитись оригінальний Server-заголовок на початку ланцюга)';
            }
        }

        // Точна версія PHP — лише якщо її прямо розкриває заголовок (X-Powered-By / Server), без здогадок за CMS
        $phpVersion = null;
        $phpSource = null;
        if ($rawPoweredBy !== null && preg_match('~php/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.-][A-Za-z0-9]+)*)~i', $rawPoweredBy, $m)) {
            $phpVersion = $m[1];
            $phpSource = 'X-Powered-By';
        } elseif ($result['raw'] !== null && preg_match('~php/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.-][A-Za-z0-9]+)*)~i', $result['raw'], $m)) {
            $phpVersion = $m[1];
            $phpSource = 'Server';
        }

        // Якщо на головній заголовок приховано (часте кешування), пробуємо точні PHP-ендпоінти
        if ($phpVersion === null) {
            $extra = $this->probePhpVersionViaHeaders();
            if ($extra !== null) {
                $phpVersion = $extra['version'];
                $phpSource = $extra['source'];
            }
        }

        // Останній шанс — відкритий phpinfo (дає точну версію, якщо адміністратор залишив файл)
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
        } else {
            // Явно прибираємо порожні php-поля, щоб не засмічувати відповідь
            unset($result['php_version'], $result['php_version_source']);
        }

        return $result;
    }

    /**
     * Виявлення Node.js за заголовками та HTML.
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

        // HTML-сигнали (без версії, лише presence)
        if ($html !== null && !$present) {
            $lowHtml = strtolower($html);
            if (str_contains($lowHtml, 'x-powered-by: express') || str_contains($lowHtml, '__next_data__') || str_contains($lowHtml, '__nuxt__')) {
                // Next/Nuxt працюють на Node, але версія невідома
                // Не маркуємо як Node присутній без заголовків, щоб не давати хибних спрацювань
            }
        }

        return ['present' => $present, 'version' => $version, 'source' => $source];
    }

    /**
     * Виявлення Python за заголовками, HTML та фреймворками.
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

        // Інференс за фреймворками Python
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
     * Будує уніфіковану секцію Веб-сервер (на всю ширину) з усіма підсистемами.
     */
    private function buildUnifiedServer(array $serverInfo, ?array $cdn, array $dbInfo, array $nodeInfo, array $pythonInfo): array
    {
        $result = $serverInfo;

        // PHP вже у $serverInfo (php_version / php_version_source) — залишаємо як є

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
            // Зберігаємо додаткові поля CDN для дебагу, але не обов'язково
            foreach ($cdn as $k => $v) {
                if (!in_array($k, ['provider', 'detection'], true)) {
                    $result['cdn_' . $k] = $v;
                }
            }
        } else {
            $result['cdn_provider'] = null;
            $result['cdn_detection'] = null;
        }

        // БД
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
     * Додаткова проба заголовків на PHP-ендпоінтах, де X-Powered-By часто не приховано кешем.
     * Перевіряє /wp-login.php, /index.php, /xmlrpc.php коротким HEAD-запитом.
     * Повертає ['version'=>string,'source'=>string] або null.
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
     * Виконує HEAD/GET запит і повертає масив заголовків (рядки "Name: value") або [].
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
                CURLOPT_NOBODY => true, // HEAD — достатньо заголовків
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
            // При NOBODY тіло відсутнє, тому весь resp — заголовки
            return $this->parseRawHeaders((string)$resp);
        }
        // Фолбек через get_headers
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
     * Строга перевірка наявності відкритого phpinfo-файлу.
     * Повертає null якщо файл не існує / не є справжнім phpinfo,
     * інакше масив ['isPhpInfo'=>bool,'version'=>?string].
     * Вимоги: HTTP 200 + наявність <title>phpinfo або PHP Version.
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
     * Дистанційне визначення СУБД сайту, що перевіряється.
     * Намагається точно встановити DBMS та її версію (MySQL/MariaDB/PostgreSQL/SQLite/Progress/MSSQL/Oracle).
     * Джерела в порядку пріоритету:
     *  1) phpinfo (строгий, HTTP 200 + title) — парсить Client API version / Server version
     *  2) витік у HTML (SQL-ошибки з версією)
     *  3) заголовки X-DB-* (рідко)
     *  4) інференс за CMS/фреймворком (WordPress→ MySQL/MariaDB без версії)
     * Якщо точну версію дистанційно визначити неможливо — повертає detected=false або version=null з поясненням.
     *
     * @return array{detected: bool, dbms: ?string, version: ?string, source: ?string, note: string, evidence: ?string}
     */
    private function detectDatabase(array $headers, ?string $html, array $cms = [], array $frameworks = [], array $tech = []): array
    {
        $headersStr = strtolower(implode("\n", $headers));
        $htmlLower = $html !== null ? strtolower($html) : '';
        $htmlRaw = $html ?? '';

        // 1) Спроба через phpinfo (найточніше — дає і тип, і версію)
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

        // 2) Заголовки, що прямо вказують на БД (рідко, але точно)
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

        // 3) Витік у HTML — пошук SQL-помилок з версією
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
                    // Перевіряємо, що поруч є ознаки помилки БД, щоб не ловити випадкові згадки
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
            // Легший пошук без версії — просто згадка БД в контексті помилки
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

        // 4) Інференс за CMS / фреймворком (ймовірно, без точної версії)
        $phpCms = ['WordPress','Joomla','Drupal','OpenCart','PrestaShop','Magento','1С-Бітрікс','MODX','phpBB','vBulletin'];
        $cmsList = [];
        foreach ($cms as $c) {
            $n = $c['name'] ?? '';
            if (in_array($n, $phpCms, true)) $cmsList[] = $n;
        }
        if (!empty($cmsList)) {
            // WordPress/Joomla/Drupal традиційно працюють на MySQL/MariaDB
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

        // 5) Нічого не знайдено — точну СУБД визначити неможливо
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
     * Отримує тіло phpinfo, якщо файл відкрито (строгий HTTP 200 + маркери), інакше null.
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
                // Повторно завантажуємо тіло (probe вже перевірив, але body не повертав)
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
     * Парсить СУБД та версію з HTML phpinfo.
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
                // Знайдено секцію БД без версії — все одно фіксуємо тип
                $evidence = $cfg['needle'];
            }
            return ['dbms' => $dbms, 'version' => $version, 'evidence' => $evidence];
        }
        // Додатково: якщо є pdo_mysql / mysqli — це MySQL/MariaDB без точної версії
        if (stripos($body, 'pdo_mysql') !== false || stripos($body, 'mysqli') !== false) {
            return ['dbms' => 'MySQL / MariaDB', 'version' => null, 'evidence' => 'pdo_mysql/mysqli'];
        }
        return null;
    }

    /**
     * Парсер заголовка Server: nginx/1.18.0, Apache/2.4.41, cloudflare тощо.
     * Повертає масив ['name' => ..., 'version' => string|null] або null для порожніх/невалідних.
     */
    private function parseServerHeader(string $value): ?array
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        // Спроба стандартного "name/version" формату
        if (preg_match('~^\s*([A-Za-z][A-Za-z0-9\-\.\+_]*)\s*/\s*([0-9][0-9\.\-]+[0-9a-zA-Z])\s*$~', $value, $m)) {
            return ['name' => $m[1], 'version' => $m[2]];
        }
        // Без версії — просто назва
        if (preg_match('~^\s*([A-Za-z][A-Za-z0-9\-\.\+_]*)\s*$~', $value, $m)) {
            return ['name' => $m[1], 'version' => null];
        }
        // Складені назви на кшталт "Microsoft-IIS/10.0" — пробуємо витягнути перший "токен/version"
        $parts = preg_split('~/\s*~', $value, 2);
        if (is_array($parts) && count($parts) === 2) {
            $name = trim($parts[0]);
            $ver = trim($parts[1]);
            if ($name !== '' && preg_match('~^[A-Za-z][A-Za-z0-9\-\.\+_]*$~', $name)
                && preg_match('~^[0-9][0-9\.\-a-zA-Z]+$~', $ver)) {
                return ['name' => $name, 'version' => $ver];
            }
        }
        return null;
    }

    /**
     * Визначення CDN (мережі доставки контенту).
     *
     * Перевіряє заголовки та HTML за конфігом CDN_SIGNATURES.
     * Повертає масив з полями: provider, detection + додаткові поля (ray_id, pop, served_by тощо).
     */
    private function detectCdn(array $headers, string $html): ?array
    {
        $lowerHtml = strtolower($html);
        $candidates = [];

        foreach (self::CDN_SIGNATURES as $provider => $cfg) {
            $detection = null;
            $extra = [];

            // 1. Специфічні заголовки
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

            // 2. Заголовок Server
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

            // 3. Заголовок Via
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

        // 4. Фолбек за HTML-вмістом
        if (empty($candidates)) {
            foreach (self::CDN_SIGNATURES as $provider => $cfg) {
                foreach ($cfg['html_signs'] ?? [] as $sign) {
                    if (str_contains($lowerHtml, strtolower($sign))) {
                        $candidates[] = [
                            'provider' => $provider,
                            'detection' => 'HTML content (' . $sign . ')',
                            'priority' => $cfg['priority'] + 100, // нижчий пріоритет за заголовки
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
     * Захоплення HTTP-заголовків останнього запиту.
     * Працює з PHP 8.5+ (http_get_last_response_headers) та попередніми версіями.
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
     * Виявлення теми та плагінів WordPress на основі HTML і додаткових запитів.
     */
    private function detectWordPressDetails(string $html, ?string $generator = null): ?array
    {
        $theme = $this->detectWordPressTheme($html);
        $parentTheme = null;

        // Якщо активна тема — child, спочатку завантажуємо info про parent-тему,
        // щоб використати її "Tested up to" для визначення версії WP.
        if (is_array($theme) && !empty($theme['parent_slug'])) {
            $parentTheme = $this->fetchThemeInfo($theme['parent_slug']);
        }

        $versionInfo = $this->detectWordPressVersion($html, $generator, $theme, $parentTheme);
        $plugins = $this->detectWordPressPlugins($html);
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
     * Визначення адреси входу в адмін-панель WordPress.
     *
     * Логіка:
     *  1) Перевіряє стандартні адреси `/wp-login.php` та `/wp-admin/` —
     *     якщо хоча б одна повертає ознаки сторінки входу (200 з формою
     *     або 302 на wp-login), повертає її як `is_default = true`.
     *  2) Якщо стандартні повертають 404 та `/wp-admin/` редиректить на
     *     кастомний шлях — перевіряє ціль редиректу, чи це login-сторінка.
     *  3) Інакше сканує HTML на наявність посилань, що містять login-like
     *     ключові слова, і перевіряє кожен кандидат пробним запитом.
     *  4) Якщо нічого не знайдено — повертає структуру з `is_hidden = true`
     *     та поясненням для користувача.
     *
     * @return array{url: ?string, path: ?string, is_default: bool, is_custom: bool, is_hidden: bool, status_code: ?int, note: string, detection_method: ?string}
     */
    private function detectWordPressLoginUrl(string $html): array
    {
        $base = rtrim($this->url, '/');
        $origin = $this->scheme . '://' . parse_url($this->url, PHP_URL_HOST)
            . (parse_url($this->url, PHP_URL_PORT) ? ':' . parse_url($this->url, PHP_URL_PORT) : '');

        // 1. Стандартні адреси
        $defaults = ['/wp-login.php', '/wp-admin/'];
        foreach ($defaults as $path) {
            $probe = $this->probeUrlForLogin($base . $path);
            if ($probe['is_login']) {
                $fullUrl = $base . $path;
                // Для /wp-admin/ може бути 302 → location містить повну адресу логіну
                if ($path === '/wp-admin/' && !empty($probe['redirect_location'])) {
                    $loc = $probe['redirect_location'];
                    // Якщо редирект веде на кастомний шлях, що є логіном — показати його
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

        // Якщо /wp-admin/ редиректить на кастомний шлях — перевіримо його навіть коли probe не дав is_login прямо
        $adminProbe = $this->probeUrlForLogin($base . '/wp-admin/');
        if (!empty($adminProbe['redirect_location'])) {
            $loc = $adminProbe['redirect_location'];
            $locLower = strtolower($loc);
            // Якщо редирект не на wp-login.php і не 404-сторінку — можливо це кастомний логін
            if (!str_contains($locLower, 'wp-login.php') && $locLower !== '' && $adminProbe['status'] >= 300 && $adminProbe['status'] < 400) {
                $resolved = $this->resolveUrl($loc, $origin);
                // Ігноруємо редиректи на головну або зовнішні домени
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

        // 2. Сканування HTML на кандидатів (посилання з login/admin у href)
        $candidates = $this->extractLoginCandidates($html);
        foreach ($candidates as $candidatePath) {
            // Пропускаємо стандартні — вже перевірені
            if (in_array($candidatePath, ['/wp-login.php', '/wp-admin', '/wp-admin/'], true)) {
                continue;
            }
            $full = $this->resolveUrl($candidatePath, $origin);
            // Якщо кандидат збігається з base (тобто відносний без слеша) — нормалізуємо
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

        // 3. Нічого не знайдено — приховано
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
     * Пробний запит до URL для перевірки, чи це сторінка входу WordPress.
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
            // Також перевіряємо через curl_getinfo redirect_url якщо заголовок не розпарсився
            if (is_string($redirectUrl) && $redirectUrl !== '') {
                $result['redirect_location'] = $result['redirect_location'] ?? $redirectUrl;
            }

            // Знайти Location заголовок (пріоритет над CURLINFO_REDIRECT_URL)
            foreach ($this->parseRawHeaders($rawHeaders) as $h) {
                if (stripos($h, 'Location:') === 0) {
                    $result['redirect_location'] = trim(substr($h, 9));
                    break;
                }
            }

            // 1) Редирект на login
            if ($code >= 300 && $code < 400 && $result['redirect_location'] !== null) {
                $locLower = strtolower($result['redirect_location']);
                if (str_contains($locLower, 'wp-login') || str_contains($locLower, 'wp-admin') || str_contains($locLower, 'login') || str_contains($locLower, 'dashboard')) {
                    // Відсікаємо канонічні редиректи типу lanet.ua/wp-login.php → www.lanet.ua/wp-login.php
                    // (той самий шлях, лише інший хост/схема) — вони не означають наявність WordPress
                    $requestedPath = strtolower(parse_url($url, PHP_URL_PATH) ?? '/');
                    // redirect_location може бути відносним або абсолютним
                    $redirectPath = strtolower(parse_url($result['redirect_location'], PHP_URL_PATH) ?? '/');
                    // Нормалізуємо trailing slash для порівняння
                    $normReq = rtrim($requestedPath, '/') ?: '/';
                    $normRedir = rtrim($redirectPath, '/') ?: '/';
                    if ($normReq === $normRedir) {
                        // Той самий шлях — канонічний редирект (www ↔ non-www, http ↔ https)
                        // Не вважаємо це ознакою WordPress-логіну
                        return $result;
                    }
                    if (str_contains($locLower, 'wp-login') || str_contains($locLower, 'wp-admin')) {
                        $result['is_login'] = true;
                        return $result;
                    }
                }
                // Для кастомних — не вважаємо одразу, нехай викликач перевірить ціль окремо
                return $result;
            }

            // 2) 200 з ознаками форми входу
            if ($code === 200 && $body !== '') {
                if ($this->isWpLoginPage($body, $url)) {
                    $result['is_login'] = true;
                    return $result;
                }
            }

            // 3) 403 з ознаками login (деякі хости віддають 403 але тіло — login)
            if ($code === 403 && $body !== '' && $this->isWpLoginPage($body, $url)) {
                $result['is_login'] = true;
                return $result;
            }

            return $result;
        }

        // Fallback без cURL — через get_headers + file_get_contents
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
     * Перевіряє, чи HTML є сторінкою входу WordPress.
     */
    private function isWpLoginPage(string $body, string $url = ''): bool
    {
        $lower = strtolower($body);
        // Найнадійніші маркери форми входу WP
        if (str_contains($lower, 'id="loginform"') || str_contains($lower, "id='loginform'")) {
            return true;
        }
        if (str_contains($lower, 'name="log"') && str_contains($lower, 'name="pwd"') && str_contains($lower, 'wp-submit')) {
            return true;
        }
        if (str_contains($lower, 'name="log"') && str_contains($lower, 'name="pwd"') && str_contains($lower, 'wordpress')) {
            return true;
        }
        // Заголовок wp-login + форма
        if (str_contains($lower, 'wp-login.php') && str_contains($lower, 'wordpress') && str_contains($lower, '<form')) {
            // Переконаємося, що це не просто згадка в контенті, а саме сторінка логіну
            if (preg_match('~<form[^>]*\baction\s*=\s*["\'][^"\']*wp-login\.php["\']~i', $body)) {
                return true;
            }
        }
        // Фолбек: якщо URL — це wp-login.php і в тілі є "log in" + wordpress
        if (str_contains(strtolower($url), 'wp-login.php') && str_contains($lower, 'wordpress') && (str_contains($lower, 'log in') || str_contains($lower, 'увійти') || str_contains($lower, 'вхід'))) {
            return true;
        }
        return false;
    }

    /**
     * Витягує кандидатів на кастомний login-шлях з HTML.
     *
     * @return string[] список шляхів/URL (наприклад, "/my-login/", "/hidden-admin/")
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
                // Пропускаємо статичні ресурси
                if (preg_match('~\.(css|js|mjs|jpg|jpeg|png|gif|webp|avif|svg|woff2?|ttf|eot|pdf|zip|mp4|mp3)(?:[?#]|$)~i', $lowerHref)) {
                    continue;
                }
                // Пропускаємо wp-content / wp-includes
                if (str_contains($lowerHref, '/wp-content/') || str_contains($lowerHref, '/wp-includes/')) {
                    continue;
                }
                // Лише ті, що містять login-like ключові слова
                if (!preg_match('~(login|log-in|signin|sign-in|admin|dashboard|auth|enter|my-login|secret)~i', $href)) {
                    continue;
                }
                // Виключаємо logout
                if (str_contains($lowerHref, 'logout') || str_contains($lowerHref, 'action=logout')) {
                    continue;
                }
                // Нормалізація
                $path = strtok($href, '#') ?: $href;
                if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
                    $parts = parse_url($path);
                    if (!isset($parts['host'])) continue;
                    $host = strtolower($parts['host']);
                    $ownHost = strtolower(parse_url($this->url, PHP_URL_HOST) ?? '');
                    if ($host !== $ownHost && $host !== 'www.' . $ownHost && $ownHost !== 'www.' . $host) {
                        continue; // чужий домен
                    }
                    $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
                } elseif (str_starts_with($path, '//')) {
                    continue;
                } elseif (!str_starts_with($path, '/')) {
                    // відносний шлях — перетворюємо на абсолютний
                    if (!str_contains($path, '/') && strlen($path) < 3) continue;
                    if (str_starts_with($path, './')) $path = substr($path, 2);
                    $path = '/' . ltrim($path, '/');
                }
                if (!str_starts_with($path, '/')) continue;
                if (strlen($path) > 160) continue;
                // Дублікати
                $candidates[$path] = true;
                if (count($candidates) >= 20) break;
            }
        }
        return array_keys($candidates);
    }

    /**
     * Розв'язує відносний/абсолютний Location у повний URL.
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
     * Визначення версії WordPress з надійних джерел.
     *
     * Пріоритет (повертає СТРУКТУРОВАНУ інформацію, а не просто рядок):
     *   1. `<meta name="generator" content="WordPress X.Y.Z">` — генерується динамічно
     *      при кожному запиті, тож це найнадійніший сигнал. Повертає ТОЧНУ версію.
     *   2. `/readme.html` — статичний файл, що постачається з ядром. Може бути
     *      застарілим, тому використовується як фолбек. Повертає ТОЧНУ версію.
     *   3. Header `Tested up to: X.Y` у `style.css` активної (або parent-) теми —
     *      автор теми оновлює це поле після тестування з новою версією WP. Дуже
     *      близький сигнал до точної версії (зазвичай співпадає або відстає на 1 мінор).
     *   4. REST endpoints `/wp-json/` — дає МІНІМАЛЬНУ нижню межу версії
     *      (наявність `wp-abilities/v1` означає ≥ 7.0).
     *   5. Twemoji-версія з `wp-includes/js/wp-emoji-release.min.js` — додатковий
     *      сигнал для новіших версій WP (≥ 6.0).
     *
     * Фолбек на `?ver=` у `/wp-includes/` для скриптів НЕ використовується: там часто
     * зустрічається версія jQuery (`jquery.min.js?ver=3.7.1`), а не WordPress.
     *
     * @param array<string, mixed>|null $theme        дані активної теми (з `detectWordPressTheme`)
     * @param array<string, mixed>|null $parentTheme  дані parent-теми (з `fetchThemeInfo`), якщо є
     * @return array{
     *   version: ?string,        // точна версія, якщо вдалося визначити
     *   version_min: ?string,    // нижня межа версії з усіх доступних сигналів
     *   source: string,          // 'generator' | 'readme' | 'theme_tested' | 'rest_api' | 'twemoji' | 'hidden'
     *   note: ?string            // пояснення для користувача
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

        // 1. meta generator — найточніший сигнал (генерується динамічно).
        $gen = $generator ?? $this->extractMeta($html, 'generator');
        if (is_string($gen) && $gen !== '' && preg_match('~^\s*WordPress\s+([0-9][0-9.]*(?:-[A-Za-z0-9.-]+)?)\s*$~i', $gen, $m)) {
            $result['version'] = $m[1];
            $result['version_min'] = $m[1];
            $result['source'] = 'generator';
            $result['note'] = null;
            return $result;
        }

        // 2. /readme.html — статичний файл ядра, може бути застарілим.
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

        // 3. Header "Tested up to" у style.css.
        // Спочатку дивимось активну тему, потім — parent-тему (бо child-теми
        // часто не мають поля "Tested up to", а реальну версію задає parent).
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

        // 4-5. Нижня межа версії: REST endpoints + twemoji-версія.
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
     * Визначає мінімальну нижню межу версії WordPress за наявністю REST endpoints.
     * Це НЕ точна версія — лише гарантована нижня межа.
     *
     * Маршрути WordPress 7.0+ (`wp-abilities/v1`, `wp-block-editor/v1`) додано, щоб
     * уникнути ситуації, коли сайт на WP 7.x показує застарілу версію через те,
     * що ми знаємо лише про маршрути до 6.6.
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

        // Маппінг "наявний маршрут → мінімальна версія WP".
        // Маршрути WP 7.0+ додано за release notes / dev-блогами.
        $hints = [
            // WP 7.0+ — Abilities API
            '/wp-abilities/v1'                  => '7.0',
            '/wp-abilities/v1/categories'       => '7.0',
            '/wp-abilities/v1/abilities'        => '7.0',
            // WP 7.0+ — Block editor REST namespace (експорт, navigation-fallback)
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

        // Додаткова перевірка за простором імен (namespace)
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
     * Визначає мінімальну нижню межу версії WordPress за версією twemoji,
     * яка завантажується з `wp-includes/js/wp-emoji-release.min.js`.
     *
     * Це НЕ точний сигнал (twemoji може відставати від WP), але корисний як
     * додаткова нижня межа для WP 6.0+, де версія twemoji оновлюється разом
     * з ядром.
     *
     * @return string|null мінімальна версія WP або null, якщо не вдалося визначити
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

        // Маппінг twemoji-версії → мінімальна версія WP.
        // Значення підібрані за офіційними release notes WordPress.
        // Якщо twemoji >= порога, повертаємо відповідну мінімальну версію WP.
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
     * Визначення усіх конструкторів сторінок, які використовуються на сайті.
     *
     * Повертає масив — адже на сайті може одночасно бути і Gutenberg (для постів,
     * віджетів, шапки/футера), і Elementor (для головної), і комбінації інших.
     *
     * Для кожного кандидата перевіряє три рівні сигналів у порядку пріоритету:
     *   1. body class    — найточніший
     *   2. плагін        — підтверджує встановлення
     *   3. сліди в HTML  — найзагальніший (класи блоків, атрибути, коментарі)
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

        // Допоміжна ознака: наявність Gutenberg-блоків у контенті.
        // Шукаємо:
        //   • <!-- wp:... --> HTML-коментарі, які Gutenberg залишає в контенті
        //   • class="...wp-block-..." / class='...wp-block-...' — рендер блоків
        //   • class="...is-layout-..." — нові layout-класи
        //   • class="...wp-elements-..." — Element class names із block.json
        //   • alignwide/alignfull/has-global-padding — типові Gutenberg-класи
        $hasGutenbergBlocks = (bool)preg_match(
            '~(?:<!--\s*wp:|class\s*=\s*["\'][^"\']*\b(?:wp-block-|is-layout-|wp-elements-)|'
            . '\balignwide\b|\balignfull\b|\bhas-global-padding\b)~i',
            $html
        );

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
                'name' => 'Gutenberg (Block Editor)',
                'description' => 'Стандартний блоковий редактор WordPress (з версії 5.0).',
                'site' => 'https://wordpress.org/gutenberg',
                'body_classes' => ['wp-is-using-gutenberg'],
                'plugin_slugs' => ['gutenberg'],
                'signs' => [
                    '<!-- wp:',
                    '<!-- /wp:',
                    'class="wp-block-',
                    'class=\'wp-block-',
                    'class="is-layout-',
                    'class="wp-elements-',
                    'wp-block-library',
                    'is-layout-flow',
                    'is-layout-constrained',
                    'wp-block-',
                    'is-layout-',
                    'wp-elements-',
                    'alignwide',
                    'alignfull',
                    'has-global-padding',
                ],
                // Додаткова умова: визнаємо лише якщо в HTML є бодай один Gutenberg-блок
                // (інакше плагін міг бути просто активований у адмінці без реального контенту).
                'requires_blocks' => true,
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

            // 1. body class — найнадійніший сигнал
            foreach ($builder['body_classes'] as $cls) {
                if ($cls !== '' && str_contains($lowerBody, strtolower($cls))) {
                    $method = 'body_class';
                    break;
                }
            }

            // 2. плагін у списку виявлених
            if ($method === null) {
                foreach ($builder['plugin_slugs'] as $slug) {
                    if (in_array(strtolower($slug), $pluginSlugs, true)) {
                        $method = 'plugin';
                        break;
                    }
                }
            }

            // 3. характерні сліди в HTML
            if ($method === null) {
                foreach ($builder['signs'] as $sign) {
                    if ($sign !== '' && str_contains($lowerHtml, strtolower($sign))) {
                        $method = 'html';
                        break;
                    }
                }
            }

            // Додаткова умова для Gutenberg: наявність плагіна/тіла без блоків
            // не рахуємо — інакше помилково спрацьовуємо на адмінці чи ліниво завантажених сайтах.
            if (!empty($builder['requires_blocks']) && $method === 'plugin' && !$hasGutenbergBlocks) {
                $method = null;
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

        // Fallback: якщо WordPress є, але жоден конструктор не виявлено і не активовано Classic Editor,
        // вважаємо що використовується стандартний Gutenberg (з WP 5.0+ він у ядрі).
        if (empty($detected)) {
            $hasClassic = false;
            foreach (['classic-editor', 'disable-gutenberg', 'disable-block-editor'] as $classicSlug) {
                if (in_array($classicSlug, $pluginSlugs, true)) {
                    $hasClassic = true;
                    break;
                }
            }
            if (!$hasClassic) {
                // Додатково перевіряємо, що HTML взагалі виглядає як WordPress (вже гарантовано, т.к. викликається лише для WP)
                // або що core-блок стилі присутні — але для надійності додаємо дефолтний Gutenberg
                // якщо hasGutenbergBlocks true або навіть якщо ні — для сучасних WP це дефолт.
                if ($hasGutenbergBlocks || stripos($lowerHtml, 'wp-content') !== false) {
                    $detected[] = [
                        'name' => 'Gutenberg (Block Editor)',
                        'description' => 'Стандартний блоковий редактор WordPress (з версії 5.0).',
                        'site' => 'https://wordpress.org/gutenberg',
                        'detection' => $hasGutenbergBlocks ? 'html' : 'core',
                    ];
                }
            }
        }

        return empty($detected) ? null : $detected;
    }

    /**
     * Визначення наявності WooCommerce та підключених модулів оплати/доставки.
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

        // Додаткові ознаки WooCommerce в HTML
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

        // 1. Найнадійніше — body class з WP core (`body_class()`):
        //    коли активна child-тема, WP додає і `wp-theme-XXX` (parent),
        //    і `wp-child-theme-XXX` (active).
        if (preg_match('~wp-child-theme-([a-z0-9_-]+)~i', $bodyClass, $m)) {
            $slug = strtolower($m[1]);
            $candidates[$slug] = ($candidates[$slug] ?? 0) + 200; // максимальний пріоритет
        } elseif (preg_match('~wp-theme-([a-z0-9_-]+)~i', $bodyClass, $m)) {
            $slug = strtolower($m[1]);
            $candidates[$slug] = ($candidates[$slug] ?? 0) + 150;
        }

        // 2. Прямі посилання на /wp-content/themes/SLUG/
        if (preg_match_all('~/wp-content/themes/([^/"\']+)/~i', $html, $matches)) {
            foreach ($matches[1] as $slug) {
                $slug = strtolower(trim($slug));
                if ($slug === '' || str_contains($slug, '..')) {
                    continue;
                }
                $candidates[$slug] = ($candidates[$slug] ?? 0) + 1;
            }
        }

        // 3. Спроба отримати активну тему через /wp-json/ (деякі сайти відкривають)
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
                // "Template:" у header вказує на parent-тему для дочірньої теми
                $parentSlug = strtolower(trim($header['template']));
                if ($parentSlug !== '' && $parentSlug !== $themeSlug) {
                    $info['parent_slug'] = $parentSlug;
                }
            }
        }

        return $info;
    }

    /**
     * Завантажує інформацію про тему (зазвичай parent) за її slug.
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
     * Витягує значення атрибута class з тегу <body>.
     */
    private function extractBodyClass(string $html): string
    {
        if (preg_match('~<body\b[^>]*\bclass\s*=\s*["\']([^"\']+)["\']~i', $html, $m)) {
            return $m[1];
        }
        return '';
    }

    private function detectWordPressPlugins(string $html): array
    {
        $slugs = [];
        if (preg_match_all('~/wp-content/plugins/([^/"\']+)/~i', $html, $matches)) {
            foreach ($matches[1] as $slug) {
                $slug = strtolower(trim($slug));
                if ($slug === '' || str_contains($slug, '..') || str_contains($slug, '?')) {
                    continue;
                }
                $slugs[$slug] = true;
            }
        }

        // Фільтруємо службові/системні плагіни, які не є реальними розширеннями
        $ignore = ['mu-plugins', 'languages', 'wp-content', 'plugin-dir'];
        foreach ($ignore as $bad) {
            unset($slugs[$bad]);
        }

        $plugins = [];
        foreach (array_keys($slugs) as $slug) {
            $plugins[] = $this->resolveWpPlugin($slug);
        }

        // Сортуємо за назвою
        usort($plugins, function ($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });

        return $plugins;
    }

    private function resolveWpPlugin(string $slug): array
    {
        $info = ['slug' => $slug];

        if (isset(self::WP_PLUGIN_NAMES[$slug])) {
            $entry = self::WP_PLUGIN_NAMES[$slug];
            $info['name'] = $entry['name'];
            if (!empty($entry['site'])) {
                $info['site'] = $entry['site'];
            }
            return $info;
        }

        // Спроба прочитати readme.txt плагіна
        $readme = $this->httpGet($this->url . '/wp-content/plugins/' . $slug . '/readme.txt', 4);
        if ($readme && preg_match('~Plugin Name:\s*(.+)~i', $readme, $m)) {
            $info['name'] = trim($m[1]);
            if (preg_match('~Stable tag:\s*(.+)~i', $readme, $v)) {
                $tag = trim($v[1]);
                if ($tag !== '' && is_numeric(str_replace('.', '', $tag))) {
                    $info['version'] = $tag;
                }
            }
            return $info;
        }

        // Спроба прочитати основний PHP-файл плагіна для заголовка
        $candidates = [
            $slug . '.php',
            'plugin.php',
            'index.php',
        ];
        foreach ($candidates as $file) {
            $php = $this->httpGet($this->url . '/wp-content/plugins/' . $slug . '/' . $file, 4);
            if ($php && preg_match('~Plugin Name:\s*(.+)~i', $php, $m)) {
                $info['name'] = trim($m[1]);
                if (preg_match('~Version:\s*(.+)~i', $php, $v)) {
                    $info['version'] = trim($v[1]);
                }
                return $info;
            }
        }

        // Fallback: гарно форматуємо slug
        $info['name'] = ucwords(str_replace(['-', '_'], ' ', $slug));
        return $info;
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
            // Дозволяємо як звичайний формат ("Theme Name: ..."),
            // так і формат WP-коментаря (" * Theme Name: ...")
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
     * Словник відомих плагінів WordPress: slug => [name, site].
     */
    private const WP_PLUGIN_NAMES = [
        'akismet' => ['name' => 'Akismet Anti-Spam', 'site' => 'https://akismet.com'],
        'akismet-anti-spam' => ['name' => 'Akismet Anti-Spam', 'site' => 'https://akismet.com'],
        'contact-form-7' => ['name' => 'Contact Form 7', 'site' => 'https://contactform7.com'],
        'contact-form-7-honeypot' => ['name' => 'Contact Form 7 Honeypot', 'site' => 'https://wordpress.org/plugins/contact-form-7-honeypot'],
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
     * Сигнатури CMS, фреймворків і технологій.
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
                    'signs' => ['/administrator/', '/components/com_', 'Joomla!', '/templates/beez3/', 'com_content'],
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
                    'signs' => ['/skin/frontend/', 'mage/cookies.js', 'magento', 'Mage.Cookies', '/static/frontend/'],
                    'generators' => ['Magento'],
                    'confidence' => 'high',
                    'description' => 'Потужна платформа для електронної комерції.',
                    'site' => 'https://magento.com',
                ],
                '1С-Бітрікс' => [
                    'signs' => ['/bitrix/', 'bx-', 'bitrix24'],
                    'generators' => ['Bitrix', '1С-Битрикс'],
                    'confidence' => 'high',
                    'description' => 'Популярна українська/російська CMS.',
                    'site' => 'https://www.1c-bitrix.ru',
                ],
                'MODX' => [
                    'signs' => ['/assets/components/', 'modx', 'MODX'],
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
                    'signs' => ['squarespace.com', 'sqsp', 'squarespace-cdn'],
                    'generators' => ['Squarespace'],
                    'confidence' => 'high',
                    'description' => 'Конструктор сайтів із шаблонами.',
                    'site' => 'https://www.squarespace.com',
                ],
                'Ghost' => [
                    'signs' => ['ghost.io', 'ghost.min.js', 'ghost-script', 'content-api'],
                    'generators' => ['Ghost'],
                    'confidence' => 'high',
                    'description' => 'Платформа для блогів та публікацій.',
                    'site' => 'https://ghost.org',
                ],
                'phpBB' => [
                    'signs' => ['phpBB', '/styles/prosilver/'],
                    'generators' => ['phpBB'],
                    'confidence' => 'high',
                    'description' => 'Форумний двигун на PHP.',
                    'site' => 'https://www.phpbb.com',
                ],
                'vBulletin' => [
                    'signs' => ['vbulletin', 'vbulletin.css'],
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
                    'signs' => ['csrf-token', 'laravel', 'X-CSRF-TOKEN', 'laravel_session'],
                    'headers' => ['Set-Cookie: laravel_session'],
                    'description' => 'Популярний PHP-фреймворк з елегантним синтаксисом.',
                    'site' => 'https://laravel.com',
                ],
                'Symfony' => [
                    'type' => 'PHP-фреймворк',
                    'signs' => ['symfony', '_sf2_', '/bundles/'],
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
                    'signs' => [
                        'vue.global.js',
                        'vue.runtime.global.js',
                        'vue.esm-browser.js',
                        'vue.esm-bundler.js',
                        'v-cloak',
                        '__vue_app__',
                        '__vue_component__',
                        'data-v-',
                        'createapp(',
                    ],
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
                    'signs' => ['x-powered-by: express'],
                    'headers' => ['X-Powered-By: Express'],
                    'description' => 'Мінімалістичний Node.js-фреймворк.',
                    'site' => 'https://expressjs.com',
                ],
                'Django' => [
                    'type' => 'Python-фреймворк',
                    'signs' => ['csrfmiddlewaretoken', 'django', 'csrf_token'],
                    'description' => 'Python-фреймворк для швидкої розробки.',
                    'site' => 'https://www.djangoproject.com',
                ],
                'Flask' => [
                    'type' => 'Python-фреймворк',
                    'signs' => ['flask'],
                    'description' => 'Мікрофреймворк для Python.',
                    'site' => 'https://flask.palletsprojects.com',
                ],
                'ASP.NET' => [
                    'type' => '.NET-фреймворк',
                    'signs' => ['asp.net', '__viewstate', 'aspx'],
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
