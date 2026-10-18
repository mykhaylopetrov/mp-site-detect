<?php

declare(strict_types=1);

namespace App;

final class SpamProtection
{
    public const TOKEN_TTL_MIN = 2;
    public const TOKEN_TTL_MAX = 7200;

    public const RATE_LIMIT_WINDOW = 600;
    public const RATE_LIMIT_MAX = 30;
    public const RATE_LIMIT_BAN = 600;

    private const RATE_PREFIX = 'rate_';
    private const BANNED_PREFIX = 'banned_';
    private const SECRET_FILE = '.secret';

    private string $secret;
    private string $storageDir;

    public function __construct(?string $storageDir = null)
    {
        $this->storageDir = rtrim($storageDir ?? (__DIR__ . '/../cache/security'), '/\\');
        $this->ensureDir();
        $this->secret = $this->loadOrCreateSecret();
    }

    public function generateToken(): string
    {
        $ts = time();
        $nonce = bin2hex(random_bytes(16));
        $sig = hash_hmac('sha256', $nonce . '|' . $ts, $this->secret);
        return $nonce . '.' . $ts . '.' . $sig;
    }

    public function validateToken(?string $token): bool
    {
        if (!is_string($token) || $token === '') {
            return false;
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }
        [$nonce, $ts, $sig] = $parts;
        if (!is_string($nonce) || !ctype_xdigit($nonce) || strlen($nonce) !== 32) {
            return false;
        }
        if (!is_string($ts) || !ctype_digit($ts)) {
            return false;
        }
        if (!is_string($sig) || !ctype_xdigit($sig) || strlen($sig) !== 64) {
            return false;
        }
        $expected = hash_hmac('sha256', $nonce . '|' . $ts, $this->secret);
        if (!hash_equals($expected, $sig)) {
            return false;
        }
        $tsInt = (int)$ts;
        $age = time() - $tsInt;
        if ($age < self::TOKEN_TTL_MIN || $age > self::TOKEN_TTL_MAX) {
            return false;
        }
        return true;
    }

    public function isValidHoneypot(?string $value): bool
    {
        if ($value === null) {
            return true;
        }
        return trim($value) === '';
    }

    public function isJavaScriptMarker(?string $marker): bool
    {
        return is_string($marker)
            && strlen($marker) >= 16
            && strlen($marker) <= 128
            && ctype_xdigit($marker);
    }

    public function checkRateLimit(string $ip): array
    {
        if ($ip === '') {
            return ['allowed' => true, 'remaining' => self::RATE_LIMIT_MAX];
        }

        $key = hash('sha256', $ip);
        $banFile = $this->storageDir . '/' . self::BANNED_PREFIX . $key . '.json';
        $now = time();

        if (is_file($banFile)) {
            $raw = @file_get_contents($banFile);
            if ($raw !== false && $raw !== '') {
                $entry = json_decode($raw, true);
                if (is_array($entry) && isset($entry['until']) && (int)$entry['until'] > $now) {
                    return [
                        'allowed' => false,
                        'retry_after' => (int)$entry['until'] - $now,
                        'remaining' => 0,
                    ];
                }
            }
            @unlink($banFile);
        }

        $rateFile = $this->storageDir . '/' . self::RATE_PREFIX . $key . '.json';
        $hits = [];
        if (is_file($rateFile)) {
            $raw = @file_get_contents($rateFile);
            if ($raw !== false && $raw !== '') {
                $parsed = json_decode($raw, true);
                if (is_array($parsed) && isset($parsed['hits']) && is_array($parsed['hits'])) {
                    $hits = array_values(array_filter(
                        $parsed['hits'],
                        static fn($h) => is_int($h) && ($now - $h) < self::RATE_LIMIT_WINDOW
                    ));
                }
            }
        }

        $hits[] = $now;
        $count = count($hits);
        $allowed = $count <= self::RATE_LIMIT_MAX;

        if (!$allowed) {
            @file_put_contents(
                $banFile,
                json_encode(['until' => $now + self::RATE_LIMIT_BAN], JSON_UNESCAPED_UNICODE),
                LOCK_EX
            );
        } else {
            @file_put_contents(
                $rateFile,
                json_encode(['hits' => $hits], JSON_UNESCAPED_UNICODE),
                LOCK_EX
            );
        }

        return [
            'allowed' => $allowed,
            'remaining' => max(0, self::RATE_LIMIT_MAX - $count),
            'retry_after' => $allowed ? 0 : self::RATE_LIMIT_BAN,
        ];
    }

    public function resetRateLimit(string $ip): void
    {
        if ($ip === '') {
            return;
        }
        $key = hash('sha256', $ip);
        @unlink($this->storageDir . '/' . self::RATE_PREFIX . $key . '.json');
        @unlink($this->storageDir . '/' . self::BANNED_PREFIX . $key . '.json');
    }

    public function guard(array $input): array
    {
        $token = $input['csrf_token'] ?? null;
        $honeypot = $input['hp'] ?? $input['website_url'] ?? null;
        $jsMarker = $input['js'] ?? $input['js_token'] ?? null;
        $formLoadedAt = isset($input['ts']) ? (int)$input['ts'] : 0;

        if (!$this->isValidHoneypot($honeypot)) {
            return [
                'ok' => false,
                'reason' => 'honeypot',
                'http_status' => 400,
                'error' => 'Запит відхилено системою захисту від ботів.',
            ];
        }

        if (!$this->isJavaScriptMarker($jsMarker)) {
            return [
                'ok' => false,
                'reason' => 'js_marker',
                'http_status' => 400,
                'error' => 'Увімкніть JavaScript у браузері для перевірки сайтів.',
            ];
        }

        if (!$this->validateToken(is_string($token) ? $token : null)) {
            return [
                'ok' => false,
                'reason' => 'token',
                'http_status' => 403,
                'error' => 'Захищений токен форми невалідний. Оновіть сторінку та спробуйте ще раз.',
            ];
        }

        if ($formLoadedAt > 0) {
            $nowMs = (int)(microtime(true) * 1000);
            $elapsedMs = $nowMs - $formLoadedAt;
            if ($elapsedMs >= 0 && $elapsedMs < 1500) {
                return [
                    'ok' => false,
                    'reason' => 'timing',
                    'http_status' => 429,
                    'error' => 'Запит надіслано занадто швидко. Зачекайте кілька секунд.',
                ];
            }
        }

        $ip = $this->getClientIp();
        $rl = $this->checkRateLimit($ip);
        if (!$rl['allowed']) {
            $retry = max(1, (int)($rl['retry_after'] ?? self::RATE_LIMIT_BAN));
            return [
                'ok' => false,
                'reason' => 'rate_limit',
                'http_status' => 429,
                'retry_after' => $retry,
                'error' => 'Забагато запитів з вашої адреси. Спробуйте пізніше (через 10 хв).',
            ];
        }

        return [
            'ok' => true,
            'rate_remaining' => (int)($rl['remaining'] ?? 0),
        ];
    }

    public function getClientIp(): string
    {
        return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    }

    public function getStorageDir(): string
    {
        return $this->storageDir;
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0755, true);
        }
        $htaccess = $this->storageDir . '/.htaccess';
        if (!is_file($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\n");
        }
    }

    private function loadOrCreateSecret(): string
    {
        $file = $this->storageDir . '/' . self::SECRET_FILE;
        if (is_file($file)) {
            $secret = trim((string)@file_get_contents($file));
            if (strlen($secret) >= 32) {
                return $secret;
            }
        }
        $secret = bin2hex(random_bytes(32));
        @file_put_contents($file, $secret);
        @chmod($file, 0600);
        return $secret;
    }
}
