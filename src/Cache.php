<?php

declare(strict_types=1);

namespace App;

/**
 * Simple file cache for site analysis results.
 * Each domain is stored in a separate JSON file in the cache directory.
 * The key is a SHA-256 hash of the normalized domain (no www, no scheme, no path).
 *
 * Used to reduce load on third-party APIs (ip-api.com,
 * who-dat.as93.net) and to speed up repeat requests for the same domains.
 */
final class Cache
{
    /** @var int Default TTL — 24 hours. */
    public const DEFAULT_TTL = 86400;

    /**
     * Cache format version. Incremented on incompatible changes
     * to the data structure — old entries are automatically discarded.
     *
     * - 6: extended WordPress data (`version_min`, `version_source`, `version_note`)
     *      in `sections.wordpress`. Old entries with only `version` are considered
     *      incomplete and overwritten.
     * - 7: added `sections.php` with PHP environment parameters
     *      (version, SAPI, config, limits, OPcache, cURL, extensions).
     *      Old entries without this section are considered incomplete and overwritten.
     * - 8: `sections.php` switched to remote checking of the
     *      remote site (previously showed the service's local phpinfo).
     *      Format changed to `remote/detected/version/...` — old entries
     *      with `available/core/limits` are considered outdated.
     * - 9: added `available` field for backward compatibility with old JS
     *      (v3), so it no longer shows "not detected in current environment"
     *      for correctly detected sites like certus.com.ua.
     * - 10: PHP detector accounts for CMS/frameworks/technologies (e.g. WordPress
     *       → guaranteed PHP) — otherwise sites hiding X-Powered-By
     *       showed "not detected" / "unknown" instead of "detected, version hidden".
     * - 11: fixed phpinfo-probe false positive (kyiv-service.com.ua,
     *       laravel.com returned 404 with a random "phpinfo" word in the body
     *       and were wrongly marked as a leak) — now requires HTTP 200
     *       + strict <title>phpinfo / PHP Version markers.
     * - 12: removed the separate `sections.php` section — the exact PHP version
     *       (if exposed via X-Powered-By/Server) is now shown
     *       directly in the `sections.server` section (`php_version`,
     *       `php_version_source` fields), without a separate block.
     * - 13: extended PHP-version detection in the server section — if the
     *       homepage header is hidden, additionally checked are
     *       /wp-login.php, /index.php, /xmlrpc.php (HEAD) plus a strict
     *       phpinfo probe; added support for X-PHP-Version / Server with PHP.
     * - 14: added `sections.db` section — remote DBMS detection
     *       (MySQL/MariaDB/PostgreSQL/SQLite/Progress/MSSQL/Oracle) and its
     *       version via phpinfo / headers / SQL-error leaks / CMS inference;
     *       removed the legacy `sections.php`.
     * - 15: added `sections.wordpress.login_url` — WordPress admin login
     *       address detection (`/wp-login.php` / `/wp-admin/` or a
     *       custom one if detected; otherwise marked as "hidden").
     * - 16: streamlined section structure — removed separate `sections.site`,
     *       `sections.technologies`, `sections.wordpress` (now inside
     *       `sections.cms[].wordpress`), `sections.cdn` and `sections.db`
     *       (now inside `sections.server`: cdn_provider/dbms/…),
     *       added Node.js/Python to `sections.server`; the Web Server section
     *       is now a single full-width card with 6 rows (web server, Node.js, PHP,
     *       Python, CDN, database).
     * - 17: fixed Gutenberg/Elementor detection — extended HTML signals for
     *       Gutenberg (`wp-block-library`, `is-layout-flow`, `alignwide`, etc.),
     *       added Gutenberg fallback for WordPress without Classic Editor and
     *       WordPress fallback detection via /wp-json/ when HTML is an antibot stub.
     * - 18: fixed WHOIS for delegated .ua zones (lviv.ua, etc.) — added
     *       fallback via TCP WHOIS (whois.ua → whois.uar.net) when RDAP at
     *       hostmaster.ua returns 501/502 (cityhouse.lviv.ua).
     * - 19: removed the CMS note in the DB section ("Site runs on CMS…") at the customer's request.
     * - 20: Wappalyzer-style CMS/framework accuracy — weighted strong/weak signals,
     *       exact matching (word boundaries, base64-noise cleanup), mutually exclusive CMS;
     *       fixed false MODX/Squarespace/ASP.NET on WordPress sites (equides.com.ua).
     * - 21: WP plugins like in Wappalyzer — version from ?ver= asset URLs without extra requests,
     *       shared WP-core ?ver= filter, strict readme/PHP headers, +20 slugs in the dictionary
     *       (WPML, Slider Revolution, SiteGround Optimizer, etc.); web server — parsing
     *       compound Server headers (Apache/2.4.52 (Ubuntu)), name normalization
     *       (IIS/OpenResty), only final-response headers, Via/X-Server capture.
     * - 22: plugin markers without assets (Rank Math via comments), +1 subpage
     *       (post page via REST) for comment-form plugins (Kama SpamBlock).
     * - 23: marker-plugin versions — readme.txt Stable tag for dictionary slugs,
     *       Yoast version from HTML comment, AIOSEO version from meta generator,
     *       uploads-directory map (pum → popup-maker).
     * - 24: server section — HTTP protocol (h1/h2/h3), secondary Server tokens
     *       (OpenSSL/…), PHP inference (PHPSESSID/CMS), Via/X-Server display.
     * - 25: Joomla details in the CMS card (sections.cms[].joomla) — core version
     *       (generator/manifest/language-xml), template (templateDetails.xml),
     *       extensions (components/modules/plugins/comment markers), admin panel.
     * - 26: Drupal details in the CMS card (sections.cms[].drupal) — version
     *       (CHANGELOG/generator/X-Generator), theme (.info.yml), modules by
     *       asset paths (core filtered out), /user/login entry.
     * - 27: added `sections.pagespeed` section — Google PageSpeed
     *       Insights scores (Lighthouse mobile: performance/accessibility/
     *       best-practices/seo scores + FCP/LCP/TBT/CLS/SI/TTI metrics + CrUX field).
     * - 28: `sections.pagespeed` — two strategies side by side (`mobile` + `desktop`,
     *       parallel requests via curl_multi), structure
     *       `{tested_url, fetch_time, mobile:{...}, desktop:{...}, key_fallback}`.
     * - 29: removed Gutenberg (Block Editor) from `page_builders` — it is in WP core
     *       by default and added noise next to Elementor.
     */
    public const SCHEMA_VERSION = 29;

    private string $dir;
    private int $ttl;

    /**
     * @param string|null $dir cache directory (default — ./cache next to the project)
     * @param int         $ttl entry lifetime in seconds
     */
    public function __construct(?string $dir = null, int $ttl = self::DEFAULT_TTL)
    {
        $this->dir = $dir ?? (__DIR__ . '/../cache');
        $this->ttl = max(0, $ttl);
        $this->ensureDir();
    }

    public function getTtl(): int
    {
        return $this->ttl;
    }

    public function getDir(): string
    {
        return $this->dir;
    }

    /**
     * Returns cached data for a domain, or null if missing / expired.
     *
     * @return array<string, mixed>|null
     */
    public function get(string $domain): ?array
    {
        if ($domain === '') {
            return null;
        }

        $file = $this->fileFor($domain);
        if (!is_file($file)) {
            return null;
        }

        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') {
            return null;
        }

        $entry = json_decode($raw, true);
        if (!is_array($entry) || !isset($entry['cached_at'], $entry['data']) || !is_array($entry['data'])) {
            // Corrupted file — remove it
            @unlink($file);
            return null;
        }

        // Storage version check: ignore entries written in an older format
        $entryVersion = isset($entry['schema_version']) ? (int)$entry['schema_version'] : 1;
        if ($entryVersion < self::SCHEMA_VERSION) {
            @unlink($file);
            return null;
        }

        if ($this->ttl > 0 && (time() - (int)$entry['cached_at']) > $this->ttl) {
            @unlink($file);
            return null;
        }

        return $entry['data'];
    }

    /**
     * Stores data for a domain. Returns true on success.
     *
     * @param array<string, mixed> $data
     */
    public function set(string $domain, array $data): bool
    {
        if ($domain === '') {
            return false;
        }
        $this->ensureDir();

        $entry = [
            'domain' => strtolower(trim($domain)),
            'cached_at' => time(),
            'schema_version' => self::SCHEMA_VERSION,
            'data' => $data,
        ];

        $json = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return false;
        }

        $file = $this->fileFor($domain);
        $bytes = @file_put_contents($file, $json, LOCK_EX);
        return $bytes !== false;
    }

    /**
     * Deletes the record for a specific domain.
     */
    public function delete(string $domain): bool
    {
        if ($domain === '') {
            return false;
        }
        $file = $this->fileFor($domain);
        if (!is_file($file)) {
            return true;
        }
        return @unlink($file);
    }

    /**
     * Clears the entire cache. Returns the number of deleted files.
     */
    public function clear(): int
    {
        return $this->cleanExpired(true);
    }

    /**
     * Deletes only expired records. Returns the number of deleted files.
     * If $force = true — deletes everything (equivalent to clear()).
     */
    public function cleanExpired(bool $force = false): int
    {
        $files = glob($this->dir . '/*.json') ?: [];
        $now = time();
        $count = 0;
        foreach ($files as $file) {
            if ($force) {
                if (@unlink($file)) {
                    $count++;
                }
                continue;
            }
            $raw = @file_get_contents($file);
            if ($raw === false) {
                continue;
            }
            $entry = json_decode($raw, true);
            if (!is_array($entry) || !isset($entry['cached_at'])) {
                if (@unlink($file)) {
                    $count++;
                }
                continue;
            }
            if (($now - (int)$entry['cached_at']) > $this->ttl) {
                if (@unlink($file)) {
                    $count++;
                }
            }
        }
        return $count;
    }

    /**
     * Returns the number of cache entries.
     */
    public function count(): int
    {
        return count(glob($this->dir . '/*.json') ?: []);
    }

    /**
     * Checks whether a record exists for a domain (ignoring TTL — for diagnostics).
     */
    public function has(string $domain): bool
    {
        $file = $this->fileFor($domain);
        return is_file($file);
    }

    /**
     * Returns the file path for a domain. Public for testing/debugging.
     */
    public function fileFor(string $domain): string
    {
        return $this->dir . '/' . $this->hashDomain($domain) . '.json';
    }

    /**
     * Ensures the cache directory exists.
     */
    private function ensureDir(): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0755, true);
        }
    }

    /**
     * Normalizes a domain and computes a SHA-256 hash for use as a file name.
     */
    private function hashDomain(string $domain): string
    {
        $key = strtolower(trim($domain));
        $key = preg_replace('#^https?://#i', '', $key) ?? $key;
        $key = preg_replace('#^www\.#i', '', $key) ?? $key;
        // Strip path, port, query, etc.
        $slash = strpos($key, '/');
        if ($slash !== false) {
            $key = substr($key, 0, $slash);
        }
        $colon = strpos($key, ':');
        if ($colon !== false) {
            $key = substr($key, 0, $colon);
        }
        if ($key === '') {
            $key = $domain; // fallback
        }
        return hash('sha256', $key);
    }
}
