<?php

declare(strict_types=1);

namespace App;

/**
 * Простий файловий кеш для результатів аналізу сайтів.
 * Кожен домен зберігається у окремому JSON-файлі в директорії кешу.
 * Ключ — SHA-256 хеш від нормалізованого домену (без www, без scheme, без шляху).
 *
 * Використовується, щоб зменшити навантаження на сторонні API (ip-api.com,
 * who-dat.as93.net) та прискорити повторні запити для тих самих доменів.
 */
final class Cache
{
    /** @var int TTL за замовчуванням — 24 години. */
    public const DEFAULT_TTL = 86400;

    /**
     * Версія формату кешу. Інкрементується при несумісних змінах
     * структури даних — старі записи будуть автоматично відкинуті.
     *
     * - 6: розширено дані WordPress (`version_min`, `version_source`, `version_note`)
     *      у `sections.wordpress`. Старі записи з лише `version` вважаються
     *      неповними і перезаписуються.
     * - 7: додано секцію `sections.php` з параметрами PHP-середовища
     *      (версія, SAPI, конфіг, ліміти, OPcache, cURL, розширення).
     *      Старі записи без цієї секції вважаються неповними і перезаписуються.
     * - 8: секцію `sections.php` переведено на дистанційну перевірку
     *      віддаленого сайту (раніше показувала локальний phpinfo сервісу).
     *      Формат змінився на `remote/detected/version/...` — старі записи
     *      з `available/core/limits` вважаються застарілими.
     * - 9: додано поле `available` для зворотної сумісності зі старим JS
     *      (v3), щоб не показувало «не виявлено в поточному середовищі»
     *      для коректно виявлених сайтів на зразок certus.com.ua.
     * - 10: PHP-детектор враховує CMS/фреймворки/технології (напр., WordPress
     *       → гарантовано PHP) — інакше сайти, що ховають X-Powered-By,
     *       показували «не виявлено» / «невідомо» замість «виявлено, версія прихована».
     * - 11: виправлено хибне спрацювання phpinfo-проби (kyiv-service.com.ua,
     *       laravel.com повертали 404 з випадковим словом "phpinfo" у тілі
     *       і помилково маркувались як витік) — тепер вимагається HTTP 200
     *       + строгі маркери <title>phpinfo / PHP Version.
     * - 12: прибрано окрему секцію `sections.php` — точна версія PHP
     *       (якщо її розкриває X-Powered-By/Server) тепер показується
     *       безпосередньо в секції `sections.server` (поля `php_version`,
     *       `php_version_source`), без окремого блоку.
     * - 13: розширено детекцію PHP-версії в секції сервера — якщо на
     *       головній заголовок приховано, додатково перевіряються
     *       /wp-login.php, /index.php, /xmlrpc.php (HEAD) та строгий
     *       phpinfo-пробник; додано підтримку X-PHP-Version / Server з PHP.
     * - 14: додано секцію `sections.db` — дистанційне визначення СУБД
     *       (MySQL/MariaDB/PostgreSQL/SQLite/Progress/MSSQL/Oracle) та її
     *       версії за phpinfo / заголовками / витоком SQL-помилок / CMS-інференсом;
     *       прибрано застарілу `sections.php`.
     * - 15: додано `sections.wordpress.login_url` — визначення адреси входу
     *       в адмін-панель WordPress (`/wp-login.php` / `/wp-admin/` або
     *       кастомна, якщо вдалося виявити; інакше — помітка «приховано»).
     * - 16: оптимізовано структуру секцій — прибрано окремі `sections.site`,
     *       `sections.technologies`, `sections.wordpress` (тепер всередині
     *       `sections.cms[].wordpress`), `sections.cdn` та `sections.db`
     *       (тепер всередині `sections.server`: cdn_provider/dbms/…),
     *       додано Node.js/Python у `sections.server`; секція Веб-сервер
     *       тепер єдина на всю ширину з 6 рядками (веб-сервер, Node.js, PHP,
     *       Python, CDN, база даних).
     * - 17: виправлено детекцію Gutenberg/Elementor — розширено HTML-сигнали
     *       Gutenberg (`wp-block-library`, `is-layout-flow`, `alignwide` тощо),
     *       додано fallback Gutenberg для WordPress без Classic Editor та
     *       резервне визначення WordPress через /wp-json/ коли HTML — антибот-заглушка.
     * - 18: виправлено WHOIS для делегованих зон .ua (lviv.ua, тощо) — додано
     *       fallback через TCP WHOIS (whois.ua → whois.uar.net) коли RDAP
     *       hostmaster.ua повертає 501/502 (cityhouse.lviv.ua).
     * - 19: прибрано примітку про CMS у секції БД («Сайт працює на CMS…») на прохання замовника.
     * - 20: точність CMS/фреймворків у стилі Wappalyzer — зважені strong/weak-сигнали,
     *       точний матчинг (межі слів, очищення base64-шуму), взаємовиключення CMS;
     *       виправлено хибні MODX/Squarespace/ASP.NET на WordPress-сайтах (equides.com.ua).
     * - 21: WP-плагіни як у Wappalyzer — версія з ?ver= asset-URL без зайвих запитів,
     *       фільтр спільної ?ver= ядра WP, строгі readme/PHP-заголовки, +20 slug'ів у словнику
     *       (WPML, Slider Revolution, SiteGround Optimizer тощо); веб-сервер — розбір
     *       складених Server-заголовків (Apache/2.4.52 (Ubuntu)), нормалізація назв
     *       (IIS/OpenResty), лише заголовки фінальної відповіді, захоплення Via/X-Server.
     * - 22: маркери плагінів без asset'ів (Rank Math за коментарями), +1 сабпейдж
     *       (сторінка запису через REST) для плагінів форм коментарів (Kama SpamBlock).
     * - 23: версії marker-плагінів — readme.txt Stable tag для словникових slug'ів,
     *       Yoast-версія з HTML-коментаря, AIOSEO-версія з meta generator,
     *       мапа uploads-директорій (pum → popup-maker).
     * - 24: серверна секція — HTTP-протокол (h1/h2/h3), вторинні токени Server
     *       (OpenSSL/…), PHP-інференс (PHPSESSID/CMS), показ Via/X-Server.
     * - 25: деталі Joomla в картці CMS (sections.cms[].joomla) — версія ядра
     *       (generator/manifest/language-xml), шаблон (templateDetails.xml),
     *       розширення (компоненти/модулі/плагіни/маркери коментарів), адмінка.
     * - 26: деталі Drupal в картці CMS (sections.cms[].drupal) — версія
     *       (CHANGELOG/generator/X-Generator), тема (.info.yml), модулі за
     *       asset-шляхами (ядро відфільтровано), вхід /user/login.
     */
    public const SCHEMA_VERSION = 26;

    private string $dir;
    private int $ttl;

    /**
     * @param string|null $dir директорія кешу (за замовчуванням — ./cache поряд із проєктом)
     * @param int         $ttl час життя запису в секундах
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
     * Повертає закешовані дані для домену або null, якщо їх немає / вони прострочені.
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
            // Пошкоджений файл — прибираємо
            @unlink($file);
            return null;
        }

        // Перевірка версії сховища: якщо записано в старішому форматі — ігноруємо
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
     * Зберігає дані для домену. Повертає true у разі успіху.
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
     * Видаляє запис для конкретного домену.
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
     * Очищає увесь кеш. Повертає кількість видалених файлів.
     */
    public function clear(): int
    {
        return $this->cleanExpired(true);
    }

    /**
     * Видаляє лише прострочені записи. Повертає кількість видалених файлів.
     * Якщо $force = true — видаляє взагалі все (еквівалент clear()).
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
     * Повертає кількість записів у кеші.
     */
    public function count(): int
    {
        return count(glob($this->dir . '/*.json') ?: []);
    }

    /**
     * Перевіряє, чи є запис для домену (без урахування TTL — для діагностики).
     */
    public function has(string $domain): bool
    {
        $file = $this->fileFor($domain);
        return is_file($file);
    }

    /**
     * Повертає шлях до файлу для домену. Публічний для тестування/дебагу.
     */
    public function fileFor(string $domain): string
    {
        return $this->dir . '/' . $this->hashDomain($domain) . '.json';
    }

    /**
     * Гарантує існування директорії кешу.
     */
    private function ensureDir(): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0755, true);
        }
    }

    /**
     * Нормалізує домен та обчислює SHA-256 хеш для використання як ім'я файлу.
     */
    private function hashDomain(string $domain): string
    {
        $key = strtolower(trim($domain));
        $key = preg_replace('#^https?://#i', '', $key) ?? $key;
        $key = preg_replace('#^www\.#i', '', $key) ?? $key;
        // Відрізаємо шлях, порт, query тощо
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
