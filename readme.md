# MP Site Detect

Web service for website analysis: detects the IP address, location, hosting provider,
domain WHOIS data, the CMS in use (with WordPress details inside), frameworks,
a unified Web Server section (server, Node.js, PHP, Python, CDN, database)
and Google PageSpeed Insights scores (Lighthouse mobile + desktop).

## Stack

- **Backend**: PHP 8+ (no external dependencies)
- **Frontend**: vanilla JavaScript + jsPDF (CDN) for PDF export
- **Styles**: CSS with BEM methodology
- **Transport**: SSE (Server-Sent Events) for streaming results
- **HTTP**: cURL for reliable header capture (Server, X-Powered-By, CF-RAY, etc.)
- **Cache**: file-based (no DB), 24 hours by default, with schema versioning

## Features

1. 🌐 **IP and location** — country, region, city, coordinates, timezone
2. 🏢 **Hosting provider** — ISP, organization, autonomous system (AS)
3. 📋 **WHOIS** — registrar, creation/update/expiration dates, DNS servers
4. ⚙️ **CMS** — WordPress, Joomla, Drupal, OpenCart, PrestaShop, Magento, 1C-Bitrix, and others. If **WordPress**, its version, theme, parent theme, page builders, WooCommerce, and plugins are shown **directly inside the CMS card** next to the CMS name (there is no separate WordPress section)
5. 🧩 **Frameworks** — Laravel, Symfony, Yii, React, Vue, Angular, Next.js, Nuxt.js, Django, ASP.NET
6. 🖥️ **Web server (single full-width section)** — briefly 6 lines:
   - web server (name, version — from `Server` / `X-Powered-By`);
   - Node.js (if present — version from `X-Powered-By: Express` / `Server: Node.js`);
   - PHP (if present — exact version from `X-Powered-By` / `Server` / `phpinfo`);
   - Python (if present — version from `Server: gunicorn/uvicorn` / `X-Powered-By: Python` or inference from Django/Flask);
   - CDN (if present — provider name: Cloudflare, Amazon CloudFront, Fastly, Akamai, QUIC.cloud, BunnyCDN, KeyCDN, Sucuri, StackPath, Imperva, Varnish);
   - database (DBMS name — MySQL / MariaDB / PostgreSQL / SQLite / Progress / MSSQL / Oracle — and version, if the site discloses it exactly via an open `phpinfo`, `X-DB-*` headers, or an SQL-error leak).
7. ⚡ **PageSpeed** — exclusively Google PageSpeed Insights scores (Lighthouse): two strategies side by side — **Mobile** and **Desktop** — for easy comparison: Performance / Accessibility / Best Practices / SEO scores (0–100) and FCP, LCP, TBT, CLS, Speed Index, TTI metrics + CrUX field data (if available).
8. 📡 **Streaming results** — each module appears as soon as it is ready
9. 💾 **Local cache** — repeat requests for the same domain are instant, with no load
   on third-party APIs and WHOIS servers
10. 🛡️ **Spam and bot protection** — multi-layer filter with no external dependencies
    (CSRF tokens, honeypot field, JS marker, interaction-time check, rate limit)

> The **"Site overview"** (title/description/generator) and **"Technologies & libraries"** (jQuery, Bootstrap, etc.) sections were removed to reduce noise. The **"CDN"** and **"Database"** sections were also removed as separate cards — their data is now part of the single **Web Server** section.

Results can be downloaded as PDF with one click.

## Joomla detector capabilities (inside CMS)

When the Joomla CMS is found on a site, the following is shown directly in the **Content Management System (CMS)** card
under the Joomla block (`sections.cms[].joomla`):

- **Core version** — by priority: `generator` meta tag
  (`Joomla! … Version X.Y.Z`) → `/administrator/manifests/files/joomla.xml`
  (`<version>`) → `/language/en-GB/en-GB.xml` (core language-pack `<version>`).
- **Active template** — most frequent slug in `/templates/SLUG/` (+ `templateDetails.xml`:
  name, version, author; the service `system` is ignored).
- **Extensions** — third-party components (`option=com_X`, excluding core), modules
  (`/modules/mod_X`, `/media/mod_X`), plugins (`/plugins/GROUP/NAME`) and markers
  in comments (Modules Anywhere, Sourcerer, Unite Gallery with version, Joomlatools,
  Akeeba, Gantry, T3…).
- **Admin panel** — `/administrator/` probe: standard address with a login form
  (`com_login` + `passwd`) or a "hidden" badge.

## Drupal detector capabilities (inside CMS)

When the Drupal CMS is found on a site, the following is shown directly in the **Content Management System (CMS)** card
under the Drupal block (`sections.cms[].drupal`):

- **Core version** — by priority: `/core/CHANGELOG.txt` (exact, if the file
  is open and contains a `Drupal X.Y.Z` line) → `Generator` meta tag / `X-Generator`
  header (`Drupal 10` — major branch only, with a corresponding note).
- **Active theme** — most frequent slug in `/sites/…/themes/SLUG/` and `/themes/…/SLUG/`
  (+ `.info.yml` at the observed path: name, version, description; usually 403).
- **Modules** — third-party ones by asset paths (`/sites/…/modules[/contrib]/SLUG/`,
  `/modules[/contrib]/SLUG/`); core modules are filtered out, RDF namespaces
  (`purl.org/…/modules/content/`) are excluded by quote context.
- **Login** — `/user/login` probe: standard form (`user-login-form` / `action="/user/login"`
  + password field) or a "hidden" badge.

## WordPress detector capabilities (inside CMS)

When the WordPress CMS is found on a site, the following is shown directly in the **Content Management System (CMS)** card under the WordPress block:

- **WordPress version** — from reliable sources in this order (returned
  as **structured info**: `version` / `version_min` / `version_source` / `version_note`):
  1. `<meta name="generator" content="WordPress X.Y.Z">` — the most accurate signal,
     generated dynamically on each request (but may be hidden by a security
     plugin). If found — this is the **exact** version.
  2. `/readme.html` — a static core file, parsed as `<p style="text-align: center"><strong>Version X.Y.Z</strong></p>`
     (handles the format with the `<strong>` wrapper). If found — the **exact** version,
     although the file may be outdated.
  3. The `Tested up to: X.Y` header in the `style.css` of the active (or parent) theme — the theme
     author updates this field after testing against a new WP version. Usually it
     matches the actual version or lags by one minor release. If
     found — treated as the **exact** version, but the source is labeled.
  4. REST API `/wp-json/` — a **lower bound** on the version based on the presence of endpoints and namespaces:
      `/wp/v2/icons` (≥ 6.6), `/wp/v2/font-collections` (≥ 6.5),
      `/wp/v2/block-patterns/categories` (≥ 6.0), `/wp/v2/block-patterns/patterns` (≥ 5.9),
      `/wp/v2/block-directory/search` (≥ 5.5), `/wp/v2/blocks` (≥ 5.0),
      `/wp/v2/settings` (≥ 4.7),
      `/wp-abilities/v1` (≥ 7.0), `/wp-block-editor/v1` (≥ 7.0), etc.
  5. Twemoji version from `/wp-includes/js/wp-emoji-release.min.js` — an additional
     lower bound for WP 6.0+.
  6. If still nothing — the UI shows a **"Version hidden"** badge with an explanation.

  **How it is displayed in the UI (inside CMS):**
  - exact version (`generator` / `readme` / `theme_tested`) — in a regular badge
    with a source badge ("generator meta tag", "/readme.html file", "theme Tested up to field");
  - lower bound only (`rest_api` / `twemoji`) — in an orange badge with a **"≥"** prefix
    and an explanation that the exact version is hidden;
  - fully hidden — a gray badge reading **"hidden"**.

  ⚠️ The `?ver=` fallback in `/wp-includes/js/` is NOT used: it often contains
  the **jQuery** version (`jquery.min.js?ver=3.7.1`), not WordPress.

- **Active theme** — determined by priority:
  1. The `wp-child-theme-XXX` class in `<body>` (most accurate — this is the active child theme).
  2. The `wp-theme-XXX` class in `<body>` (active or parent).
  3. REST API `/wp-json/` (`themes`, `active_theme`, `stylesheet`).
  4. Most frequent slug in the HTML.
  
  `style.css` is parsed for the `Theme Name`, `Version`, `Author`, `Description`,
  `Theme URI`, `Author URI` fields. Both the `Theme Name: ...` format and
  ` * Theme Name: ...` (WP comment) are supported.

- **Parent theme** — if the active theme's `style.css` has a `Template: parent-slug` header,
  information about the parent theme is additionally loaded (name, version, author).

- **Page builder** — returned as an array of all detected builders
  (a site may have, for example, both Elementor and WPBakery at the same time).
  **Gutenberg (Block Editor) is not included here**: it is the WordPress core default
  and is often present alongside other builders,
  so showing it would only add noise. Signals in priority order:
  1. Class in `<body>` (most accurate).
  2. Plugin presence.
  3. Characteristic traces in HTML (classes, attributes, comments).
  
  Supported:
  - **Elementor** — `elementor-page`, `elementor-default` in body, `elementor` plugin
  - **Divi Builder** — `et_pb_builder`, `et_pb_pagebuilder_layout`
  - **Bricks** — `bricks-is-frontend`, `/wp-content/themes/bricks/` path
  - **Beaver Builder** — `fl-builder`, `beaver-builder-lite-version` plugin
  - **WPBakery (Visual Composer)** — `wpb_row`, `vc_row`, `js_composer` plugin
  - **SiteOrigin Page Builder** — `siteorigin-panels`
  - **Thrive Architect** — `thrive-visual-editor` plugin
  - **Oxygen** — `oxygen` plugin
  - **Avada Live (Fusion Builder)** — `/wp-content/themes/Avada/`
  - **Live Composer** — `dslca-enabled` in body

- **WooCommerce** — plugin presence, version, list of detected payment gateways
  (Stripe, PayPal, Square, Braintree, Mollie, Adyen, Razorpay, Klarna,
  Amazon Pay, Afterpay, WooCommerce Payments, etc.) and shipping modules
  (UPS, FedEx, Australia Post, Canada Post, Shipment Tracking, Table Rate,
  Flexible Shipping, Printful, Printify, etc.). URLs of the
  shop, cart, checkout, and account pages are additionally checked.

- **Admin login URL** (`login_url`) — if WordPress is detected,
  the login page URL is determined:
  1. The standard addresses `/wp-login.php` and `/wp-admin/` are checked (a trial
     request without redirects: `200` with an `id="loginform"` / `name="log"` +
     `name="pwd"` + `wp-submit` form, or `302` with a `Location: …wp-login.php` — if
     present, it is returned as `is_default: true` with the full URL).
  2. If `/wp-admin/` redirects to a custom path (e.g. `/my-login/`)
     — the redirect target is checked with a separate request, and if it contains a login form,
     it is returned as `is_custom: true` (`detection_method: redirect:/wp-admin/ → …`).
  3. Otherwise the HTML is scanned for `<a href="…">` links with the keywords `login` /
     `admin` / `dashboard` (up to 20 candidates) — each candidate is checked
     with a trial request for a login form (`detection_method: html:…`).
  4. If the standard addresses return `404` and there is no working
     login page among the HTML links — `is_hidden: true` is returned with the message:
     > "The default admin login address was changed by the site owner.
     > It is not possible to determine the new address remotely — it is hidden
     > by a security plugin (e.g. WPS Hide Login, iThemes Security, etc.)."

  Structure (`sections.cms[].wordpress.login_url`):

  | Field | Description |
  |------|------|
  | `url` | full URL (`https://example.com/wp-login.php` or custom) or `null` if hidden |
  | `path` | path (`/wp-login.php` / `/my-secret-login/`) or `null` |
  | `is_default` | `true` if this is the standard address |
  | `is_custom` | `true` if a custom one was found (via redirect or an HTML link) |
  | `is_hidden` | `true` if the standard ones do not respond and no custom one could be detected |
  | `status_code` | HTTP code of the check (`200` / `302` / `404`, etc.) |
  | `note` | human-readable explanation |
  | `detection_method` | `probe:/wp-login.php (200)` / `redirect:/wp-admin/ → /my-login/` / `html:/my-login/` |

  In the frontend (inside the CMS card) — the **"Admin panel"** block:
  - standard — green **"standard"** badge + clickable URL;
  - custom — blue **"custom"** badge + clickable URL;
  - hidden — yellow **"hidden"** badge + the message above.

- **Plugins** — HTML scan by `/wp-content/plugins/PLUGIN_NAME/` paths
  (like Wappalyzer), dictionary-based name recognition. The version is determined
  without extra requests — from `?ver=` asset URLs (`version_source: asset-ver`);
  a shared `?ver=` across ≥4 plugins is discarded (it is the default WP core version).
  Next — `readme.txt` (`Stable tag`) and the main PHP file header with strict
  multiline regex (protection against HTML fallbacks); timestamps and md5 hashes as versions
  are filtered out. Dictionary plugins without an asset version get their Stable tag
  from readme.txt; the Yoast version — from the HTML comment, AIOSEO — from the meta generator;
  Popup Maker is caught via `/uploads/pum/`. Plugins without assets on the page are caught by markers
  in comments/attributes (`WP_PLUGIN_HTML_MARKERS`: Rank Math, Yoast, CF7…)
  — search only outside text content, so articles about Elementor do not cause
  false positives. One additional post page is scanned (via REST),
  where comment-form plugins are visible (e.g. Kama SpamBlock). Plugins that leave
  no trace (WPS Hide Login — by design; output only on specific pages)
  cannot be detected remotely.

All this data is stored in `sections.cms[].wordpress` and rendered by the frontend
inside the CMS card, not as a separate card.

## Spam and bot protection

The search form is protected by a **multi-layer filter** (`src/SpamProtection.php`),
which needs no third-party services (no reCAPTCHA / hCaptcha) and works
on plain PHP and JS only:

| Level | What is checked | What it stops |
|--------|------------------|------------|
| 🪤 **Honeypot field** | hidden `website_url` field that must stay empty | dumb bots that fill in every form field |
| 🔐 **CSRF token** | signed HMAC-SHA256 token (`nonce.ts.signature`) valid from 2 s to 2 h | direct POST requests without loading the page first, token reuse |
| 🧠 **JS marker** | random 32-char hex string added to the form by JS only | HTTP clients without JS (curl, scripts, simple scrapers) |
| ⏱ **Interaction time** | difference between page load time (`form_loaded_at`) and submit time | instant automated requests right after receiving the HTML |
| 🚦 **Rate limit** | no more than **30 requests / 10 min** from a single IP address; on excess — a **10 min** ban | brute force, mass scanning, DDoS on slow requests |

### How it works

1. Each load of `index.php` generates a new **CSRF token**
   (`<meta name="csrf-token">` + `<input type="hidden" name="csrf_token">`).
   The token is `random_nonce . timestamp . hmac_sha256(secret, nonce|ts)`.
2. A **honeypot field** `website_url` is added to the form, moved off-screen via CSS
   (`position: absolute; left: -10000px`) with `tabindex="-1"`,
   so real users never see or fill it.
3. On startup, JS fills the hidden `js_token` field with a random 32-char hex string.
   The `form_loaded_at` field is pre-filled on the server with the page render time.
4. On submit, JS appends `csrf_token`, `hp` (honeypot value),
   `js` and `ts` as query params (for SSE) or POST body (for `check.php`).
5. On the server, `SpamProtection::guard($input)` is called before analysis,
   checking in this order: honeypot → JS marker → CSRF token → timing
   → rate limit. The first failure returns `400` / `403` / `429` with a
   localized user-facing message.

### Where service data is stored

All service files are created automatically in `cache/security/`:

- `.secret` — server secret (HMAC) for signing tokens, `0600` permissions.
- `rate_<sha256(ip)>.json` — request counter for the current window.
- `banned_<sha256(ip)>.json` — temporary ban for IPs that exceeded the limit.

The `cache/security/` directory is automatically protected by its own `.htaccess`
(`Require all denied`), and also inherits the ban from the parent
`cache/.htaccess`.

### Default settings

All thresholds are defined as `public const` in the `SpamProtection` class, so they are easy
to tune to your needs:

| Constant | Default | Description |
|-----------|----------|------|
| `TOKEN_TTL_MIN` | `2` s | minimum time from token generation to its use |
| `TOKEN_TTL_MAX` | `7200` s (2 h) | maximum token lifetime |
| `RATE_LIMIT_WINDOW` | `600` s (10 min) | width of the request-counting window |
| `RATE_LIMIT_MAX` | `30` | allowed number of requests per window from one IP |
| `RATE_LIMIT_BAN` | `600` s (10 min) | ban duration when the limit is exceeded |

### User-facing messages

All protection errors are localized and clear:

- `honeypot` → "Request rejected by the bot protection system."
- `js_marker` → "Enable JavaScript in your browser to check websites."
- `token` → "The form security token is invalid. Reload the page and try again."
- `timing` → "The request was sent too quickly. Wait a few seconds."
- `rate_limit` → "Too many requests from your address. Try again later."

In SSE mode the error arrives as a separate `error` event, and the client-side JS
renders it in the standard error block (`status--error`).

## Web Server detector capabilities (single section)

The single **Web Server** card (full width) collects the whole runtime environment.
Web server detection uses the `Server` HTTP header (e.g. `Server: nginx/1.18.0`),
`X-Powered-By`, as well as security headers. The server name is rendered
as a large "hero" block.

**HTTP header capture is done via cURL** (`src/Detector.php::fetchWithCurl`),
since the built-in `file_get_contents` with `stream_context` on some hosts
does **not refresh `$http_response_header`** between consecutive requests. cURL is isolated
per request, so headers always match exactly the current call.

The section briefly covers 6 lines:

- **Web server** — name + version (nginx, Apache, LiteSpeed, IIS, Caddy, OpenLiteSpeed, Microsoft-IIS, gunicorn, Phusion Passenger). If `Server: cloudflare` or `Server: cloudfront` — shown as `cloudflare`/`cloudfront` with the warning "Real web server hidden behind CDN" and a **"behind CDN / hidden"** badge. If `Server` is missing but `X-Powered-By` exists, "IIS (ASP.NET)", "Express", or "PHP application" is shown with a note.
- **Node.js** — if present: version from `X-Powered-By: Express/4.18.2` / `Server: Node.js/20.x` (if the version is hidden — "present (version hidden)", otherwise "not detected").
- **PHP** — exact version, only if directly disclosed by `X-Powered-By: PHP/8.1.34` or `Server: ... PHP/8.1` or a strict `phpinfo` probe (`phpinfo.php`/`info.php` `HTTP 200` + `<title>phpinfo`). If hidden — "not detected". Additionally, `HEAD /wp-login.php`, `/index.php`, `/xmlrpc.php` are checked.
- **Python** — if present: version from `Server: gunicorn/20.x` / `Server: uvicorn` / `X-Powered-By: Python/3.11` or inference from the Django/Flask frameworks (no version). Otherwise "not detected".
- **CDN** — provider name, if detected by headers/HTML: Cloudflare (`CF-RAY`, `Server: cloudflare`), Amazon CloudFront (`X-Amz-Cf-Id`), Fastly (`X-Served-By`), Akamai (`X-Akamai-*`), QUIC.cloud (`X-QUIC`, `Via: quic.cloud`), BunnyCDN (`Server: BunnyCDN`), KeyCDN (`Server: keycdn-engine`), Sucuri (`X-Sucuri-ID`), StackPath / NetDNA (`Server: NetDNA-cache`), Imperva Incapsula (`X-Iinfo`), Varnish (`X-Varnish`, `Via: varnish`). Otherwise "not detected".
- **Database** — which DBMS the site uses (MySQL / MariaDB / PostgreSQL / SQLite / Progress / MSSQL / Oracle) and its version, if the site discloses it exactly.

> A remote check can learn the exact DBMS only if the site **directly discloses** it. In most cases the server hides this information.

**DB sources in priority order (first exact one wins):**

1. **Open `phpinfo`** — `GET /phpinfo.php` and `/info.php` with an `HTTP 200` + `<title>phpinfo` / `PHP Version` check. The `MySQL`/`MariaDB`/`PostgreSQL`/`SQLite`/`Progress`/`sqlsrv`/`oci8` sections are parsed.
2. **HTTP headers** `X-DB-Version`, `X-MySQL-Version`, etc. (rare, but exact).
3. **HTML leak** — search for SQL errors with a version (`MySQL server version 8.0.33`, `MariaDB 10.6.12`, `PostgreSQL 15.2`, etc.).
4. **CMS/framework inference** — `WordPress`/`Joomla`/`Drupal` traditionally → `MySQL / MariaDB`; `Laravel`/`Symfony`/`Yii` → several DBMSs. This gives a likely type without a version.
5. **Nothing found** — "not detected".

**Section structure (`sections.server`):**

| Field | Description |
|------|------|
| `name` | web server name |
| `version` | web server version or `null` |
| `raw` | raw `Server` value |
| `php_version` | PHP version or `null` |
| `php_version_source` | PHP version source |
| `node_present` | `true` if Node.js is detected |
| `node_version` | Node.js version or `null` |
| `node_source` | Node.js source |
| `python_present` | `true` if Python is detected |
| `python_version` | Python version or `null` |
| `cdn_provider` | CDN name or `null` |
| `cdn_detection` | CDN detection method |
| `dbms` | `MySQL` / `MariaDB` / … or `null` |
| `db_version` | DBMS version or `null` |
| `db_source` | `phpinfo` / `X-DB-Version` / `HTML leak` / `CMS inference` |
| `db_note` | explanation |
| `note` | note about a hidden server/CDN |

In the frontend this section has the `card--full` class (full width) and in the PDF it goes as a single "Web Server" section.

## PageSpeed block capabilities (Google PSI only)

A separate **PageSpeed** card (`sections.pagespeed`) — direct scores from
Google PageSpeed Insights API v5 (Lighthouse), two strategies side by side
for comparison: `mobile` and `desktop` (parallel requests via curl_multi):

- **Category scores (0–100):** Performance, Accessibility, Best Practices, SEO.
- **Lighthouse lab metrics:** FCP, LCP, TBT, CLS, Speed Index, TTI
  (`displayValue` + numeric `numericValue` values).
- **CrUX field data** (`loadingExperience`): overall category
  (`FAST` / `AVERAGE` / `SLOW`) and FCP/LCP/CLS/INP percentiles, if Google
  has real data for this URL.
- On error (quota, timeout, Lighthouse could not render the page)
  the card does not disappear but shows the error text and the tested URL.

**API key (recommended, free):**

- Without a key the API works, but with a low quota (~100 requests/day per IP).
- With a free key — ~25,000 requests/day, no card needed.
  Creation: Google Cloud Console → enable `PageSpeed Insights API` →
  Credentials → API key (restrict to this API only).
- IMPORTANT: set **Application restrictions = None** for the key.
  Requests come from the PHP server without a `Referer`, so the
  "Websites / HTTP referrers" restriction produces the error
  `Requests from referer <empty> are blocked`. Restrict the key only via
  **API restrictions = PageSpeed Insights API**.
  If the key is blocked by referer — the backend automatically retries the request
  without the key (with a mark in the card) instead of an empty error.
- The key is set in one of these ways (first found wins):
  `config.php` (recommended: copy `config.example.php` to `config.php`,
  the file is in `.gitignore`), then the `PAGESPEED_API_KEY` env, `$_ENV['PAGESPEED_API_KEY']`
  or the `PAGESPEED_API_KEY` PHP constant.

**Section structure (`sections.pagespeed`):**

| Field | Description |
|------|------|
| `tested_url` | tested URL (final after redirects) |
| `fetch_time` | PSI analysis time |
| `mobile` / `desktop` | strategy subsection: `strategy`, `performance` / `accessibility` / `best_practices` / `seo` scores (0–100), `metrics` (FCP/LCP/TBT/CLS/SI/TTI with `display`+`value`), `field_category` / `field_metrics` (CrUX) or `error` with a reason |
| `key_fallback` | `true` if the key was rejected by referer and the request was retried without a key |

**Notes:**

- Both strategies are requested in parallel (one wait instead of
  a doubled one, curl_multi; without cURL — sequentially); each request times out after 70 s.
  If one strategy fails with an error and the other succeeds — the card shows
  both (the error inline).
- In `runAnalysis()`, PageSpeed runs only when requested
  (`only=pagespeed` — then DNS/WHOIS/HTML requests are not performed at all).
  The frontend opens PSI as a separate parallel stream, so the slow Lighthouse
  (10–60 s per strategy) does not delay the fast blocks.
- The `pagespeed` SSE event is sent by its own stream; the main stream section order is:
  `location → hosting → whois → cms → frameworks → server`.
- Cache is invalidated by: `Cache::SCHEMA_VERSION = 28`.

## Structure

```
mp-site-detect/
├── index.php              # Main page with the form and progress checklist
├── config.example.php     # Local settings template (commit it)
├── config.php             # Local secrets (PAGESPEED_API_KEY) — in .gitignore, do NOT commit
├── .gitignore             # Ignores config.php and cache/ contents
├── api/
│   ├── check.php          # Full-analysis REST endpoint (JSON, for external clients)
│   └── stream.php         # SSE endpoint for streaming results (only/skip)
├── src/
│   ├── Detector.php       # Technology detection class (callback mode, only/skip filter)
│   ├── Cache.php          # File-based results cache with schema versioning
│   └── SpamProtection.php # CSRF tokens, honeypot, JS marker, rate limit
├── assets/
│   ├── css/
│   │   └── style.css      # Styles (BEM)
│   ├── js/
│   │   └── app.js         # Form, two parallel EventSource streams, rendering, PDF
│   └── fonts/             # PTSans fonts for Cyrillic PDF
├── cache/                 # Cache directory (created automatically, closed by .htaccess)
│   ├── .htaccess          # Denies direct HTTP access
│   ├── *.json             # Cached results
│   └── security/          # SpamProtection service data (tokens, rate limit), .htaccess inside
└── readme.md
```

## Installation

1. Copy the files to the web server root (e.g. `htdocs` for Apache or a Laragon folder).
2. Make sure `allow_url_fopen` is enabled in PHP (usually enabled by default).
3. Make sure aggressive compression is disabled for the `api/stream.php` SSE endpoint
   (or the `mod_deflate` module is used, which does not compress `text/event-stream`).
4. Make sure the `cache/` directory is writable by the PHP process.
   Usually this is `www-data` (Linux) or `IUSR` / `Everyone` (Windows). On the
   first request, the `cache/security/` subdirectory is created automatically for
   bot-protection service data (tokens, rate limit, HMAC secret).
5. (Recommended) Copy `config.example.php` to `config.php` and enter the
   free Google PageSpeed Insights API key (`PAGESPEED_API_KEY`) —
   without it, the PageSpeed block runs on the low keyless quota.
   `config.php` is already in `.gitignore` and is never committed
   (see "[PageSpeed block capabilities](#pagespeed-block-capabilities-google-psi-only)").
6. Open `http://your-host/mp-site-detect/` in a browser.
   JavaScript **must be enabled** in your browser — otherwise the form
   will reject the request (see "[Spam and bot protection](#spam-and-bot-protection)").

> **Laragon / Apache**: no extra setup needed — PHP serves
> `text/event-stream` without buffering, and `.htaccess` in `cache/` blocks direct access.
>
> **Nginx**: make sure your location block contains `proxy_buffering off;`
> and/or add a rule for `text/event-stream`. The `X-Accel-Buffering: no` header is also sent
> for compatibility. To protect `cache/`, add this rule:
>
> ```nginx
> location ^~ /mp-site-detect/cache/ {
>     deny all;
>     return 403;
> }
> ```

## Usage

1. Enter a URL or domain in the form field.
2. Click **"Check"**.
3. A progress checklist appears in the results block right away — each module
   switches from *"pending"* → *"active"* (spinner) → *"done"* (✓),
   and the corresponding data card appears on the page without reloading.
4. If there is already a cached result for the domain — it appears instantly,
   and a **"From cache"** badge appears in the header with the relative age of the record
   (just now / N min ago / N hours ago / N days ago).
5. The **"Refresh"** button next to the PDF forces the cache to be ignored
   and runs a fresh analysis.
6. After the main analysis finishes, the **"Download PDF"** button becomes active.
   The PageSpeed card may load later — if it is already on screen,
   the PDF will include it too.

## How it works

### Asynchrony (SSE)

Instead of one large request waiting for the full analysis, **Server-Sent Events** are used
via `api/stream.php`. PHP runs the analysis steps sequentially
(`src/Detector.php::analyzeWithCallback`) and after each completed module
sends the client an SSE event with data:

| Event       | When it is sent                              |
|-------------|------------------------------------------------|
| `cached`    | at the start of the stream, if the result came from cache |
| `meta`      | right after the IP address is determined              |
| `location`  | after a successful request to ip-api.com           |
| `hosting`   | together with `location` (from the same request)           |
| `whois`     | after the request to who-dat.as93.net               |
| `cms`       | after CMS detection (with embedded WordPress details, if any) |
| `frameworks`| after HTML and header analysis               |
| `server`    | after parsing HTTP headers — single Web Server section (web server + Node.js/PHP/Python + CDN + database) |
| `pagespeed` | via a separate parallel stream — Google PSI scores (Lighthouse mobile+desktop), 10–120 s |
| `complete`  | final event with the full result (each stream has its own) |
| `error`     | on error (a PageSpeed-stream error is shown in its card, not as a banner) |

**Parallel streams.** The frontend opens two `EventSource`s at once:
the main one (`skip=pagespeed` — fast blocks: IP, location, hosting, WHOIS, CMS,
frameworks, server) and PageSpeed (`only=pagespeed` — Lighthouse only).
Fast cards appear in 1–2 s without waiting for the slow PSI.
The `only` / `skip` params (comma-separated) are supported by the backend
(`Detector::analyzeWithCallback($emit, $only, $skip)`): unneeded sections
are not even executed (no extra HTTP requests). The PageSpeed stream is cached
separately (`<domain>.pagespeed`), so parallel writes do not overwrite each other.
Without `only`/`skip` — the former behavior: everything in one stream.

In the frontend (`assets/js/app.js`), two `EventSource` listeners (main + PageSpeed)
update the corresponding card and check off the checklist step on each event.
This way the user sees the first results in 1–2 seconds
(IP, location, hosting) without waiting for the full analysis cycle, and the PageSpeed card
is drawn as soon as Lighthouse responds. The main stream's `complete` does not
overwrite the already received PageSpeed (merge), and the PageSpeed stream's `complete`
does not touch the main result.

The legacy `POST api/check.php` is kept for external clients that need
a single JSON response instead of a stream.

### Results cache

To reduce load on third-party APIs (`ip-api.com`, `who-dat.as93.net`)
and speed up repeat requests, a simple file cache is implemented
(`src/Cache.php`) — **without using a database**.

- The result is stored in a `cache/<sha256>.json` file.
- The key is the SHA-256 of the normalized domain (no `www`, no scheme, no path).
- The PageSpeed stream (`only=pagespeed`) is cached separately — `cache/<sha256>.json`
  for the `<domain>.pagespeed` key, so parallel streams do not overwrite each other's
  records, and a repeat visit instantly shows the PSI block too.
- Default TTL — **24 hours** (can be overridden with the `ttl=` param).
- The domains `example.com`, `https://www.example.com/path` resolve to one key.
- The `cache/` directory is protected from direct HTTP access via `.htaccess`.
- **Schema versioning** (`schema_version`): on incompatible structure changes
  the `Cache::SCHEMA_VERSION` constant is incremented — old records
  are automatically treated as invalid and overwritten. Current version: **29**
  (removed standalone `sections.site`, `sections.technologies`, `sections.wordpress` — now `sections.cms[].wordpress`; `sections.cdn`/`sections.db` merged into `sections.server`; added Node.js/Python to `sections.server`; added `sections.pagespeed` — Google PSI mobile+desktop; removed Gutenberg from `page_builders`).

**Algorithm:**

1. A `?url=example.com` request arrives.
2. The backend checks whether `cache/` has a file for the domain and whether it is expired.
3. If so — the `cached` event is sent first, then all sections are
   replayed from cache without calling third-party services.
4. If not — a full analysis runs, the result is stored in cache,
   and `complete` is sent at the end of the stream.

**Request parameters:**

| Parameter | Description                                                                  |
|----------|-----------------------------------------------------------------------|
| `url`    | URL or domain to analyze (required)                               |
| `force`  | `1` — ignore cache and run a fresh analysis (optional)          |
| `ttl`    | cache TTL in seconds (optional, defaults to `86400` = 24 h)  |
| `only`   | run only these sections, e.g. `only=pagespeed` (the page opens this stream in parallel) |
| `skip`   | skip sections, e.g. `skip=pagespeed` (the page's main stream) |
| `csrf_token` | secured form token (appended automatically by JS)              |
| `hp`     | honeypot field value (must be empty)                           |
| `js`     | 32-char hex JS-execution marker                                       |
| `ts`     | form load time in milliseconds (Unix timestamp × 1000)         |

All requests (both POST and GET/SSE) **must** pass a valid CSRF token
and JS marker, otherwise the request is rejected by the protection system (see
"[Spam and bot protection](#spam-and-bot-protection)").

**Examples:**

```
GET /api/stream.php?url=example.com&csrf_token=…&js=…&ts=…      # regular request (with cache)
GET /api/stream.php?url=example.com&force=1&csrf_token=…&js=…&ts=…  # force fresh analysis
GET /api/stream.php?url=example.com&ttl=300&csrf_token=…&js=…&ts=…  # 5 min TTL
POST /api/check.php  url=example.com  csrf_token=… js=… ts=…    # JSON response, with cache
POST /api/check.php  url=example.com  force=1 csrf_token=…       # JSON response, no cache
```

In real code, all protection params are appended automatically
by the frontend (`assets/js/app.js`) — the client does not need to pass them manually.

**Clearing the cache:** in the `cache/` directory, just delete the `*.json` files,
or call programmatically:

```php
$cache = new \App\Cache();
$cache->clear();              // delete everything
$cache->cleanExpired();       // delete only expired
$cache->delete('example.com');// delete one domain
```

**Clearing bot-protection data:** the `cache/security/` subdirectory stores
request counters (`rate_*.json`), temporary bans (`banned_*.json`), and the token-signing
secret (`.secret`). If needed, they can be deleted manually or
programmatically:

```php
$spam = new \App\SpamProtection();
$spam->resetRateLimit('203.0.113.42'); // lift the limit and ban for a specific IP
```

## Third-party services used

| Service | Purpose |
|--------|------------|
| [ip-api.com](http://ip-api.com) | Geolocation and ISP by IP |
| [who-dat.as93.net](https://who-dat.as93.net) | WHOIS info about the domain |
| [PageSpeed Insights API](https://developers.google.com/speed/docs/insights/v5/get-started) | Lighthouse scores (mobile + desktop), a free API key is needed for the full quota |
| [jsPDF](https://github.com/parallax/jsPDF) (CDN) | PDF generation |

## Running locally (Laragon)

The service is built to run in the Laragon environment. Place the `mp-site-detect` folder
in `F:\laragon\www\ai\` and open `http://mp-site-detect.test/` (or your
corresponding virtual host).

## License

Free to use.
