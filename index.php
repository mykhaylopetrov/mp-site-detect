<?php declare(strict_types=1);
require_once __DIR__ . '/src/SpamProtection.php';
use App\SpamProtection;
$spamProtection = new SpamProtection();
$csrfToken = $spamProtection->generateToken();
?>
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="MP Site Detect — аналіз сайту: IP-адреса, геолокація, хостинг, WHOIS, CMS, фреймворки та технології.">
    <meta name="theme-color" content="#1f1147">
    <meta name="csrf-token" content="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
    <title>MP Site Detect — аналіз сайту | thePetrov.com</title>
    <link rel="preconnect" href="https://cdnjs.cloudflare.com">
    <link rel="stylesheet" href="assets/css/style.css?v=18">
    <link rel="icon" href="assets/img/logo-512x512.png">
</head>
<body class="page">
    <header class="header">
        <div class="header__container">
            <a class="header__logo" href="">
                <div class="header__brand"><img src="assets/img/logo-512x512.png" alt="MP Site Detect — аналіз сайту | thePetrov.com"></div>
                <span class="header__name">MP Site Detect — аналіз сайту | thePetrov.com</span>
            </a>
            <p class="header__subtitle">Аналіз сайту: IP, геолокація, хостинг, WHOIS, CMS та технології</p>
        </div>
    </header>

    <main class="main">
        <section class="hero">
            <div class="hero__container">
                <h1 class="hero__title">Дізнайтесь все про&nbsp;будь-який&nbsp;сайт</h1>
                <p class="hero__text">
                    Введіть домен або URL-адресу, і сервіс миттєво покаже IP-адресу, місцезнаходження,
                    хостинг-провайдера, WHOIS-дані, використану CMS, фреймворки та&nbsp;інші технології.
                </p>
            </div>
        </section>

        <section class="checker" aria-labelledby="checker-title">
            <div class="checker__container">
                <h2 class="visually-hidden" id="checker-title">Перевірка сайту</h2>

                <form class="form" id="check-form" novalidate>
                    <div class="form__group">
                        <label class="form__label" for="url-input">URL або домен сайту</label>
                        <div class="form__row">
                            <input
                                class="form__input"
                                type="text"
                                id="url-input"
                                name="url"
                                placeholder="example.com або https://example.com"
                                autocomplete="off"
                                spellcheck="false"
                                autocapitalize="off"
                                required
                            >
                            <button class="form__button" type="submit" id="check-btn">
                                <span class="form__button-text">Перевірити</span>
                                <span class="form__button-loader" aria-hidden="true"></span>
                            </button>
                        </div>
                        <div class="form__hint">Наприклад: <button type="button" class="form__example" data-example="2ip.ua">2ip.ua</button>, <button type="button" class="form__example" data-example="wordpress.org">wordpress.org</button>, <button type="button" class="form__example" data-example="laravel.com">laravel.com</button></div>
                    </div>

                    <div class="form__honeypot" aria-hidden="true">
                        <label for="website_url">Будь ласка, залиште це поле порожнім</label>
                        <input type="text" id="website_url" name="website_url" tabindex="-1" autocomplete="off" inputmode="none">
                    </div>
                    <input type="hidden" name="csrf_token" id="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="js_token" id="js_token" value="">
                    <input type="hidden" name="form_loaded_at" id="form_loaded_at" value="<?= (int)(microtime(true) * 1000) ?>">
                </form>

                <div class="status status--error" id="status-error" hidden role="alert">
                    <p class="status__text" id="status-error-text"></p>
                </div>

                <article class="results" id="results" hidden>
                    <header class="results__header">
                        <div class="results__heading">
                            <h2 class="results__title" id="results-domain"></h2>
                            <p class="results__subtitle" id="results-title"></p>
                            <p class="results__meta">
                                <span class="results__meta-item"><span class="results__meta-label">IP:</span> <code id="results-ip">…</code></span>
                                <span class="results__meta-item"><span class="results__meta-label">Перевірено:</span> <time id="results-date">…</time></span>
                                <span class="results__meta-item results__meta-item--badge" id="results-cached" hidden>
                                    <span class="results__cached-badge" title="Результат завантажено з локального кешу">
                                        <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true">
                                            <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm4.2 7.6-5.5 5.5a1 1 0 0 1-1.4 0l-3-3a1 1 0 0 1 1.4-1.4L10 13.2l4.8-4.8a1 1 0 0 1 1.4 1.4z"/>
                                        </svg>
                                        З кешу
                                    </span>
                                    <span class="results__cached-age" id="results-cached-age"></span>
                                </span>
                            </p>
                        </div>
                        <div class="results__actions">
                            <button class="results__refresh-btn" id="refresh-btn" type="button" title="Проігнорувати кеш і виконати свіжий аналіз">
                                <svg class="results__refresh-icon" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true">
                                    <path d="M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 7.5 10.5.75.75 0 0 0-1.4-.5A6.5 6.5 0 1 1 12 5.5c1.7 0 3.22.66 4.4 1.73L14 9.5h7v-7l-2.35 2.85z"/>
                                </svg>
                                <span>Оновити</span>
                            </button>
                            <button class="results__pdf-btn" id="pdf-btn" type="button" disabled>
                                <svg class="results__pdf-icon" viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm0 7V3.5L19.5 9H14zM8 13h2v2H8v-2zm0 4h2v2H8v-2zm0-8h2v2H8V9zm4 0h1v2h-1V9zm4 8h-3v-2h3v2zm0-4h-3v-2h3v2zm0-4h-3V9h3v2z"/>
                                </svg>
                                <span>Завантажити PDF</span>
                            </button>
                        </div>
                    </header>

                    <section class="progress" id="progress" aria-label="Хід аналізу">
                        <h3 class="progress__title">Аналіз у реальному часі</h3>
                        <ol class="progress__list" id="progress-list">
                            <li class="progress__item" data-step="meta">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">Визначення IP-адреси</span>
                            </li>
                            <li class="progress__item" data-step="location">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">Місцезнаходження сервера</span>
                            </li>
                            <li class="progress__item" data-step="hosting">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">Хостинг-провайдер</span>
                            </li>
                            <li class="progress__item" data-step="whois">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">WHOIS-інформація</span>
                            </li>
                            <li class="progress__item" data-step="cms">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">Система керування (CMS)</span>
                            </li>
                            <li class="progress__item" data-step="frameworks">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">Фреймворки</span>
                            </li>
                            <li class="progress__item" data-step="server">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">Веб-сервер</span>
                            </li>
                            <li class="progress__item" data-step="pagespeed">
                                <span class="progress__indicator" aria-hidden="true"></span>
                                <span class="progress__label">PageSpeed</span>
                            </li>
                        </ol>
                    </section>

                    <div class="results__content" id="results-content">
                        <!-- Картки результатів рендеряться JS у міру надходження даних -->
                    </div>
                </article>
            </div>
        </section>

        <section class="features">
            <div class="features__container">
                <h2 class="features__title">Що перевіряє сервіс</h2>
                <ul class="features__list">
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">🌍</span>
                        <h3 class="features__heading">IP та місцезнаходження</h3>
                        <p class="features__text">Країна, регіон, місто, координати та часовий пояс сервера.</p>
                    </li>
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">🏢</span>
                        <h3 class="features__heading">Хостинг-провайдер</h3>
                        <p class="features__text">ISP, організація, автономна система та тип хостингу.</p>
                    </li>
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">📋</span>
                        <h3 class="features__heading">WHOIS-інформація</h3>
                        <p class="features__text">Реєстратор, дати створення, оновлення й закінчення домену.</p>
                    </li>
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">⚙️</span>
                        <h3 class="features__heading">CMS</h3>
                        <p class="features__text">Виявлення WordPress, Joomla, Drupal, OpenCart, Magento та інших.</p>
                    </li>
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">🧩</span>
                        <h3 class="features__heading">Фреймворки</h3>
                        <p class="features__text">Laravel, Symfony, React, Vue, Angular, Next.js, Nuxt.js тощо.</p>
                    </li>
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">🖥️</span>
                        <h3 class="features__heading">Веб-сервер</h3>
                        <p class="features__text">Сервер, Node.js, PHP, Python, CDN та база даних — однією карткою.</p>
                    </li>
                    <li class="features__item">
                        <span class="features__icon" aria-hidden="true">⚡</span>
                        <h3 class="features__heading">PageSpeed</h3>
                        <p class="features__text">Бали Google PageSpeed Insights (mobile) та метрики LCP, CLS, TBT.</p>
                    </li>
                </ul>
            </div>
        </section>
    </main>

    <footer class="footer">
        <div class="footer__container">
            <p class="footer__text">MP Site Detect | thePetrov.com &copy; <span id="year"><?= date('Y') ?></span> — аналіз сайтів українською</p>
            <p class="footer__note">Сервіс використовує відкриті джерела даних: ip-api.com, who-dat.as93.net.</p>
        </div>
    </footer>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js" defer></script>
    <script src="assets/js/app.js?v=18" defer></script>
</body>
</html>
