/* =============================================================
 * MP Site Detect — Frontend logic
 * - Form submit + SSE (EventSource) to api/stream.php
 * - Progressive rendering of detected sections in BEM blocks
 * - PDF export using jsPDF
 * ============================================================= */

(() => {
    'use strict';

    /* ------------------------- DOM refs ----------------------------- */
    const form = document.getElementById('check-form');
    const input = document.getElementById('url-input');
    const btn = document.getElementById('check-btn');
    const statusError = document.getElementById('status-error');
    const statusErrorText = document.getElementById('status-error-text');
    const results = document.getElementById('results');
    const resultsDomain = document.getElementById('results-domain');
    const resultsTitle = document.getElementById('results-title');
    const resultsIp = document.getElementById('results-ip');
    const resultsDate = document.getElementById('results-date');
    const resultsContent = document.getElementById('results-content');
    const progressBlock = document.getElementById('progress');
    const progressList = document.getElementById('progress-list');
    const pdfBtn = document.getElementById('pdf-btn');
    const refreshBtn = document.getElementById('refresh-btn');
    const cachedBadge = document.getElementById('results-cached');
    const cachedAge = document.getElementById('results-cached-age');
    const honeypotField = document.getElementById('website_url');
    const csrfField = document.getElementById('csrf_token');
    const jsTokenField = document.getElementById('js_token');
    const formLoadedAtField = document.getElementById('form_loaded_at');

    /* ------------------------- Spam protection init ----------------- */
    const randomHex = (len) => {
        const chars = '0123456789abcdef';
        let out = '';
        const arr = new Uint32Array(Math.ceil(len / 8));
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(arr);
        } else {
            for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 0xffffffff);
        }
        for (let i = 0; i < arr.length; i++) {
            out += arr[i].toString(16).padStart(8, '0');
        }
        return out.slice(0, len);
    };
    if (jsTokenField) {
        jsTokenField.value = randomHex(32);
    }

    /* ------------------------- State -------------------------------- */
    let lastResult = null;
    let lastUrl = null;
    let eventSource = null;
    let psiSource = null;
    let fromCache = false;

    /* ------------------------- Helpers ------------------------------ */
    const escapeHtml = (str) => {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };

    const nl2br = (str) => escapeHtml(str).replace(/\n/g, '<br>');

    const formatDateTime = (iso) => {
        if (!iso) return '—';
        try {
            const d = new Date(iso);
            if (isNaN(d.getTime())) return iso;
            return d.toLocaleString('uk-UA', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
            });
        } catch {
            return iso;
        }
    };

    /* ------------------------- Cached helpers ----------------------- */
    const formatAge = (iso) => {
        if (!iso) return '';
        const then = new Date(iso).getTime();
        if (!then || isNaN(then)) return '';
        const diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
        if (diffSec < 60) return 'щойно';
        if (diffSec < 3600) {
            const m = Math.floor(diffSec / 60);
            return `${m} хв тому`;
        }
        if (diffSec < 86400) {
            const h = Math.floor(diffSec / 3600);
            return `${h} год тому`;
        }
        const d = Math.floor(diffSec / 86400);
        return `${d} д тому`;
    };

    const showCachedBadge = (cachedAt) => {
        if (!cachedBadge) return;
        cachedBadge.hidden = false;
        if (cachedAge) {
            cachedAge.textContent = cachedAt ? `· ${formatAge(cachedAt)}` : '';
        }
    };

    const hideCachedBadge = () => {
        if (!cachedBadge) return;
        cachedBadge.hidden = true;
        if (cachedAge) cachedAge.textContent = '';
    };

    const validateUrl = (value) => {
        const trimmed = (value || '').trim();
        if (!trimmed) return { ok: false, msg: 'Введіть URL або домен' };

        const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : 'https://' + trimmed;

        let host;
        try {
            host = new URL(normalized).hostname;
        } catch {
            return { ok: false, msg: 'Некоректний формат URL' };
        }

        const domainPattern = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
        if (!domainPattern.test(host)) {
            return { ok: false, msg: 'Некоректне ім\'я домену' };
        }

        return { ok: true, value: trimmed };
    };

    const setLoading = (on) => {
        if (on) {
            btn.classList.add('form__button--loading');
            btn.disabled = true;
            statusError.hidden = true;
        } else {
            btn.classList.remove('form__button--loading');
            btn.disabled = false;
        }
    };

    const showError = (message) => {
        statusErrorText.textContent = message;
        statusError.hidden = false;
        results.hidden = true;
    };

    const hideError = () => {
        statusError.hidden = true;
    };

    /* ------------------------- Progress list ------------------------ */
    const setStepState = (step, state) => {
        if (!progressList) return;
        const item = progressList.querySelector(`[data-step="${step}"]`);
        if (!item) return;
        item.classList.remove('progress__item--pending', 'progress__item--active', 'progress__item--done');
        item.classList.add('progress__item--' + state);
    };

    const resetProgress = () => {
        if (!progressList) return;
        progressList.querySelectorAll('.progress__item').forEach((item) => {
            item.classList.remove('progress__item--active', 'progress__item--done');
            item.classList.add('progress__item--pending');
        });
    };

    const markActiveStep = (step) => {
        if (!progressList) return;
        const order = ['meta', 'location', 'hosting', 'whois', 'cms', 'frameworks', 'server', 'pagespeed'];
        const idx = order.indexOf(step);
        if (idx < 0) return;
        // mark current and any earlier pending steps as active (current)
        for (let i = 0; i <= idx; i++) {
            const key = order[i];
            const item = progressList.querySelector(`[data-step="${key}"]`);
            if (!item) continue;
            if (item.classList.contains('progress__item--done')) continue;
            if (i === idx) {
                item.classList.remove('progress__item--pending');
                item.classList.add('progress__item--active');
            } else {
                // попередні кроки, які ще не завершилися — позначаємо як активні, поки немає відповіді
                if (!item.classList.contains('progress__item--active')) {
                    item.classList.remove('progress__item--pending');
                    item.classList.add('progress__item--active');
                }
            }
        }
    };

    const markStepDone = (step) => {
        if (!progressList) return;
        const item = progressList.querySelector(`[data-step="${step}"]`);
        if (!item) return;
        item.classList.remove('progress__item--pending', 'progress__item--active');
        item.classList.add('progress__item--done');
    };

    const finishProgress = () => {
        if (!progressList) return;
        progressList.querySelectorAll('.progress__item').forEach((item) => {
            item.classList.remove('progress__item--pending', 'progress__item--active');
            item.classList.add('progress__item--done');
        });
    };

    /* ------------------------- Rendering ---------------------------- */
    const renderDefinitions = (data) => {
        if (!data || Object.keys(data).length === 0) {
            return '<p class="empty">Інформацію не знайдено</p>';
        }
        const rows = Object.entries(data).map(([key, value]) => `
            <dt class="defs__term">${escapeHtml(key)}</dt>
            <dd class="defs__def">${nl2br(value)}</dd>
        `).join('');
        return `<dl class="defs">${rows}</dl>`;
    };

    const renderTags = (items) => {
        if (!items || items.length === 0) {
            return '<p class="empty">Не виявлено</p>';
        }
        return `<div class="tech-list">${items.map(item => {
            const confidence = (item.confidence || 'medium').toLowerCase();
            const tagLabel = item.category || (item.type ? item.type : null);
            const tagHtml = tagLabel
                ? `<span class="tech-item__tag tech-item__category">${escapeHtml(tagLabel)}</span>`
                : (item.confidence
                    ? `<span class="tech-item__tag tech-item__tag--${confidence}">${escapeHtml(confidence)}</span>`
                    : '');
            return `
                <div class="tech-item">
                    <div class="tech-item__head">
                        <span class="tech-item__name">${escapeHtml(item.name)}</span>
                        ${tagHtml}
                    </div>
                    ${item.description ? `<p class="tech-item__desc">${escapeHtml(item.description)}</p>` : ''}
                    ${item.site ? `<a class="tech-item__link" href="${escapeHtml(item.site)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.site)} →</a>` : ''}
                </div>
            `;
        }).join('')}</div>`;
    };

    const renderWordPress = (wp) => {
        const parts = [];
        const methodLabels = {
            body_class: 'клас <body>',
            plugin: 'наявний плагін',
            html: 'HTML-розмітка',
        };

        // Version
        // wp.version       — точна версія (з generator/readme/theme_tested)
        // wp.version_min   — нижня межа (з REST API або twemoji), якщо точна невідома
        // wp.version_source — джерело визначення: 'generator' | 'readme' | 'theme_tested' | 'rest_api' | 'twemoji' | 'hidden'
        // wp.version_note  — пояснення для користувача
        if (wp.version) {
            const sourceLabels = {
                generator: 'мета-тег <em>generator</em>',
                readme: 'файл <em>/readme.html</em>',
                theme_tested: 'поле <em>Tested up to</em> теми',
            };
            const sourceHtml = sourceLabels[wp.version_source]
                ? ` <span class="wp-version__source" title="Джерело: ${sourceLabels[wp.version_source].replace(/<[^>]+>/g, '')}">(${sourceLabels[wp.version_source]})</span>`
                : '';
            const noteHtml = wp.version_note
                ? `<div class="wp-version__note">${escapeHtml(wp.version_note)}</div>`
                : '';
            parts.push(`<div class="wp-version">
                <span class="wp-version__label">Версія WordPress:</span>
                <span class="wp-version__value">${escapeHtml(wp.version)}</span>${sourceHtml}
                ${noteHtml}
            </div>`);
        } else if (wp.version_min) {
            const sourceLabels = {
                rest_api: 'наявні маршрути <em>/wp-json/</em>',
                twemoji: 'версія twemoji у <em>wp-emoji-release.min.js</em>',
            };
            const sourceHtml = sourceLabels[wp.version_source]
                ? ` <span class="wp-version__source" title="Джерело: ${sourceLabels[wp.version_source].replace(/<[^>]+>/g, '')}">(${sourceLabels[wp.version_source]})</span>`
                : '';
            parts.push(`<div class="wp-version wp-version--approx" title="Мета-тег generator прибрано, /readme.html заблоковано — визначено лише нижню межу">
                <span class="wp-version__label">Версія WordPress:</span>
                <span class="wp-version__value">≥ ${escapeHtml(wp.version_min)}</span>${sourceHtml}
                <div class="wp-version__note">${escapeHtml(wp.version_note || 'Точна версія прихована власником сайту.')}</div>
            </div>`);
        } else {
            const isWordpressDetected = wp.theme || wp.parent_theme || (wp.page_builders && wp.page_builders.length) || (wp.plugins && wp.plugins.length);
            if (isWordpressDetected) {
                parts.push(`<div class="wp-version wp-version--hidden" title="Мета-тег generator прибрано, /readme.html заблоковано — точна версія недоступна">
                    <span class="wp-version__label">Версія WordPress:</span>
                    <span class="wp-version__value">прихована</span>
                </div>`);
            }
        }

        // Active theme
        if (wp.theme) {
            const t = wp.theme;
            parts.push(`<div class="wp-theme">
                <div class="wp-theme__heading">
                    <span class="wp-theme__label">Активна тема</span>
                    <span class="wp-theme__name">${escapeHtml(t.name || t.slug || '—')}${
                        t.version ? ' <span class="wp-theme__version">v' + escapeHtml(t.version) + '</span>' : ''
                    }</span>
                </div>
                ${t.author ? '<div class="wp-theme__author">Автор: ' + escapeHtml(t.author) + '</div>' : ''}
                ${t.description ? '<p class="wp-theme__desc">' + escapeHtml(t.description) + '</p>' : ''}
                ${t.homepage ? '<a class="wp-theme__link" href="' + escapeHtml(t.homepage) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(t.homepage) + ' →</a>' : ''}
                <div class="wp-theme__slug">Slug: <code>${escapeHtml(t.slug || '')}</code></div>
            </div>`);
        }

        // Parent theme
        if (wp.parent_theme) {
            const p = wp.parent_theme;
            parts.push(`<div class="wp-theme wp-theme--parent">
                <div class="wp-theme__heading">
                    <span class="wp-theme__label">Parent-тема</span>
                    <span class="wp-theme__name">${escapeHtml(p.name || p.slug || '—')}${
                        p.version ? ' <span class="wp-theme__version">v' + escapeHtml(p.version) + '</span>' : ''
                    }</span>
                </div>
                ${p.author ? '<div class="wp-theme__author">Автор: ' + escapeHtml(p.author) + '</div>' : ''}
                ${p.homepage ? '<a class="wp-theme__link" href="' + escapeHtml(p.homepage) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(p.homepage) + ' →</a>' : ''}
                <div class="wp-theme__slug">Slug: <code>${escapeHtml(p.slug || '')}</code></div>
            </div>`);
        }

        // Page builder(s) — може бути кілька (наприклад, Elementor + WPBakery).
        // Gutenberg тут немає свідомо: він у ядрі WP за замовчуванням.
        const builders = Array.isArray(wp.page_builders)
            ? wp.page_builders
            : (wp.page_builder ? [wp.page_builder] : []);

        if (builders.length) {
            const items = builders.map((pb) => {
                const method = pb.detection ? methodLabels[pb.detection] || pb.detection : '';
                return `<div class="wp-page-builder">
                    <div class="wp-page-builder__heading">
                        <span class="wp-page-builder__name">${escapeHtml(pb.name)}</span>
                        ${method ? '<span class="wp-page-builder__method">(' + escapeHtml(method) + ')</span>' : ''}
                    </div>
                    ${pb.description ? '<p class="wp-page-builder__desc">' + escapeHtml(pb.description) + '</p>' : ''}
                    ${pb.site ? '<a class="wp-page-builder__link" href="' + escapeHtml(pb.site) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(pb.site) + ' →</a>' : ''}
                </div>`;
            }).join('');

            parts.push(`<div class="wp-page-builders">
                <div class="wp-page-builders__heading">
                    <span class="wp-page-builders__label">Конструктор${builders.length > 1 ? 'и' : ''} сторінок (${builders.length}):</span>
                </div>
                <div class="wp-page-builders__list">${items}</div>
            </div>`);
        }

        // WooCommerce
        if (wp.woocommerce && wp.woocommerce.active) {
            const woo = wp.woocommerce;
            const wooItems = [];
            if (woo.version) {
                wooItems.push(`<div class="wp-woo__row"><strong>Версія:</strong> ${escapeHtml(woo.version)}</div>`);
            }
            const urls = woo.urls || {};
            const urlFlags = [];
            if (urls.shop) urlFlags.push('магазин');
            if (urls.cart) urlFlags.push('кошик');
            if (urls.checkout) urlFlags.push('оформлення');
            if (urls.my_account) urlFlags.push('особистий кабінет');
            if (urlFlags.length) {
                wooItems.push(`<div class="wp-woo__row"><strong>Сторінки WooCommerce:</strong> ${urlFlags.map(escapeHtml).join(', ')}</div>`);
            }
            if (Array.isArray(woo.payment_gateways) && woo.payment_gateways.length) {
                wooItems.push(`<div class="wp-woo__row"><strong>Оплата:</strong> ${woo.payment_gateways.map(escapeHtml).join(', ')}</div>`);
            }
            if (Array.isArray(woo.shipping_modules) && woo.shipping_modules.length) {
                wooItems.push(`<div class="wp-woo__row"><strong>Доставка:</strong> ${woo.shipping_modules.map(escapeHtml).join(', ')}</div>`);
            }
            parts.push(`<div class="wp-woo">
                <div class="wp-woo__heading">🛒 WooCommerce</div>
                <div class="wp-woo__body">${wooItems.join('')}</div>
            </div>`);
        }

        // Plugins
        if (Array.isArray(wp.plugins) && wp.plugins.length > 0) {
            const pluginList = wp.plugins.map((p) => `
                <div class="wp-plugin">
                    <span class="wp-plugin__name">${escapeHtml(p.name)}${
                        p.version ? ' <span class="wp-plugin__version">v' + escapeHtml(p.version) + '</span>' : ''
                    }</span>
                    ${p.site ? '<a class="wp-plugin__link" href="' + escapeHtml(p.site) + '" target="_blank" rel="noopener noreferrer">↗</a>' : ''}
                </div>
            `).join('');
            parts.push(`<div class="wp-plugins"><h4 class="wp-plugins__title">Виявлені плагіни (${wp.plugins.length}):</h4><div class="wp-plugins__list">${pluginList}</div></div>`);
        }

        if (wp.note) {
            parts.push('<p class="wp-note">' + escapeHtml(wp.note) + '</p>');
        }

        // Адмін-панель (логін) — під інформаційним повідомленням про плагіни
        if (wp.login_url) {
            const li = wp.login_url;
            if (li.is_hidden) {
                parts.push(`<div class="wp-login wp-login--hidden">
                    <span class="wp-login__label">Адмін-панель</span>
                    <span class="wp-login__badge wp-login__badge--hidden">приховано</span>
                    <div class="wp-login__note">${escapeHtml(li.note || 'Адреса за замовчуванням входу в адмін-панель була змінена власником сайту.')}</div>
                </div>`);
            } else if (li.url) {
                const isCustom = li.is_custom;
                const badgeClass = isCustom ? 'wp-login__badge--custom' : '';
                const badgeText = isCustom ? 'кастомна' : 'стандартна';
                const blockClass = isCustom ? 'wp-login--custom' : '';
                parts.push(`<div class="wp-login ${blockClass}">
                    <span class="wp-login__label">Адмін-панель</span>
                    <a class="wp-login__url" href="${escapeHtml(li.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(li.url)}</a>
                    <span class="wp-login__badge ${badgeClass}">${escapeHtml(badgeText)}</span>
                    ${li.path && li.path !== li.url ? `<span class="wp-login__note">Шлях: <code>${escapeHtml(li.path)}</code></span>` : ''}
                    ${li.note ? `<div class="wp-login__note">${escapeHtml(li.note)}</div>` : ''}
                </div>`);
            }
        }

        return parts.join('');
    };

    const renderJoomla = (j) => {
        if (!j) return '';
        const parts = [];

        // Версія ядра
        if (j.version) {
            const sourceLabels = {
                generator: 'мета-тег generator',
                manifest: 'файл <em>/administrator/manifests/files/joomla.xml</em>',
                language: 'файл <em>/language/en-GB/en-GB.xml</em>',
            };
            const sourceHtml = sourceLabels[j.version_source]
                ? ` <span class="wp-version__source">(${sourceLabels[j.version_source]})</span>`
                : '';
            parts.push(`<div class="wp-version">
                <span class="wp-version__label">Версія Joomla:</span>
                <span class="wp-version__value">${escapeHtml(j.version)}</span>${sourceHtml}
                ${j.version_note ? `<div class="wp-version__note">${escapeHtml(j.version_note)}</div>` : ''}
            </div>`);
        } else if (j.template || (Array.isArray(j.extensions) && j.extensions.length)) {
            parts.push(`<div class="wp-version wp-version--hidden">
                <span class="wp-version__label">Версія Joomla:</span>
                <span class="wp-version__value">прихована</span>
            </div>`);
        }

        // Активний шаблон
        if (j.template) {
            const t = j.template;
            parts.push(`<div class="wp-theme">
                <div class="wp-theme__heading">
                    <span class="wp-theme__label">Активний шаблон</span>
                    <span class="wp-theme__name">${escapeHtml(t.name || t.slug || '—')}${
                        t.version ? ' <span class="wp-theme__version">v' + escapeHtml(t.version) + '</span>' : ''
                    }</span>
                </div>
                ${t.author ? '<div class="wp-theme__author">Автор: ' + escapeHtml(t.author) + '</div>' : ''}
                ${t.description ? '<p class="wp-theme__desc">' + escapeHtml(t.description) + '</p>' : ''}
                <div class="wp-theme__slug">Slug: <code>${escapeHtml(t.slug || '')}</code></div>
            </div>`);
        }

        // Розширення (компоненти, модулі, плагіни)
        if (Array.isArray(j.extensions) && j.extensions.length > 0) {
            const extList = j.extensions.map((e) => `
                <div class="wp-plugin">
                    <span class="wp-plugin__name">${escapeHtml(e.name)}${
                        e.version ? ' <span class="wp-plugin__version">v' + escapeHtml(e.version) + '</span>' : ''
                    }</span>
                </div>
            `).join('');
            parts.push(`<div class="wp-plugins"><h4 class="wp-plugins__title">Виявлені розширення (${j.extensions.length}):</h4><div class="wp-plugins__list">${extList}</div></div>`);
        }

        if (j.note) {
            parts.push('<p class="wp-note">' + escapeHtml(j.note) + '</p>');
        }

        // Адмінка
        if (j.admin_url) {
            const ad = j.admin_url;
            if (ad.is_hidden) {
                parts.push(`<div class="wp-login wp-login--hidden">
                    <span class="wp-login__label">Адмін-панель</span>
                    <span class="wp-login__badge wp-login__badge--hidden">приховано</span>
                    <div class="wp-login__note">${escapeHtml(ad.note || '')}</div>
                </div>`);
            } else if (ad.url) {
                parts.push(`<div class="wp-login">
                    <span class="wp-login__label">Адмін-панель</span>
                    <a class="wp-login__url" href="${escapeHtml(ad.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ad.url)}</a>
                    <span class="wp-login__badge">стандартна</span>
                    ${ad.note ? `<div class="wp-login__note">${escapeHtml(ad.note)}</div>` : ''}
                </div>`);
            }
        }

        return parts.join('');
    };

    const renderDrupal = (d) => {
        if (!d) return '';
        const parts = [];

        // Версія ядра
        if (d.version) {
            const sourceLabels = {
                changelog: 'файл <em>/core/CHANGELOG.txt</em>',
                'meta-generator': 'мета-тег generator',
                'header-x-generator': 'заголовок <em>X-Generator</em>',
            };
            const sourceHtml = sourceLabels[d.version_source]
                ? ` <span class="wp-version__source">(${sourceLabels[d.version_source]})</span>`
                : '';
            parts.push(`<div class="wp-version">
                <span class="wp-version__label">Версія Drupal:</span>
                <span class="wp-version__value">${escapeHtml(d.version)}</span>${sourceHtml}
                ${d.version_note ? `<div class="wp-version__note">${escapeHtml(d.version_note)}</div>` : ''}
            </div>`);
        } else if (d.theme || (Array.isArray(d.modules) && d.modules.length)) {
            parts.push(`<div class="wp-version wp-version--hidden">
                <span class="wp-version__label">Версія Drupal:</span>
                <span class="wp-version__value">прихована</span>
            </div>`);
        }

        // Активна тема
        if (d.theme) {
            const t = d.theme;
            parts.push(`<div class="wp-theme">
                <div class="wp-theme__heading">
                    <span class="wp-theme__label">Активна тема</span>
                    <span class="wp-theme__name">${escapeHtml(t.name || t.slug || '—')}${
                        t.version ? ' <span class="wp-theme__version">v' + escapeHtml(t.version) + '</span>' : ''
                    }</span>
                </div>
                <div class="wp-theme__slug">Slug: <code>${escapeHtml(t.slug || '')}</code></div>
            </div>`);
        }

        // Модулі
        if (Array.isArray(d.modules) && d.modules.length > 0) {
            const modList = d.modules.map((mm) => `
                <div class="wp-plugin">
                    <span class="wp-plugin__name">${escapeHtml(mm.name)}</span>
                </div>
            `).join('');
            parts.push(`<div class="wp-plugins"><h4 class="wp-plugins__title">Виявлені модулі (${d.modules.length}):</h4><div class="wp-plugins__list">${modList}</div></div>`);
        }

        if (d.note) {
            parts.push('<p class="wp-note">' + escapeHtml(d.note) + '</p>');
        }

        // Вхід
        if (d.login_url) {
            const li = d.login_url;
            if (li.is_hidden) {
                parts.push(`<div class="wp-login wp-login--hidden">
                    <span class="wp-login__label">Адмін-панель</span>
                    <span class="wp-login__badge wp-login__badge--hidden">приховано</span>
                    <div class="wp-login__note">${escapeHtml(li.note || '')}</div>
                </div>`);
            } else if (li.url) {
                parts.push(`<div class="wp-login">
                    <span class="wp-login__label">Адмін-панель</span>
                    <a class="wp-login__url" href="${escapeHtml(li.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(li.url)}</a>
                    <span class="wp-login__badge">стандартна</span>
                    ${li.note ? `<div class="wp-login__note">${escapeHtml(li.note)}</div>` : ''}
                </div>`);
            }
        }

        return parts.join('');
    };

    const renderSiteInfo = (site) => {
        const data = {};
        if (site.title) data['Заголовок'] = site.title;
        if (site.description) data['Опис'] = site.description;
        if (site.generator) data['Генератор'] = site.generator;
        return renderDefinitions(data);
    };

    /* ------------------------- Card helpers ------------------------- */
    const findCard = (key) => resultsContent.querySelector(`[data-card="${key}"]`);

    const addCard = (key, opts) => {
        if (findCard(key)) return findCard(key);
        const card = document.createElement('section');
        card.className = 'card' + (opts.full ? ' card--full' : '');
        card.setAttribute('data-card', key);
        card.innerHTML = `
            <header class="card__header">
                <span class="card__icon" aria-hidden="true">${opts.icon}</span>
                <h3 class="card__title">${escapeHtml(opts.title)}</h3>
                <span class="card__count">${opts.count || ''}</span>
            </header>
            <div class="card__body">${opts.body || ''}</div>
        `;
        resultsContent.appendChild(card);
        return card;
    };

    const updateCard = (key, { icon, title, count, body, full }) => {
        const card = findCard(key);
        if (!card) {
            addCard(key, { icon, title, count, body, full });
            return;
        }
        if (typeof count !== 'undefined') {
            const c = card.querySelector('.card__count');
            if (c) c.textContent = count;
        }
        if (typeof body !== 'undefined') {
            const b = card.querySelector('.card__body');
            if (b) b.innerHTML = body;
        }
    };

    /* ------------------------- Section renderers -------------------- */
    const cardMeta = {
        location:   { icon: '🌍', title: 'Місцезнаходження' },
        hosting:    { icon: '🏢', title: 'Хостинг-провайдер' },
        whois:      { icon: '📋', title: 'WHOIS-інформація' },
        cms:        { icon: '⚙️', title: 'Система керування (CMS)', full: true },
        frameworks: { icon: '🧩', title: 'Фреймворки' },
        server:     { icon: '🖥️', title: 'Веб-сервер', full: true },
        pagespeed:  { icon: '⚡', title: 'PageSpeed', full: true },
    };

    const renderServer = (data) => {
        if (!data) return '<p class="empty">Інформацію не знайдено</p>';
        const parts = [];
        const rows = [];

        // 1. веб-сервер
        const name = (data.name && data.name !== 'невідомо') ? data.name : (data.raw || 'невідомо');
        let serverLabel = data.version ? escapeHtml(name) + ' / ' + escapeHtml(data.version) : escapeHtml(name);
        if (data.server_modules && typeof data.server_modules === 'object') {
            const mods = Object.entries(data.server_modules).map(([k, v]) => escapeHtml(k) + (v ? '/' + escapeHtml(v) : '')).join(', ');
            if (mods) serverLabel += ' <em>(' + mods + ')</em>';
        }
        rows.push('<dt class="defs__term">Веб-сервер</dt><dd class="defs__def">' + serverLabel + '</dd>');

        // 1b. протокол (реальний факт про стек: HTTP/1.1 vs HTTP/2)
        if (data.http_version) {
            rows.push('<dt class="defs__term">Протокол</dt><dd class="defs__def">' + escapeHtml(data.http_version) + '</dd>');
        }

        // 2. Node.js
        if (data.node_present) {
            const v = data.node_version ? 'v' + escapeHtml(data.node_version) + (data.node_source ? ' <em>(' + escapeHtml(data.node_source) + ')</em>' : '') : 'присутній (версія прихована)';
            rows.push('<dt class="defs__term">Node.js</dt><dd class="defs__def">' + v + '</dd>');
        } else {
            rows.push('<dt class="defs__term">Node.js</dt><dd class="defs__def"><span class="empty" style="padding:0;font-style:normal">не виявлено</span></dd>');
        }

        // 3. PHP
        if (data.php_version) {
            rows.push('<dt class="defs__term">PHP</dt><dd class="defs__def"><code>PHP/' + escapeHtml(data.php_version) + '</code> <em>(' + escapeHtml(data.php_version_source || 'X-Powered-By') + ')</em></dd>');
        } else if (data.php_present) {
            rows.push('<dt class="defs__term">PHP</dt><dd class="defs__def">присутній (версія прихована)' + (data.php_source ? ' <em>(' + escapeHtml(data.php_source) + ')</em>' : '') + '</dd>');
        } else if (data.powered_by && /php/i.test(data.powered_by)) {
            rows.push('<dt class="defs__term">PHP</dt><dd class="defs__def">присутній (версія прихована)</dd>');
        } else {
            rows.push('<dt class="defs__term">PHP</dt><dd class="defs__def"><span class="empty" style="padding:0;font-style:normal">не виявлено</span></dd>');
        }

        // 4. Python
        if (data.python_present) {
            const v = data.python_version ? 'v' + escapeHtml(data.python_version) + (data.python_source ? ' <em>(' + escapeHtml(data.python_source) + ')</em>' : '') : 'присутній (версія прихована)';
            rows.push('<dt class="defs__term">Python</dt><dd class="defs__def">' + v + '</dd>');
        } else {
            rows.push('<dt class="defs__term">Python</dt><dd class="defs__def"><span class="empty" style="padding:0;font-style:normal">не виявлено</span></dd>');
        }

        // 5. CDN
        if (data.cdn_provider) {
            rows.push('<dt class="defs__term">CDN</dt><dd class="defs__def">' + escapeHtml(data.cdn_provider) + (data.cdn_detection ? ' <em>(' + escapeHtml(data.cdn_detection) + ')</em>' : '') + '</dd>');
        } else {
            rows.push('<dt class="defs__term">CDN</dt><dd class="defs__def"><span class="empty" style="padding:0;font-style:normal">не виявлено</span></dd>');
        }

        // 6. База даних
        if (data.dbms) {
            const dbVer = data.db_version ? ' v' + escapeHtml(data.db_version) : '';
            const dbSrc = data.db_source ? ' <em>(' + escapeHtml(data.db_source) + ')</em>' : '';
            rows.push('<dt class="defs__term">База даних</dt><dd class="defs__def">' + escapeHtml(data.dbms) + dbVer + dbSrc + '</dd>');
        } else {
            rows.push('<dt class="defs__term">База даних</dt><dd class="defs__def"><span class="empty" style="padding:0;font-style:normal">не виявлено</span></dd>');
        }

        parts.push('<dl class="defs">' + rows.join('') + '</dl>');

        // Докази проксі/бекенда, коли Server приховано або за CDN.
        if (data.via) {
            parts.push('<div class="server-note">Via: ' + escapeHtml(data.via) + '</div>');
        }
        if (data.x_server) {
            parts.push('<div class="server-note">' + escapeHtml(data.x_server) + '</div>');
        }

        if (data.note) {
            parts.push('<div class="server-note">' + escapeHtml(data.note) + '</div>');
        }
        if (data.db_note && data.db_note !== data.note) {
            parts.push('<div class="server-note">' + escapeHtml(data.db_note) + '</div>');
        }

        return parts.join('');
    };

    const renderCms = (items) => {
        if (!items || items.length === 0) return '<p class="empty">Не виявлено</p>';
        return `<div class="tech-list">${items.map(item => {
            const confidence = (item.confidence || 'medium').toLowerCase();
            const tagHtml = `<span class="tech-item__tag tech-item__tag--${confidence}">${escapeHtml(confidence)}</span>`;
            let wpHtml = '';
            if (item.wordpress) {
                wpHtml = '<div class="wp-inline">' + renderWordPress(item.wordpress) + '</div>';
            }
            let joomlaHtml = '';
            if (item.joomla) {
                joomlaHtml = '<div class="wp-inline">' + renderJoomla(item.joomla) + '</div>';
            }
            let drupalHtml = '';
            if (item.drupal) {
                drupalHtml = '<div class="wp-inline">' + renderDrupal(item.drupal) + '</div>';
            }
            return `
                <div class="tech-item">
                    <div class="tech-item__head">
                        <span class="tech-item__name">${escapeHtml(item.name)}</span>
                        ${tagHtml}
                    </div>
                    ${item.description ? `<p class="tech-item__desc">${escapeHtml(item.description)}</p>` : ''}
                    ${item.site ? `<a class="tech-item__link" href="${escapeHtml(item.site)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.site)} →</a>` : ''}
                    ${wpHtml}
                    ${joomlaHtml}
                    ${drupalHtml}
                </div>
            `;
        }).join('')}</div>`;
    };

    const renderPagespeed = (data) => {
        if (!data) return '<p class="empty">Інформацію не знайдено</p>';
        if (data.error && !data.mobile && !data.desktop) {
            return `<p class="empty">${escapeHtml(data.error)}</p>`
                + (data.tested_url ? `<div class="server-note">${escapeHtml(data.tested_url)}</div>` : '');
        }
        const scoreClass = (v) => {
            if (v === null || v === undefined) return 'psi-score--na';
            if (v >= 90) return 'psi-score--good';
            if (v >= 50) return 'psi-score--avg';
            return 'psi-score--bad';
        };
        const renderPanel = (title, d) => {
            if (!d) return '';
            if (d.error) {
                return `<div class="psi-panel"><h4 class="psi-panel__title">${escapeHtml(title)}</h4>`
                    + `<p class="empty">${escapeHtml(d.error)}</p></div>`;
            }
            const panelScores = [
                ['Продуктивність', d.performance],
                ['Доступність', d.accessibility],
                ['Практики', d.best_practices],
                ['SEO', d.seo],
            ];
            const panelScoresHtml = `<div class="psi-scores">${panelScores.map(([label, v]) => `
                <div class="psi-score ${scoreClass(v)}">
                    <span class="psi-score__value">${(v === null || v === undefined) ? '—' : v}</span>
                    <span class="psi-score__label">${escapeHtml(label)}</span>
                </div>`).join('')}</div>`;
            const panelMetrics = d.metrics || {};
            const panelRows = Object.entries(metricLabels).map(([key, label]) => {
                const m = panelMetrics[key];
                if (!m) return '';
                const val = m.display || (m.value !== null && m.value !== undefined ? String(m.value) : '—');
                return `<dt class="defs__term">${escapeHtml(key)}</dt><dd class="defs__def">${escapeHtml(val)} <em>(${escapeHtml(label)})</em></dd>`;
            }).join('');
            const panelField = d.field_category
                ? `<dl class="defs"><dt class="defs__term">Польові дані</dt><dd class="defs__def">${escapeHtml(d.field_category)}</dd></dl>`
                : '';
            return `<div class="psi-panel"><h4 class="psi-panel__title">${escapeHtml(title)}</h4>`
                + panelScoresHtml
                + (panelRows ? `<dl class="defs psi-metrics">${panelRows}</dl>` : '')
                + panelField + `</div>`;
        };
        const metricLabels = {
            FCP: 'First Contentful Paint',
            LCP: 'Largest Contentful Paint',
            TBT: 'Total Blocking Time',
            CLS: 'Cumulative Layout Shift',
            SI: 'Speed Index',
            TTI: 'Time to Interactive',
        };
        const strategyNote = `<div class="server-note">Lighthouse · ${escapeHtml(data.tested_url || '')}</div>`
            + (data.key_fallback ? `<div class="server-note">Ключ API обмежено HTTP-referrer’ами — показано результат без ключа (низька квота). Зніміть обмеження ключа: Application restrictions = None.</div>` : '');
        return `<div class="psi-cols">${renderPanel('📱 Mobile', data.mobile)}${renderPanel('🖥️ Desktop', data.desktop)}</div>`
            + strategyNote;
    };

    const renderSection = (name, data) => {
        const meta = cardMeta[name];
        if (!meta) return;

        if (name === 'cms') {
            const count = Array.isArray(data) ? data.length : 0;
            updateCard(name, { ...meta, count: count, body: renderCms(data) });
            return;
        }
        if (name === 'frameworks') {
            updateCard(name, { ...meta, count: data.length, body: renderTags(data) });
            return;
        }
        if (name === 'server') {
            // Кількість рядків динамічна (базові 6 + протокол/Via за наявності)
            const body = renderServer(data);
            const rowCount = (body.match(/defs__term/g) || []).length || 6;
            updateCard('server', { ...meta, count: rowCount, body: body });
            return;
        }
        if (name === 'pagespeed') {
            const body = renderPagespeed(data);
            const hasError = !!(data && (data.error || (data.mobile && data.mobile.error) || (data.desktop && data.desktop.error)));
            updateCard('pagespeed', { ...meta, count: hasError ? '!' : 'mobile + desktop', body: body });
            return;
        }
        // location, hosting, whois — це key-value definitions
        updateCard(name, { ...meta, count: Object.keys(data || {}).length, body: renderDefinitions(data) });
    };

    /* ------------------------- EventSource -------------------------- */
    const closeStream = () => {
        if (eventSource) {
            try { eventSource.close(); } catch (e) { /* noop */ }
            eventSource = null;
        }
        if (psiSource) {
            try { psiSource.close(); } catch (e) { /* noop */ }
            psiSource = null;
        }
    };

    const startStream = (url, force = false) => {
        closeStream();

        if (typeof EventSource === 'undefined') {
            showError('Ваш браузер не підтримує EventSource. Скористайтесь сучасним браузером.');
            setLoading(false);
            return;
        }

        // Скидаємо стан результатів
        lastResult = {
            input: url,
            domain: '',
            url: '',
            ip: null,
            checked_at: null,
            sections: {},
        };
        fromCache = false;
        hideCachedBadge();
        resultsContent.innerHTML = '';
        resultsDomain.textContent = 'Аналіз…';
        resultsTitle.textContent = '';
        resultsIp.textContent = '…';
        resultsDate.textContent = '…';
        if (pdfBtn) pdfBtn.disabled = true;
        if (progressBlock) progressBlock.hidden = false;
        resetProgress();
        setStepState('meta', 'active');
        results.hidden = false;
        hideError();

        const params = 'url=' + encodeURIComponent(url)
            + (force ? '&force=1' : '')
            + '&csrf_token=' + encodeURIComponent(csrfField ? csrfField.value : '')
            + '&hp=' + encodeURIComponent(honeypotField ? honeypotField.value : '')
            + '&js=' + encodeURIComponent(jsTokenField ? jsTokenField.value : '')
            + '&ts=' + encodeURIComponent(formLoadedAtField ? formLoadedAtField.value : '');
        const es = new EventSource('api/stream.php?' + params + '&skip=pagespeed');
        eventSource = es;
        // PageSpeed — окремий паралельний стрім: Lighthouse думає 10–120 с,
        // і не повинен затримувати швидкі блоки основного стріму.
        const psi = new EventSource('api/stream.php?' + params + '&only=pagespeed');
        psiSource = psi;

        let sectionsRendered = 0;
        let cachedAt = null;
        let serverErrorShown = false;
        let pendingMain = true;
        let pendingPsi = true;

        const finishIfDone = () => {
            if (!pendingMain && !pendingPsi) {
                setLoading(false);
            }
        };
        const closePsi = () => {
            if (psiSource) {
                try { psiSource.close(); } catch (e) { /* noop */ }
                psiSource = null;
            }
        };

        const onMessage = (eventName, tag) => (e) => {
            let payload = null;
            try { payload = JSON.parse(e.data); } catch (err) { payload = null; }

            switch (eventName) {
                case 'cached':
                    fromCache = true;
                    if (payload && payload.cached_at) {
                        cachedAt = payload.cached_at;
                    }
                    break;

                case 'meta':
                    markStepDone('meta');
                    markActiveStep('location');
                    if (payload) {
                        lastResult.domain = payload.domain || lastResult.domain;
                        lastResult.url = payload.url || lastResult.url;
                        lastResult.ip = payload.ip || null;
                        lastResult.checked_at = payload.checked_at || lastResult.checked_at;
                        resultsDomain.textContent = lastResult.domain;
                        resultsTitle.textContent = lastResult.url;
                        resultsIp.textContent = lastResult.ip || '—';
                        resultsDate.textContent = formatDateTime(lastResult.checked_at);
                    }
                    break;

                case 'location':
                case 'hosting':
                case 'whois':
                case 'cms':
                case 'frameworks':
                case 'server':
                case 'pagespeed':
                    sectionsRendered++;
                    markStepDone(eventName);
                    const order = ['meta', 'location', 'hosting', 'whois', 'cms', 'frameworks', 'server', 'pagespeed'];
                    const nextIdx = order.indexOf(eventName) + 1;
                    if (nextIdx < order.length) {
                        markActiveStep(order[nextIdx]);
                    }
                    if (payload !== null) {
                        lastResult.sections[eventName] = payload;
                        renderSection(eventName, payload);
                    }
                    break;

                case 'complete':
                    if (tag === 'psi') {
                        // Не затираємо основний результат — лише домерджуємо PageSpeed.
                        if (payload && payload.sections && payload.sections.pagespeed && lastResult && lastResult.sections) {
                            lastResult.sections.pagespeed = payload.sections.pagespeed;
                        }
                        markStepDone('pagespeed');
                        pendingPsi = false;
                        closePsi();
                        finishIfDone();
                    } else {
                        if (payload && payload.sections) {
                            // Зберігаємо PageSpeed, якщо він уже прийшов паралельним стрімом.
                            const keepPsi = lastResult && lastResult.sections ? lastResult.sections.pagespeed : undefined;
                            lastResult = payload;
                            if (keepPsi !== undefined && lastResult.sections && !lastResult.sections.pagespeed) {
                                lastResult.sections.pagespeed = keepPsi;
                            }
                        } else if (payload && payload.data) {
                            lastResult = payload.data;
                        }
                        ['meta', 'location', 'hosting', 'whois', 'cms', 'frameworks', 'server'].forEach(markStepDone);
                        if (pdfBtn) pdfBtn.disabled = false;
                        if (fromCache) {
                            showCachedBadge(cachedAt || (payload && payload.checked_at) || null);
                        } else {
                            hideCachedBadge();
                        }
                        pendingMain = false;
                        try { es.close(); } catch (e) { /* noop */ }
                        eventSource = null;
                        finishIfDone();
                    }
                    break;

                case 'error':
                    if (tag === 'psi') {
                        // Помилка PageSpeed не валить весь аналіз — показуємо її в картці.
                        const errData = { error: (payload && payload.error) || 'Сталася помилка PageSpeed', tested_url: (lastResult && lastResult.url) || lastUrl || '' };
                        if (lastResult && lastResult.sections) {
                            lastResult.sections.pagespeed = errData;
                        }
                        renderSection('pagespeed', errData);
                        markStepDone('pagespeed');
                        pendingPsi = false;
                        closePsi();
                        finishIfDone();
                    } else {
                        serverErrorShown = true;
                        ['meta', 'location', 'hosting', 'whois', 'cms', 'frameworks', 'server', 'pagespeed'].forEach(markStepDone);
                        pendingMain = false;
                        pendingPsi = false;
                        closePsi();
                        try { es.close(); } catch (e) { /* noop */ }
                        eventSource = null;
                        setLoading(false);
                        showError((payload && payload.error) || 'Сталася помилка під час аналізу');
                    }
                    break;
            }
        };

        // реєструємо обробники для кожної події
        ['cached', 'meta', 'location', 'hosting', 'whois', 'cms', 'frameworks', 'server', 'complete', 'error'].forEach((name) => {
            es.addEventListener(name, onMessage(name, 'main'));
        });
        ['cached', 'pagespeed', 'complete', 'error'].forEach((name) => {
            psi.addEventListener(name, onMessage(name, 'psi'));
        });

        es.onerror = () => {
            if (es.readyState === EventSource.CLOSED && pendingMain) {
                if (!serverErrorShown && lastResult && (!lastResult.sections || Object.keys(lastResult.sections).length === 0)) {
                    showError('З\'єднання з сервером перервано. Спробуйте пізніше.');
                }
                pendingMain = false;
                try { es.close(); } catch (e) { /* noop */ }
                eventSource = null;
                finishIfDone();
            }
        };

        psi.onerror = () => {
            if (psi.readyState === EventSource.CLOSED && pendingPsi) {
                if (!lastResult.sections || !lastResult.sections.pagespeed) {
                    const errData = { error: 'Не вдалося завантажити PageSpeed. Спробуйте оновити.', tested_url: (lastResult && lastResult.url) || lastUrl || '' };
                    lastResult.sections.pagespeed = errData;
                    renderSection('pagespeed', errData);
                }
                markStepDone('pagespeed');
                pendingPsi = false;
                closePsi();
                finishIfDone();
            }
        };
    };

    /* ------------------------- Submit handler ----------------------- */
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const validation = validateUrl(input.value);
        if (!validation.ok) {
            input.classList.add('form__input--invalid');
            showError(validation.msg);
            input.focus();
            return;
        }

        input.classList.remove('form__input--invalid');
        lastUrl = validation.value;
        setLoading(true);
        hideError();
        startStream(validation.value, false);
    });

    /* ------------------------- Refresh button ----------------------- */
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            if (!lastUrl) {
                // Якщо ще не було аналізу, просто повторюємо submit форми
                if (typeof form.requestSubmit === 'function') {
                    form.requestSubmit();
                } else {
                    form.dispatchEvent(new Event('submit', { cancelable: true }));
                }
                return;
            }
            // Примусово оновлюємо з поточним URL, ігноруючи кеш
            const url = input.value && input.value.trim() ? input.value.trim() : lastUrl;
            const validation = validateUrl(url);
            if (!validation.ok) {
                showError(validation.msg);
                return;
            }
            lastUrl = validation.value;
            input.value = validation.value;
            setLoading(true);
            hideError();
            startStream(validation.value, true);
        });
    }

    input.addEventListener('input', () => {
        input.classList.remove('form__input--invalid');
        hideError();
    });

    /* ------------------------- Example chips ------------------------ */
    document.querySelectorAll('.form__example').forEach((chip) => {
        chip.addEventListener('click', () => {
            input.value = chip.dataset.example || '';
            input.focus();
        });
    });

    /* ------------------------- PDF export --------------------------- */
    const waitForJsPdf = () => new Promise((resolve) => {
        if (window.jspdf && window.jspdf.jsPDF) {
            resolve(window.jspdf.jsPDF);
            return;
        }
        let attempts = 0;
        const interval = setInterval(() => {
            attempts++;
            if (window.jspdf && window.jspdf.jsPDF) {
                clearInterval(interval);
                resolve(window.jspdf.jsPDF);
            } else if (attempts > 40) {
                clearInterval(interval);
                resolve(null);
            }
        }, 100);
    });

    const FONT_BASE = 'assets/fonts';
    const FONT_REGULAR = 'PTSans-Regular.ttf';
    const FONT_BOLD = 'PTSans-Bold.ttf';
    const FONT_FAMILY = 'PTSans';
    const fontCache = { regular: null, bold: null };

    const arrayBufferToBase64 = (buffer) => {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(
                null,
                bytes.subarray(i, i + chunkSize),
            );
        }
        return btoa(binary);
    };

    const loadFontBase64 = async (filename, cacheKey) => {
        if (fontCache[cacheKey]) return fontCache[cacheKey];
        const res = await fetch(`${FONT_BASE}/${filename}`);
        if (!res.ok) throw new Error(`Не вдалося завантажити шрифт: ${filename}`);
        const buffer = await res.arrayBuffer();
        const base64 = arrayBufferToBase64(buffer);
        fontCache[cacheKey] = base64;
        return base64;
    };

    const loadPdfFonts = async () => {
        const [regular, bold] = await Promise.all([
            loadFontBase64(FONT_REGULAR, 'regular'),
            loadFontBase64(FONT_BOLD, 'bold'),
        ]);
        return { regular, bold };
    };

    const buildPdf = async () => {
        if (!lastResult) {
            alert('Спочатку виконайте перевірку сайту');
            return;
        }

        const JsPDF = await waitForJsPdf();
        if (!JsPDF) {
            alert('Бібліотека PDF не завантажилась. Перевірте з\'єднання з інтернетом.');
            return;
        }

        let fonts;
        try {
            fonts = await loadPdfFonts();
        } catch (err) {
            console.error(err);
            alert('Не вдалося завантажити шрифти для PDF. Спробуйте пізніше.');
            return;
        }

        const doc = new JsPDF({ unit: 'pt', format: 'a4' });
        doc.addFileToVFS('PTSans-Regular.ttf', fonts.regular);
        doc.addFont('PTSans-Regular.ttf', FONT_FAMILY, 'normal');
        doc.addFileToVFS('PTSans-Bold.ttf', fonts.bold);
        doc.addFont('PTSans-Bold.ttf', FONT_FAMILY, 'bold');

        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();
        const margin = 40;
        const maxWidth = pageWidth - margin * 2;
        let y = margin;

        const checkPageBreak = (needed = 20) => {
            if (y + needed > pageHeight - margin) {
                doc.addPage();
                y = margin;
            }
        };

        const setText = (size, style, color) => {
            doc.setFontSize(size);
            doc.setFont(FONT_FAMILY, style);
            const [r, g, b] = color || [31, 17, 71];
            doc.setTextColor(r, g, b);
        };

        const writeWrapped = (text, size = 10, style = 'normal', color = [31, 17, 71]) => {
            setText(size, style, color);
            const lines = doc.splitTextToSize(String(text), maxWidth);
            lines.forEach((line) => {
                checkPageBreak(size * 1.4);
                doc.text(line, margin, y);
                y += size * 1.35;
            });
        };

        const writePair = (label, value) => {
            setText(10, 'normal', [91, 87, 120]);
            const labelWidth = 130;
            const labelLines = doc.splitTextToSize(label, labelWidth);
            labelLines.forEach((line) => {
                checkPageBreak(15);
                doc.text(line, margin, y);
                y += 14;
            });

            setText(10, 'normal', [31, 17, 71]);
            const valueLines = doc.splitTextToSize(String(value), maxWidth - labelWidth - 10);
            const startY = y - labelLines.length * 14;
            valueLines.forEach((line, idx) => {
                checkPageBreak(14);
                doc.text(line, margin + labelWidth + 10, startY + idx * 14);
            });
            y = Math.max(y, startY + valueLines.length * 14) + 4;
        };

        /* ----- Header ----- */
        doc.setFillColor(109, 40, 217);
        doc.rect(0, 0, pageWidth, 70, 'F');
        setText(20, 'bold', [255, 255, 255]);
        doc.text('MP Site Detect', margin, 32);
        setText(11, 'normal', [255, 255, 255]);
        doc.text('Звіт аналізу сайту', margin, 52);

        y = 100;
        writeWrapped(lastResult.domain, 18, 'bold', [31, 17, 71]);
        writeWrapped(`URL: ${lastResult.url}`, 10, 'normal', [91, 87, 120]);
        writeWrapped(`IP-адреса: ${lastResult.ip || '—'}`, 10, 'normal', [91, 87, 120]);
        writeWrapped(`Дата перевірки: ${formatDateTime(lastResult.checked_at)}`, 10, 'normal', [91, 87, 120]);
        y += 8;

        /* ----- Section helper ----- */
        const renderSection = (title, items, isList = false) => {
            if (!items) return;
            if (isList && items.length === 0) return;
            if (!isList && Object.keys(items).length === 0) return;

            checkPageBreak(40);
            doc.setDrawColor(229, 225, 245);
            doc.line(margin, y, pageWidth - margin, y);
            y += 16;
            writeWrapped(title, 13, 'bold', [109, 40, 217]);
            y += 4;

            if (isList) {
                items.forEach((item) => {
                    checkPageBreak(30);
                    setText(11, 'bold', [31, 17, 71]);
                    doc.text(`• ${item.name}`, margin, y);
                    y += 16;
                    if (item.description) {
                        writeWrapped(item.description, 9, 'normal', [91, 87, 120]);
                    }
                    if (item.category) {
                        writeWrapped(`Категорія: ${item.category}`, 9, 'normal', [139, 136, 163]);
                    }
                    if (item.confidence) {
                        writeWrapped(`Впевненість: ${item.confidence}`, 9, 'normal', [139, 136, 163]);
                    }
                    y += 6;
                });
            } else {
                Object.entries(items).forEach(([k, v]) => {
                    writePair(k, v);
                });
                y += 6;
            }
        };

        const sections = lastResult.sections || {};
        renderSection('Місцезнаходження', sections.location);
        renderSection('Хостинг-провайдер', sections.hosting);
        renderSection('WHOIS-інформація', sections.whois);
        // CMS — якщо є WordPress, його деталі вже всередині елемента cms
        if (sections.cms) {
            checkPageBreak(40);
            doc.setDrawColor(229, 225, 245);
            doc.line(margin, y, pageWidth - margin, y);
            y += 16;
            writeWrapped('Система керування (CMS)', 13, 'bold', [109, 40, 217]);
            y += 4;
            sections.cms.forEach((item) => {
                checkPageBreak(30);
                setText(11, 'bold', [31, 17, 71]);
                doc.text(`• ${item.name} (${item.confidence || 'medium'})`, margin, y);
                y += 16;
                if (item.description) writeWrapped(item.description, 9, 'normal', [91, 87, 120]);
                if (item.wordpress) {
                    const wp = item.wordpress;
                    if (wp.version) writeWrapped(`Версія WordPress: ${wp.version}`, 9, 'normal', [31, 17, 71]);
                    else if (wp.version_min) writeWrapped(`Версія WordPress: ≥ ${wp.version_min} (точна прихована)`, 9, 'normal', [31, 17, 71]);
                    if (wp.theme) writeWrapped(`Тема: ${wp.theme.name || wp.theme.slug || '—'}${wp.theme.version ? ' v' + wp.theme.version : ''}`, 9, 'normal', [91, 87, 120]);
                    if (wp.parent_theme) writeWrapped(`Parent-тема: ${wp.parent_theme.name || wp.parent_theme.slug}${wp.parent_theme.version ? ' v' + wp.parent_theme.version : ''}`, 9, 'normal', [91, 87, 120]);
                    if (Array.isArray(wp.page_builders) && wp.page_builders.length) writeWrapped(`Конструктори: ${wp.page_builders.map(pb=>pb.name).join(', ')}`, 9, 'normal', [91, 87, 120]);
                    if (wp.woocommerce && wp.woocommerce.active) writeWrapped(`WooCommerce: активний${wp.woocommerce.version ? ' v'+wp.woocommerce.version : ''}`, 9, 'normal', [91, 87, 120]);
                    if (Array.isArray(wp.plugins) && wp.plugins.length) {
                        writeWrapped(`Плагіни (${wp.plugins.length}): ${wp.plugins.map(p=>p.name + (p.version ? ' v'+p.version : '')).join(', ')}`, 9, 'normal', [91, 87, 120]);
                    }
                    if (wp.note) writeWrapped(wp.note, 8, 'normal', [139, 136, 163]);
                    if (wp.login_url) {
                        if (wp.login_url.is_hidden) writeWrapped('Адмін-панель: приховано — ' + (wp.login_url.note || ''), 9, 'normal', [139, 136, 163]);
                        else if (wp.login_url.url) writeWrapped(`Адмін-панель: ${wp.login_url.url}${wp.login_url.is_custom ? ' (кастомна)' : ' (стандартна)'}`, 9, 'normal', [91, 87, 120]);
                    }
                }
                if (item.joomla) {
                    const j = item.joomla;
                    if (j.version) writeWrapped(`Версія Joomla: ${j.version}`, 9, 'normal', [31, 17, 71]);
                    if (j.template) writeWrapped(`Шаблон: ${j.template.name || j.template.slug || '—'}${j.template.version ? ' v' + j.template.version : ''}`, 9, 'normal', [91, 87, 120]);
                    if (Array.isArray(j.extensions) && j.extensions.length) {
                        writeWrapped(`Розширення (${j.extensions.length}): ${j.extensions.map(e=>e.name + (e.version ? ' v'+e.version : '')).join(', ')}`, 9, 'normal', [91, 87, 120]);
                    }
                    if (j.admin_url) {
                        if (j.admin_url.is_hidden) writeWrapped('Адмін-панель: приховано', 9, 'normal', [139, 136, 163]);
                        else if (j.admin_url.url) writeWrapped(`Адмін-панель: ${j.admin_url.url} (стандартна)`, 9, 'normal', [91, 87, 120]);
                    }
                }
                if (item.drupal) {
                    const dd = item.drupal;
                    if (dd.version) writeWrapped(`Версія Drupal: ${dd.version}`, 9, 'normal', [31, 17, 71]);
                    if (dd.theme) writeWrapped(`Тема: ${dd.theme.name || dd.theme.slug || '—'}${dd.theme.version ? ' v' + dd.theme.version : ''}`, 9, 'normal', [91, 87, 120]);
                    if (Array.isArray(dd.modules) && dd.modules.length) {
                        writeWrapped(`Модулі (${dd.modules.length}): ${dd.modules.map(mm=>mm.name).join(', ')}`, 9, 'normal', [91, 87, 120]);
                    }
                    if (dd.login_url) {
                        if (dd.login_url.is_hidden) writeWrapped('Вхід: приховано', 9, 'normal', [139, 136, 163]);
                        else if (dd.login_url.url) writeWrapped(`Вхід: ${dd.login_url.url} (стандартна)`, 9, 'normal', [91, 87, 120]);
                    }
                }
                y += 4;
            });
            y += 6;
        }
        renderSection('Фреймворки', sections.frameworks, true);

        // Веб-сервер — єдина секція на всю ширину (6 рядків)
        if (sections.server) {
            const s = sections.server;
            checkPageBreak(40);
            doc.setDrawColor(229, 225, 245);
            doc.line(margin, y, pageWidth - margin, y);
            y += 16;
            writeWrapped('Веб-сервер', 13, 'bold', [109, 40, 217]);
            y += 4;
            writeWrapped(`Веб-сервер: ${(s.name || 'невідомо')}${s.version ? ' / ' + s.version : ''}`, 10, 'bold', [31, 17, 71]);
            if (s.server_modules && typeof s.server_modules === 'object') {
                const mods = Object.entries(s.server_modules).map(([k, v]) => k + (v ? '/' + v : '')).join(', ');
                if (mods) writeWrapped(`Модулі: ${mods}`, 9, 'normal', [31, 17, 71]);
            }
            if (s.http_version) {
                writeWrapped(`Протокол: ${s.http_version}`, 9, 'normal', [31, 17, 71]);
            }
            if (s.node_present) {
                writeWrapped(`Node.js: ${s.node_version ? 'v' + s.node_version + (s.node_source ? ' ('+s.node_source+')' : '') : 'присутній (версія прихована)'}`, 9, 'normal', [31, 17, 71]);
            } else {
                writeWrapped('Node.js: не виявлено', 9, 'normal', [139, 136, 163]);
            }
            if (s.php_version) {
                writeWrapped(`PHP: PHP/${s.php_version}${s.php_version_source ? ' ('+s.php_version_source+')' : ''}`, 9, 'normal', [31, 17, 71]);
            } else if (s.php_present) {
                writeWrapped(`PHP: присутній (версія прихована)${s.php_source ? ' ('+s.php_source+')' : ''}`, 9, 'normal', [31, 17, 71]);
            } else {
                writeWrapped('PHP: не виявлено', 9, 'normal', [139, 136, 163]);
            }
            if (s.python_present) {
                writeWrapped(`Python: ${s.python_version ? 'v' + s.python_version + (s.python_source ? ' ('+s.python_source+')' : '') : 'присутній (версія прихована)'}`, 9, 'normal', [31, 17, 71]);
            } else {
                writeWrapped('Python: не виявлено', 9, 'normal', [139, 136, 163]);
            }
            writeWrapped(`CDN: ${s.cdn_provider || 'не виявлено'}${s.cdn_detection ? ' ('+s.cdn_detection+')' : ''}`, 9, 'normal', [s.cdn_provider ? 31 : 139, s.cdn_provider ? 17 : 136, s.cdn_provider ? 71 : 163]);
            if (s.dbms) {
                writeWrapped(`База даних: ${s.dbms}${s.db_version ? ' v'+s.db_version : ''}${s.db_source ? ' ('+s.db_source+')' : ''}`, 9, 'normal', [31, 17, 71]);
            } else {
                writeWrapped('База даних: не виявлено', 9, 'normal', [139, 136, 163]);
            }
            if (s.note) writeWrapped(s.note, 9, 'italic', [139, 136, 163]);
            if (s.via) writeWrapped('Via: ' + s.via, 9, 'italic', [139, 136, 163]);
            if (s.x_server) writeWrapped(s.x_server, 9, 'italic', [139, 136, 163]);
            if (s.db_note && s.db_note !== s.note) writeWrapped(s.db_note, 9, 'italic', [139, 136, 163]);
            y += 6;
        }

        // PageSpeed Insights (Lighthouse mobile + desktop) — виключно покази PSI
        if (sections.pagespeed) {
            const p = sections.pagespeed;
            checkPageBreak(40);
            doc.setDrawColor(229, 225, 245);
            doc.line(margin, y, pageWidth - margin, y);
            y += 16;
            writeWrapped('PageSpeed', 13, 'bold', [109, 40, 217]);
            y += 4;
            if (p.error && !p.mobile && !p.desktop) {
                writeWrapped('Помилка: ' + p.error, 10, 'normal', [139, 136, 163]);
                if (p.tested_url) writeWrapped(p.tested_url, 9, 'normal', [139, 136, 163]);
            } else {
                [['Mobile', p.mobile], ['Desktop', p.desktop]].forEach(([label, s]) => {
                    if (!s) return;
                    if (s.error) {
                        writeWrapped(`${label}: помилка — ${s.error}`, 10, 'normal', [139, 136, 163]);
                        return;
                    }
                    const scoreLine = ['performance', 'accessibility', 'best_practices', 'seo']
                        .map((k) => `${k}: ${s[k] ?? '—'}`).join(' · ');
                    writeWrapped(`Бали (${label}): ${scoreLine}`, 10, 'bold', [31, 17, 71]);
                    if (s.metrics) {
                        Object.entries({ FCP: 'First Contentful Paint', LCP: 'Largest Contentful Paint', TBT: 'Total Blocking Time', CLS: 'Cumulative Layout Shift', SI: 'Speed Index', TTI: 'Time to Interactive' }).forEach(([k, lb]) => {
                            const m = s.metrics[k];
                            if (m) writeWrapped(`${label} ${k} (${lb}): ${m.display || m.value || '—'}`, 9, 'normal', [31, 17, 71]);
                        });
                    }
                    if (s.field_category) writeWrapped(`${label} польові дані (CrUX): ${s.field_category}`, 9, 'normal', [91, 87, 120]);
                });
                if (p.tested_url) writeWrapped(p.tested_url, 9, 'normal', [139, 136, 163]);
            }
            y += 6;
        }

        // Сумісність зі старими кешами — якщо раптом є окрема wordpress секція
        if (sections.wordpress && !sections.cms?.some(c=>c.wordpress)) {
            const wp = sections.wordpress;
            checkPageBreak(40);
            doc.setDrawColor(229, 225, 245);
            doc.line(margin, y, pageWidth - margin, y);
            y += 16;
            writeWrapped('WordPress: версія, тема, плагіни', 13, 'bold', [109, 40, 217]);
            y += 4;

            if (wp.version) {
                checkPageBreak(16);
                writeWrapped(`Версія WordPress: ${wp.version}`, 11, 'bold', [31, 17, 71]);
                y += 2;
            } else if (wp.version_min) {
                checkPageBreak(16);
                writeWrapped(`Версія WordPress: ≥ ${wp.version_min} (точна версія прихована)`, 11, 'bold', [31, 17, 71]);
                writeWrapped(wp.version_note || 'Мета-тег generator вимкнено, /readme.html заблоковано — визначено лише нижню межу.', 9, 'normal', [139, 136, 163]);
                y += 2;
            } else if (wp.theme || wp.parent_theme || (Array.isArray(wp.page_builders) && wp.page_builders.length) || (Array.isArray(wp.plugins) && wp.plugins.length)) {
                checkPageBreak(16);
                writeWrapped('Версія WordPress: прихована власником (мета-тег вимкнено, /readme.html заблоковано)', 10, 'normal', [139, 136, 163]);
                y += 2;
            }

            if (wp.theme) {
                const t = wp.theme;
                checkPageBreak(60);
                writeWrapped(`Активна тема: ${t.name || t.slug || '—'}` + (t.version ? ` (v${t.version})` : ''), 12, 'bold', [31, 17, 71]);
                if (t.slug) writeWrapped(`Slug: ${t.slug}`, 9, 'normal', [139, 136, 163]);
                if (t.author) writeWrapped(`Автор: ${t.author}`, 9, 'normal', [91, 87, 120]);
                if (t.homepage) writeWrapped(`Сторінка: ${t.homepage}`, 9, 'normal', [91, 87, 120]);
                y += 4;
            }

            if (wp.parent_theme) {
                const p = wp.parent_theme;
                checkPageBreak(40);
                writeWrapped(`Parent-тема: ${p.name || p.slug || '—'}` + (p.version ? ` (v${p.version})` : ''), 11, 'bold', [31, 17, 71]);
                if (p.slug) writeWrapped(`Slug: ${p.slug}`, 9, 'normal', [139, 136, 163]);
                if (p.author) writeWrapped(`Автор: ${p.author}`, 9, 'normal', [91, 87, 120]);
                y += 4;
            }

            if (Array.isArray(wp.page_builders) && wp.page_builders.length) {
                const methodLabels = { body_class: 'клас <body>', plugin: 'наявний плагін', html: 'HTML-розмітка' };
                const label = wp.page_builders.length > 1
                    ? `Конструктори сторінок (${wp.page_builders.length}):`
                    : 'Конструктор сторінок:';
                checkPageBreak(28);
                writeWrapped(label, 11, 'bold', [31, 17, 71]);
                wp.page_builders.forEach((pb) => {
                    const method = methodLabels[pb.detection] || pb.detection || '';
                    checkPageBreak(20);
                    setText(10, 'bold', [31, 17, 71]);
                    doc.text(`• ${pb.name}${method ? ' (' + method + ')' : ''}`, margin + 8, y);
                    y += 14;
                    if (pb.description) {
                        writeWrapped(pb.description, 9, 'normal', [91, 87, 120]);
                    }
                });
                y += 4;
            } else if (wp.page_builder) {
                // Зворотна сумісність зі старим форматом кешу
                const pb = wp.page_builder;
                const methodLabels = { body_class: 'клас <body>', plugin: 'наявний плагін', html: 'HTML-розмітка' };
                const method = methodLabels[pb.detection] || pb.detection || '';
                checkPageBreak(28);
                writeWrapped(`Конструктор сторінок: ${pb.name}${method ? ' (' + method + ')' : ''}`, 11, 'bold', [31, 17, 71]);
                if (pb.description) {
                    writeWrapped(pb.description, 9, 'normal', [91, 87, 120]);
                }
                y += 4;
            }

            if (wp.woocommerce && wp.woocommerce.active) {
                const woo = wp.woocommerce;
                checkPageBreak(40);
                writeWrapped('WooCommerce: активний' + (woo.version ? ` (v${woo.version})` : ''), 11, 'bold', [31, 17, 71]);
                if (Array.isArray(woo.payment_gateways) && woo.payment_gateways.length) {
                    writeWrapped(`Оплата: ${woo.payment_gateways.join(', ')}`, 9, 'normal', [91, 87, 120]);
                }
                if (Array.isArray(woo.shipping_modules) && woo.shipping_modules.length) {
                    writeWrapped(`Доставка: ${woo.shipping_modules.join(', ')}`, 9, 'normal', [91, 87, 120]);
                }
                const urls = woo.urls || {};
                const urlLabels = [];
                if (urls.shop) urlLabels.push('магазин');
                if (urls.cart) urlLabels.push('кошик');
                if (urls.checkout) urlLabels.push('оформлення');
                if (urls.my_account) urlLabels.push('особистий кабінет');
                if (urlLabels.length) {
                    writeWrapped('Сторінки: ' + urlLabels.join(', '), 9, 'normal', [91, 87, 120]);
                }
                y += 4;
            }

            if (Array.isArray(wp.plugins) && wp.plugins.length > 0) {
                checkPageBreak(30);
                writeWrapped(`Виявлені плагіни (${wp.plugins.length}):`, 11, 'bold', [31, 17, 71]);
                wp.plugins.forEach((p) => {
                    checkPageBreak(16);
                    setText(10, 'normal', [31, 17, 71]);
                    doc.text(`• ${p.name}${p.version ? ' (v' + p.version + ')' : ''}`, margin + 8, y);
                    y += 14;
                });
                y += 4;
            }

            if (wp.note) {
                writeWrapped(wp.note, 9, 'normal', [139, 136, 163]);
            }

            if (wp.login_url) {
                const li = wp.login_url;
                checkPageBreak(24);
                if (li.is_hidden) {
                    writeWrapped('Адмін-панель: приховано', 11, 'bold', [31, 17, 71]);
                    writeWrapped(li.note || 'Адреса за замовчуванням входу в адмін-панель була змінена власником сайту.', 9, 'normal', [139, 136, 163]);
                } else if (li.url) {
                    const label = li.is_custom ? 'Адмін-панель (кастомна): ' : 'Адмін-панель: ';
                    writeWrapped(label + li.url, 10, 'bold', [31, 17, 71]);
                    if (li.note) writeWrapped(li.note, 9, 'normal', [139, 136, 163]);
                }
                y += 4;
            }
        }

        /* ----- Footer on every page ----- */
        const totalPages = doc.internal.getNumberOfPages();
        for (let i = 1; i <= totalPages; i++) {
            doc.setPage(i);
            setText(8, 'normal', [139, 136, 163]);
            doc.text(`MP Site Detect — сторінка ${i} з ${totalPages}`, margin, pageHeight - 16);
            doc.text(`Згенеровано: ${formatDateTime(new Date().toISOString())}`, pageWidth - margin, pageHeight - 16, { align: 'right' });
        }

        const safeDomain = (lastResult.domain || 'site').replace(/[^a-z0-9.-]/gi, '_');
        const fileName = `mp-site-detect_${safeDomain}_${Date.now()}.pdf`;
        doc.save(fileName);
    };

    if (pdfBtn) {
        pdfBtn.addEventListener('click', () => {
            if (!lastResult || !lastResult.sections || Object.keys(lastResult.sections).length === 0) {
                alert('Спочатку дочекайтесь завершення аналізу');
                return;
            }
            pdfBtn.disabled = true;
            const span = pdfBtn.querySelector('span');
            const originalText = span ? span.textContent : 'Завантажити PDF';
            if (span) span.textContent = 'Генерація PDF…';
            buildPdf()
                .catch((err) => {
                    console.error(err);
                    alert('Не вдалося створити PDF: ' + err.message);
                })
                .finally(() => {
                    pdfBtn.disabled = false;
                    if (span) span.textContent = originalText;
                });
        });
    }

    /* ------------------------- Footer year -------------------------- */
    const yearEl = document.getElementById('year');
    if (yearEl) yearEl.textContent = new Date().getFullYear();
})();
