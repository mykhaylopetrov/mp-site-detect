<?php

declare(strict_types=1);

/**
 * Приклад локальних налаштувань (безпечно комітити).
 * Скопіюйте цей файл у `config.php` і впишіть свій ключ:
 *   cp config.example.php config.php
 * Файл `config.php` ігнорується гітом (.gitignore) і ніколи не пушиться.
 */

if (!defined('PAGESPEED_API_KEY')) {
    define('PAGESPEED_API_KEY', '');
}
