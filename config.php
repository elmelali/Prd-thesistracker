<?php

declare(strict_types=1);

return [
    'db' => [
        'host' => getenv('THESIS_DB_HOST') ?: '127.0.0.1',
        'port' => (int) (getenv('THESIS_DB_PORT') ?: 3306),
        'name' => getenv('THESIS_DB_NAME') ?: 'thesis_tracker',
        'user' => getenv('THESIS_DB_USER') ?: 'root',
        'pass' => getenv('THESIS_DB_PASS') ?: '',
        'charset' => 'utf8mb4',
    ],
    'auth' => [
        'password_hash' => getenv('THESIS_APP_PASSWORD_HASH') ?: '__SET_DURING_INSTALL__',
        'session_lifetime_seconds' => (int) (getenv('THESIS_SESSION_LIFETIME') ?: 8 * 60 * 60),
    ],
    'install' => [
        'enabled' => filter_var(getenv('THESIS_INSTALL_ENABLED') ?: 'true', FILTER_VALIDATE_BOOLEAN),
    ],
];
