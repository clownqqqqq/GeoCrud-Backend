<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    */

    'paths' => ['api/*', 'sanctum/csrf-cookie'],

    'allowed_methods' => ['*'],

    'allowed_origins' => [
        'https://clownqqqq.github.io',
        'https://clownqqqqq.github.io',
        'http://localhost:8000',
        'http://localhost:3000',
        'http://127.0.0.1:8000',
    ],

    'allowed_origins_patterns' => [
        'https://*.github.io',
    ],

    'allowed_headers' => ['*'],

    'exposed_headers' => ['*'],

    'max_age' => 86400,

    'supports_credentials' => true,

];

