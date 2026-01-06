<?php
/**
 * Safe OPcache Clear Script - Only Affects THIS Laravel App
 * 
 * Access this file via: https://geocrud.bytevortexz.com/clear-opcache.php
 * 
 * WARNING: Remove this file after use for security!
 */

header('Content-Type: text/plain');

echo "🔧 Clearing OPcache for THIS Laravel app only...\n\n";

// Method 1: Clear OPcache for specific files (safest - only affects this app)
if (function_exists('opcache_invalidate')) {
    $files = [
        __DIR__ . '/../app/Http/Middleware/ApiAuthMiddleware.php',
        __DIR__ . '/../app/Http/Controllers/AuthController.php',
        __DIR__ . '/../app/Http/Controllers/GisController.php',
        __DIR__ . '/../app/Http/Controllers/ProfileController.php',
    ];
    
    $cleared = 0;
    foreach ($files as $file) {
        if (file_exists($file)) {
            opcache_invalidate($file, true);
            echo "✅ Cleared OPcache for: " . basename($file) . "\n";
            $cleared++;
        }
    }
    
    if ($cleared > 0) {
        echo "\n✅ Cleared OPcache for {$cleared} files (only THIS app affected)\n";
    } else {
        echo "ℹ️ No files found to clear\n";
    }
} else {
    echo "ℹ️ opcache_invalidate() not available\n";
}

// Method 2: Clear Laravel caches (only affects this app)
if (file_exists(__DIR__ . '/../artisan')) {
    echo "\n📦 Clearing Laravel caches...\n";
    
    $commands = [
        'config:clear',
        'cache:clear',
        'route:clear',
        'view:clear'
    ];
    
    foreach ($commands as $cmd) {
        $output = [];
        $return = 0;
        exec('cd ' . escapeshellarg(__DIR__ . '/..') . ' && php artisan ' . $cmd . ' 2>&1', $output, $return);
        if ($return === 0) {
            echo "✅ {$cmd}\n";
        } else {
            echo "⚠️ {$cmd} - " . implode("\n", $output) . "\n";
        }
    }
}

echo "\n✅ Done! Only THIS Laravel app was affected.\n";
echo "⚠️ IMPORTANT: Delete this file after use for security!\n";

