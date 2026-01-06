<?php
/**
 * Force OPcache Reload - Most Aggressive Method
 * This script tries multiple methods to force OPcache to reload
 */

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Force OPcache Reload</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .success { color: #28a745; background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .error { color: #dc3545; background: #f8d7da; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .info { color: #0c5460; background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 10px 0; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Force OPcache Reload - Aggressive Method</h1>
        
        <?php
        $basePath = dirname(__DIR__);
        $files = [
            $basePath . '/app/Http/Middleware/ApiAuthMiddleware.php',
            $basePath . '/app/Http/Controllers/AuthController.php',
            $basePath . '/app/Http/Controllers/GisController.php',
            $basePath . '/app/Http/Controllers/ProfileController.php',
            $basePath . '/routes/api.php',
        ];

        echo '<div class="info">📋 Attempting multiple methods to force OPcache reload...</div>';

        $results = [];

        foreach ($files as $file) {
            if (!file_exists($file)) {
                $results[] = ['file' => basename($file), 'status' => 'not_found'];
                continue;
            }

            $realPath = realpath($file);
            $methods = [];

            // Method 1: opcache_invalidate
            if (function_exists('opcache_invalidate')) {
                if (opcache_invalidate($realPath, true)) {
                    $methods[] = 'opcache_invalidate';
                }
            }

            // Method 2: Touch file (change modification time)
            if (touch($realPath)) {
                $methods[] = 'touch';
            }

            // Method 3: opcache_reset (if available)
            if (function_exists('opcache_reset')) {
                opcache_reset();
                $methods[] = 'opcache_reset';
            }

            $results[] = [
                'file' => basename($file),
                'path' => $realPath,
                'methods' => $methods,
                'status' => !empty($methods) ? 'success' : 'failed'
            ];
        }

        // Display results
        foreach ($results as $result) {
            if ($result['status'] === 'not_found') {
                echo '<div class="error">❌ File not found: <code>' . htmlspecialchars($result['file']) . '</code></div>';
            } elseif ($result['status'] === 'success') {
                echo '<div class="success">✅ <code>' . htmlspecialchars($result['file']) . '</code> - Methods used: ' . implode(', ', $result['methods']) . '</div>';
            } else {
                echo '<div class="error">❌ Failed to reload: <code>' . htmlspecialchars($result['file']) . '</code></div>';
            }
        }

        // Get OPcache status
        if (function_exists('opcache_get_status')) {
            $status = opcache_get_status();
            if ($status) {
                echo '<div class="info">';
                echo '<strong>OPcache Status After Reload:</strong><br>';
                echo 'Enabled: ' . ($status['opcache_enabled'] ? 'Yes' : 'No') . '<br>';
                echo 'Cached Scripts: ' . $status['opcache_statistics']['num_cached_scripts'] . '<br>';
                echo '</div>';
            }
        }
        ?>

        <div class="info" style="margin-top: 20px;">
            <strong>⚠️ If this still doesn't work:</strong><br>
            OPcache is very persistent. You need to contact Hostinger support to restart PHP-FPM.<br><br>
            <strong>What to tell them:</strong><br>
            "I've tried multiple methods to clear OPcache (opcache_invalidate, touch files, etc.) but my Laravel middleware is still serving old cached code. Can you restart PHP-FPM for my domain (geocrud.bytevortexz.com) only?"
        </div>

        <div class="info" style="margin-top: 20px;">
            <strong>📝 Next Steps:</strong>
            <ol>
                <li>Wait 2-3 minutes</li>
                <li>Clear localStorage: <code>localStorage.clear()</code></li>
                <li>Refresh dashboard</li>
                <li>Log in again</li>
                <li>If still 401, contact Hostinger support</li>
            </ol>
        </div>
    </div>
</body>
</html>

