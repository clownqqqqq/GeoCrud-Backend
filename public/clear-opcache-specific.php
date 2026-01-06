<?php
/**
 * Clear OPcache for specific Laravel files only
 * This script only clears OPcache for your Laravel application files,
 * not for other domains or websites on the server.
 * 
 * Access: https://geocrud.bytevortexz.com/clear-opcache-specific.php
 */

// Security: Only allow access from localhost or your domain
$allowedHosts = ['geocrud.bytevortexz.com', 'localhost', '127.0.0.1'];
$currentHost = $_SERVER['HTTP_HOST'] ?? '';

// Optional: Add a secret key for extra security
$secretKey = 'your-secret-key-here'; // Change this!
$providedKey = $_GET['key'] ?? '';

// Check if access is allowed
if (!in_array($currentHost, $allowedHosts) && $providedKey !== $secretKey) {
    http_response_code(403);
    die('Access denied. This script can only be accessed from authorized domains.');
}

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Clear OPcache - Specific Files Only</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #333; }
        .success { color: #28a745; background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .error { color: #dc3545; background: #f8d7da; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .info { color: #0c5460; background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .file-list { background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Clear OPcache - Specific Files Only</h1>
        
        <?php
        // Check if OPcache is enabled
        if (!function_exists('opcache_get_status')) {
            echo '<div class="error">❌ OPcache is not enabled on this server.</div>';
            echo '<p>This script only works if OPcache is enabled.</p>';
            exit;
        }

        // Get Laravel base path
        $basePath = dirname(__DIR__);
        
        // Files to clear from OPcache (only your Laravel files)
        $filesToClear = [
            $basePath . '/app/Http/Middleware/ApiAuthMiddleware.php',
            $basePath . '/app/Http/Controllers/AuthController.php',
            $basePath . '/app/Http/Controllers/GisController.php',
            $basePath . '/app/Http/Controllers/ProfileController.php',
            $basePath . '/routes/api.php',
        ];

        $cleared = [];
        $failed = [];
        $notFound = [];

        echo '<div class="info">📋 Clearing OPcache for specific Laravel files only...</div>';

        foreach ($filesToClear as $file) {
            if (!file_exists($file)) {
                $notFound[] = basename($file);
                continue;
            }

            // Get absolute path
            $realPath = realpath($file);
            
            if ($realPath && opcache_invalidate($realPath, true)) {
                $cleared[] = basename($file);
            } else {
                $failed[] = basename($file);
            }
        }

        // Also try to reset OPcache for the entire script directory
        if (function_exists('opcache_reset')) {
            // Only reset if we're in a safe environment
            // opcache_reset(); // Uncomment if needed, but this affects all files
        }

        // Display results
        if (!empty($cleared)) {
            echo '<div class="success">✅ Successfully cleared OPcache for:</div>';
            echo '<div class="file-list"><ul>';
            foreach ($cleared as $file) {
                echo '<li><code>' . htmlspecialchars($file) . '</code></li>';
            }
            echo '</ul></div>';
        }

        if (!empty($failed)) {
            echo '<div class="error">⚠️ Failed to clear OPcache for:</div>';
            echo '<div class="file-list"><ul>';
            foreach ($failed as $file) {
                echo '<li><code>' . htmlspecialchars($file) . '</code></li>';
            }
            echo '</ul></div>';
        }

        if (!empty($notFound)) {
            echo '<div class="info">ℹ️ Files not found (may be in different location):</div>';
            echo '<div class="file-list"><ul>';
            foreach ($notFound as $file) {
                echo '<li><code>' . htmlspecialchars($file) . '</code></li>';
            }
            echo '</ul></div>';
        }

        // Get OPcache status
        $status = opcache_get_status();
        if ($status) {
            echo '<div class="info">';
            echo '<strong>OPcache Status:</strong><br>';
            echo 'Enabled: ' . ($status['opcache_enabled'] ? 'Yes' : 'No') . '<br>';
            echo 'Cached Scripts: ' . $status['opcache_statistics']['num_cached_scripts'] . '<br>';
            echo 'Cache Hits: ' . $status['opcache_statistics']['hits'] . '<br>';
            echo 'Cache Misses: ' . $status['opcache_statistics']['misses'] . '<br>';
            echo '</div>';
        }
        ?>

        <div class="info" style="margin-top: 20px;">
            <strong>📝 Next Steps:</strong>
            <ol>
                <li>Wait 30-60 seconds for OPcache to reload</li>
                <li>Clear browser localStorage: <code>localStorage.clear()</code></li>
                <li>Refresh your dashboard page</li>
                <li>Log in again</li>
                <li>Locations should now display!</li>
            </ol>
        </div>

        <div class="info" style="margin-top: 20px;">
            <strong>🔒 Security Note:</strong><br>
            After testing, delete this file or protect it with a secret key in the URL:<br>
            <code>?key=your-secret-key-here</code>
        </div>
    </div>
</body>
</html>

