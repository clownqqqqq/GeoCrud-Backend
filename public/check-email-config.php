<?php
/**
 * Email Configuration Diagnostic Script
 * 
 * This script checks your email configuration without sending emails.
 * DELETE THIS FILE AFTER USE FOR SECURITY!
 * 
 * Access: https://geocrud.bytevortexz.com/check-email-config.php
 */

// Security: Only allow access if APP_DEBUG is true or from localhost
$allowAccess = false;

// Determine project root (script might be in public/ or root)
$projectRoot = __DIR__;
if (basename(__DIR__) === 'public') {
    $projectRoot = dirname(__DIR__);
}

// Check if running from command line
if (php_sapi_name() === 'cli') {
    $allowAccess = true;
} else {
    // Check if APP_DEBUG is enabled
    $envFile = $projectRoot . '/.env';
    if (file_exists($envFile)) {
        $envContent = file_get_contents($envFile);
        if (strpos($envContent, 'APP_DEBUG=true') !== false) {
            $allowAccess = true;
        }
    }
}

if (!$allowAccess) {
    die('Access denied. This script can only run when APP_DEBUG=true or from command line.');
}

require $projectRoot.'/vendor/autoload.php';

$app = require_once $projectRoot.'/bootstrap/app.php';

echo "<h1>Email Configuration Diagnostic</h1>\n";
echo "<pre>\n";

// Check .env file directly
echo "=== Reading .env file directly ===\n";
$envFile = $projectRoot . '/.env';
if (file_exists($envFile)) {
    $envContent = file_get_contents($envFile);
    
    // Extract mail settings
    preg_match('/MAIL_HOST=(.+)/', $envContent, $mailHost);
    preg_match('/MAIL_PORT=(.+)/', $envContent, $mailPort);
    preg_match('/MAIL_USERNAME=(.+)/', $envContent, $mailUsername);
    preg_match('/MAIL_PASSWORD=(.+)/', $envContent, $mailPassword);
    preg_match('/MAIL_ENCRYPTION=(.+)/', $envContent, $mailEncryption);
    
    echo "MAIL_HOST: " . (isset($mailHost[1]) ? trim($mailHost[1]) : 'NOT FOUND') . "\n";
    echo "MAIL_PORT: " . (isset($mailPort[1]) ? trim($mailPort[1]) : 'NOT FOUND') . "\n";
    echo "MAIL_USERNAME: " . (isset($mailUsername[1]) ? trim($mailUsername[1]) : 'NOT FOUND') . "\n";
    
    $passwordValue = isset($mailPassword[1]) ? trim($mailPassword[1]) : 'NOT FOUND';
    $passwordLength = strlen($passwordValue);
    $passwordPreview = $passwordLength > 4 ? substr($passwordValue, 0, 4) . '...' : $passwordValue;
    
    echo "MAIL_PASSWORD: " . $passwordPreview . " (Length: " . $passwordLength . ")\n";
    echo "MAIL_ENCRYPTION: " . (isset($mailEncryption[1]) ? trim($mailEncryption[1]) : 'NOT FOUND') . "\n";
    
    // Check for common issues
    echo "\n=== Issues Found ===\n";
    $issues = [];
    
    if ($passwordValue === 'NOT FOUND' || empty($passwordValue)) {
        $issues[] = "❌ MAIL_PASSWORD is not set in .env file";
    }
    
    if (strpos($passwordValue, 'your-actual') !== false || strpos($passwordValue, 'YOUR_SMTP') !== false) {
        $issues[] = "❌ MAIL_PASSWORD still contains placeholder text";
    }
    
    if (strpos($passwordValue, ' ') !== false) {
        $issues[] = "❌ MAIL_PASSWORD contains spaces (should have none)";
    }
    
    if (trim($mailHost[1] ?? '') === 'smtp.gmail.com' && $passwordLength !== 16) {
        $issues[] = "❌ Gmail App Password should be exactly 16 characters (current: $passwordLength)";
    }
    
    if (empty($issues)) {
        echo "✅ No obvious issues found in .env file\n";
    } else {
        foreach ($issues as $issue) {
            echo $issue . "\n";
        }
    }
} else {
    echo "❌ .env file not found at: $envFile\n";
}

echo "\n=== Reading via Laravel Config (cached values) ===\n";
try {
    $configHost = config('mail.mailers.smtp.host');
    $configPort = config('mail.mailers.smtp.port');
    $configUsername = config('mail.mailers.smtp.username');
    $configPassword = config('mail.mailers.smtp.password');
    $configEncryption = config('mail.mailers.smtp.encryption');
    
    echo "MAIL_HOST: " . ($configHost ?: 'NOT SET') . "\n";
    echo "MAIL_PORT: " . ($configPort ?: 'NOT SET') . "\n";
    echo "MAIL_USERNAME: " . ($configUsername ?: 'NOT SET') . "\n";
    
    $configPasswordLength = strlen($configPassword ?? '');
    $configPasswordPreview = $configPasswordLength > 4 ? substr($configPassword, 0, 4) . '...' : ($configPassword ?: 'NOT SET');
    
    echo "MAIL_PASSWORD: " . $configPasswordPreview . " (Length: " . $configPasswordLength . ")\n";
    echo "MAIL_ENCRYPTION: " . ($configEncryption ?: 'NOT SET') . "\n";
    
    // Compare .env vs Config
    echo "\n=== Comparison (.env vs Config) ===\n";
    $envHost = trim($mailHost[1] ?? '');
    $configHost = $configHost ?: '';
    
    if ($envHost !== $configHost) {
        echo "⚠️  WARNING: MAIL_HOST mismatch!\n";
        echo "   .env: $envHost\n";
        echo "   Config: $configHost\n";
        echo "   → Config cache needs to be cleared!\n";
    } else {
        echo "✅ MAIL_HOST matches\n";
    }
    
    $envPasswordLength = strlen($passwordValue);
    if ($envPasswordLength !== $configPasswordLength) {
        echo "⚠️  WARNING: MAIL_PASSWORD length mismatch!\n";
        echo "   .env length: $envPasswordLength\n";
        echo "   Config length: $configPasswordLength\n";
        echo "   → Config cache needs to be cleared!\n";
    } else {
        echo "✅ MAIL_PASSWORD length matches\n";
    }
    
} catch (\Exception $e) {
    echo "❌ Error reading config: " . $e->getMessage() . "\n";
}

echo "\n=== Recommendations ===\n";
echo "1. If .env and Config don't match → Run: php artisan config:clear\n";
echo "2. If password length is wrong → Check .env file, regenerate App Password\n";
echo "3. If password has spaces → Remove all spaces from .env file\n";
echo "4. After fixing .env → Clear cache: php artisan config:clear\n";

echo "\n⚠️  SECURITY: Delete this file (check-email-config.php) after use!\n";
echo "</pre>\n";

