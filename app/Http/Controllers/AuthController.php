<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\EmailVerification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

class AuthController extends Controller
{
    /**
     * Show login form
     */
    public function showLoginForm(Request $request)
    {
        $successMessage = null;
        $errorMessage = null;

        if ($request->has('registered')) {
            $successMessage = 'Registration successful! You can now log in.';
        }

        if ($request->has('error')) {
            switch ($request->error) {
                case 'invalid_token':
                    $errorMessage = 'Your session has expired or authentication token is invalid. Please log in again.';
                    break;
                case 'token_tampered':
                    $errorMessage = 'Authentication token has been modified. Please log in again for security.';
                    break;
                default:
                    $errorMessage = 'Authentication error. Please log in again.';
            }
        }

        return view('frontend.auth.login', [
            'title' => 'Login',
            'success' => $successMessage,
            'error' => $errorMessage
        ]);
    }

    /**
     * Handle login
     */
    public function login(Request $request)
    {
        // Check if this is an API request (from /api/ routes)
        // Always treat /api/* routes as JSON requests
        $isJsonRequest = $request->expectsJson() || $request->is('api/*') || $request->wantsJson() || str_starts_with($request->path(), 'api/');
        
        // NOTE: Avoid framework logging here because the logging configuration
        // can be misconfigured on some shared hosts and cause a 500 error.
        // If you need to debug locally, you can temporarily uncomment this block.
        /*
        if (!$isJsonRequest) {
            Log::info('Login request not detected as JSON', [
                'path' => $request->path(),
                'expectsJson' => $request->expectsJson(),
                'wantsJson' => $request->wantsJson(),
                'is_api' => $request->is('api/*'),
                'accept_header' => $request->header('Accept'),
                'content_type' => $request->header('Content-Type'),
            ]);
        }
        */

        $credentials = $request->validate([
            'email' => 'required_without:username',
            'username' => 'required_without:email',
            'password' => 'required',
        ]);

        // Trim whitespace from credentials
        if (isset($credentials['username'])) {
            $credentials['username'] = trim($credentials['username']);
        }
        if (isset($credentials['email'])) {
            $credentials['email'] = trim($credentials['email']);
        }
        $credentials['password'] = trim($credentials['password']);

        $user = null;
        if (isset($credentials['email'])) {
            $user = User::where('email', $credentials['email'])->first();
        } elseif (isset($credentials['username'])) {
            $user = User::where('username', $credentials['username'])->first();
        }

        if (!$user) {
            // Silent fail in web UI – avoid using Log facade to prevent errors
            // when LOG_CHANNEL is not configured correctly.
            if ($isJsonRequest) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid credentials',
                    'message' => 'Username or password is incorrect'
                ], 401);
            }
            return back()->withErrors(['error' => 'Invalid credentials'])->withInput();
        }

        // Check password - handle both hashed and plain text (for legacy accounts)
        $passwordValid = false;
        if (Hash::check($credentials['password'], $user->password)) {
            $passwordValid = true;
        } elseif ($user->password === $credentials['password']) {
            // Legacy plain text password - rehash it
            $passwordValid = true;
            $user->password = Hash::make($credentials['password']);
            $user->save();
        }

        if (!$passwordValid) {
            // Silent fail in web UI – avoid using Log facade to prevent errors
            // when LOG_CHANNEL is not configured correctly.
            if ($isJsonRequest) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid credentials',
                    'message' => 'Username or password is incorrect'
                ], 401);
            }
            return back()->withErrors(['error' => 'Invalid credentials'])->withInput();
        }

        // Check if account is blocked
        if ($user->isBlocked()) {
            if ($isJsonRequest) {
                return response()->json([
                    'success' => false,
                    'error' => 'Account blocked',
                    'message' => 'Your account has been blocked. Please contact the administrator.'
                ], 403);
            }
            return back()->withErrors(['error' => 'Your account has been blocked. Please contact the administrator.'])->withInput();
        }

        // Check if account is activated
        if (!$user->isActivated()) {
            if ($isJsonRequest) {
                return response()->json([
                    'success' => false,
                    'message' => 'Account not activated. Please check your email for OTP.',
                    'requires_activation' => true,
                    'email' => $user->email
                ], 403);
            }

            session(['pending_activation_user_id' => $user->id]);
            session(['pending_activation_email' => $user->email]);
            return redirect('/auth/activate');
        }

        // Generate auth token (64 characters from 32 random bytes)
        $authToken = bin2hex(random_bytes(32));
        
        // Ensure token is exactly 64 characters
        if (strlen($authToken) !== 64) {
            Log::error('Invalid token length generated', [
                'length' => strlen($authToken),
                'user_id' => $user->id
            ]);
            $authToken = bin2hex(random_bytes(32)); // Regenerate
        }
        
        // Save token using direct DB update to ensure exact match (bypass Eloquent potential modifications)
        $updateData = ['auth_token' => $authToken];
        if (Schema::hasColumn('users', 'token_expires_at')) {
            $updateData['token_expires_at'] = now()->addDays(30);
        }
        
        // Use direct DB update to ensure exact token storage
        DB::table('users')
            ->where('id', $user->id)
            ->update($updateData);
        
        // Refresh and verify token was saved exactly
        $user->refresh();
        $savedToken = $user->auth_token;
        
        // Strict comparison - tokens must match exactly
        if ($savedToken !== $authToken) {
            Log::error('Token mismatch after save - CRITICAL', [
                'expected_length' => strlen($authToken),
                'actual_length' => strlen($savedToken),
                'expected_preview' => substr($authToken, 0, 20) . '...',
                'actual_preview' => substr($savedToken, 0, 20) . '...',
                'expected_full' => $authToken,
                'actual_full' => $savedToken,
                'user_id' => $user->id,
                'tokens_match' => $savedToken === $authToken,
                'tokens_equal' => $savedToken == $authToken
            ]);
            
            // Force update one more time using raw query
            DB::table('users')
                ->where('id', $user->id)
                ->update(['auth_token' => $authToken]);
            
            $user->refresh();
            $savedToken = $user->auth_token;
            
            // Final check
            if ($savedToken !== $authToken) {
                Log::critical('Token still mismatched after retry', [
                    'user_id' => $user->id,
                    'expected' => $authToken,
                    'actual' => $savedToken
                ]);
        }
        }
        
        // Use the saved token from database (in case it was modified)
        $finalAuthToken = $user->auth_token;

        // Only use sessions for web requests, not API requests
        if (!$isJsonRequest) {
            // Regenerate session ID to prevent session fixation and ensure clean session
            $request->session()->regenerate();
            
            // Set session
            session([
                'user_id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
                'auth_token' => $finalAuthToken, // Use verified token from DB
            ]);
        }

        if ($isJsonRequest) {
            // Final verification - ensure token in DB matches what we're returning
            $user->refresh();
            $dbToken = $user->auth_token;
            
            Log::info('Login successful - Token verification', [
                'user_id' => $user->id,
                'username' => $user->username,
                'token_length' => strlen($dbToken),
                'token_preview' => substr($dbToken, 0, 20) . '...',
                'token_full' => $dbToken,
                'token_matches_original' => $dbToken === $authToken,
                'returning_token' => $dbToken
            ]);
            
            // Always return the token from database to ensure exact match
            return response()->json([
                'success' => true,
                'message' => 'Login successful',
                'auth_token' => $dbToken, // Always use token from database
                'user' => [
                    'id' => $user->id,
                    'username' => $user->username,
                    'email' => $user->email,
                    'role' => $user->role, // Include role for frontend permissions
                    'profile_picture' => $user->profile_picture, // Include profile picture
                    'is_activated' => $user->isActivated()
                ]
            ]);
        }

        // Redirect to intended URL if set, otherwise to dashboard
        $intendedUrl = session('intended_url');
        if ($intendedUrl) {
            session()->forget('intended_url');
            return redirect($intendedUrl);
        }
        
        return redirect('/dashboard');
    }

    /**
     * Show registration form
     */
    public function showRegisterForm()
    {
        return view('frontend.auth.register', ['title' => 'Register']);
    }

    /**
     * Handle registration
     */
    public function register(Request $request)
    {
        // Check if this is an API request (from /api/ routes)
        $isJsonRequest = $request->expectsJson() || $request->is('api/*') || $request->wantsJson();

        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users',
            'email' => 'required|email|max:100|unique:users',
            'password' => 'required|string|min:6',
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobilenum' => 'nullable|string|max:20',
            'profile_picture' => 'nullable|image|max:2048',
        ]);

        // Handle profile picture upload
        $profilePicture = 'default-profile.svg';
        if ($request->hasFile('profile_picture')) {
            $file = $request->file('profile_picture');
            $extension = $file->getClientOriginalExtension();
            $filename = 'profile-' . bin2hex(random_bytes(8)) . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $profilePicture = $filename;
        }

        // Create user (default role is 'member')
        $user = User::create([
            'username' => $validated['username'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'firstname' => $validated['firstname'] ?? null,
            'lastname' => $validated['lastname'] ?? null,
            'mobile_number' => $validated['mobilenum'] ?? null,
            'profile_picture' => $profilePicture,
            'email_verified' => false,
            'role' => 'member', // Default role
            'status' => 'active', // Default status
        ]);

        // Generate and send OTP
        $otpCode = str_pad((string) random_int(100000, 999999), 6, '0', STR_PAD_LEFT);
        EmailVerification::create([
            'user_id' => $user->id,
            'email' => $user->email,
            'otp_code' => $otpCode,
            'expires_at' => now()->addMinutes(15),
        ]);

        // Try to send OTP email, but don't fail registration if email fails
        // User is created and OTP is saved - user can resend OTP later if needed
        $emailSent = false;
        $emailError = null;
        try {
            $this->sendOtpEmail($user->email, $otpCode, $user->username);
            $emailSent = true;
        } catch (PHPMailerException $e) {
            // Log the error with full details
            $errorMessage = $e->getMessage();
            Log::error('Failed to send OTP email during registration', [
                'user_id' => $user->id,
                'email' => $user->email,
                'error' => $errorMessage,
                'trace' => $e->getTraceAsString()
            ]);
            $emailSent = false;
            $emailError = $errorMessage;
        }

        // Always return success - user is created, OTP is saved
        // If email failed, user can use resend OTP feature
        if ($isJsonRequest) {
            if ($emailSent) {
                return response()->json([
                    'success' => true,
                    'message' => 'Registration successful. Please check your email for OTP code.',
                    'email' => $user->email,
                    'userId' => $user->id,
                    'requiresVerification' => true
                ], 201);
            } else {
                // Email failed but user is created - return success with warning
                return response()->json([
                    'success' => true,
                    'message' => 'Registration successful, but failed to send activation email. Please use "Resend OTP" feature.',
                    'email' => $user->email,
                    'userId' => $user->id,
                    'requiresVerification' => true,
                    'emailError' => $emailError,
                    'canResendOtp' => true
                ], 201);
            }
        }

        session(['pending_activation_user_id' => $user->id]);
        session(['pending_activation_email' => $user->email]);

        if ($emailSent) {
            return redirect('/auth/activate')->with('message', 'Registration successful. Please check your email for OTP code.');
        } else {
            return redirect('/auth/activate')->with('warning', 'Registration successful, but failed to send activation email. Please use "Resend OTP" feature.');
        }
    }

    /**
     * Show activation form
     */
    public function showActivateForm(Request $request)
    {
        // Get email from URL parameter or session
        $email = $request->query('email') ?? session('pending_activation_email');
        
        // If email is provided in URL but not in session, store it in session
        if ($request->query('email') && !session('pending_activation_email')) {
            $user = User::where('email', $request->query('email'))->first();
            if ($user) {
                session(['pending_activation_user_id' => $user->id]);
                session(['pending_activation_email' => $user->email]);
            }
        }
        
        return view('frontend.auth.activate', [
            'title' => 'Activate Account',
            'email' => $email
        ])->with('email', $email);
    }

    /**
     * Handle activation
     */
    public function activate(Request $request)
    {
        $validated = $request->validate([
            'otp_code' => 'required|string|size:6',
            'email' => 'sometimes|email', // For API requests
        ]);

        // For API requests, get user by email instead of session
        if ($request->expectsJson() || $request->is('api/*')) {
            if (!$request->has('email')) {
                return response()->json([
                    'success' => false,
                    'message' => 'Email is required'
                ], 400);
            }

            $user = User::where('email', $request->email)->first();
            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found'
                ], 404);
            }

            $userId = $user->id;
        } else {
            $userId = session('pending_activation_user_id');
            if (!$userId) {
                return back()->withErrors(['error' => 'Session expired. Please register again.']);
            }
        }

        $verification = EmailVerification::where('user_id', $userId)
            ->where('otp_code', $validated['otp_code'])
            ->where('expires_at', '>', now())
            ->first();

        if (!$verification) {
            // Check if this is an API request
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid or expired OTP code'
                ], 400);
            }
            return back()->withErrors(['error' => 'Invalid or expired OTP code']);
        }

        $user = User::find($userId);
        $user->email_verified = true;
        $user->email_verified_at = now();
        $user->save();

        $verification->delete();

        // Check if this is an API request
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'success' => true,
                'message' => 'Account activated successfully'
            ]);
        }

        return redirect('/auth/login?registered=1');
    }

    /**
     * Resend OTP
     */
    public function resendOtp(Request $request)
    {
        $email = $request->input('email') ?? session('pending_activation_email');
        
        if (!$email) {
            return response()->json([
                'success' => false,
                'error' => 'Email not found'
            ], 400);
        }

        $user = User::where('email', $email)->first();
        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => 'Email not found'
            ], 404);
        }

        if ($user->isActivated()) {
            return response()->json([
                'success' => false,
                'error' => 'Account already activated'
            ], 400);
        }

        $otpCode = str_pad((string) random_int(100000, 999999), 6, '0', STR_PAD_LEFT);
        
        // Delete old OTP codes
        EmailVerification::where('user_id', $user->id)->delete();
        
        EmailVerification::create([
            'user_id' => $user->id,
            'email' => $user->email,
            'otp_code' => $otpCode,
            'expires_at' => now()->addMinutes(15),
        ]);

        try {
            $this->sendOtpEmail($user->email, $otpCode, $user->username);
        } catch (PHPMailerException $e) {
            // Log the error with full details
            $errorMessage = $e->getMessage();
            Log::error('Failed to resend OTP email', [
                'user_id' => $user->id,
                'email' => $user->email,
                'error' => $errorMessage,
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'success' => false,
                'error' => 'Failed to send OTP email. Please check your email configuration or try again later.',
                'message' => env('APP_DEBUG') ? $errorMessage : 'Failed to send OTP email'
            ], 500);
        }

        return response()->json([
            'success' => true,
            'message' => 'OTP code sent to your email'
        ]);
    }

    /**
     * Logout
     */
    public function logout(Request $request)
    {
        // Clear auth token from database if user is logged in
        if (session('user_id')) {
            $user = User::find(session('user_id'));
            if ($user) {
                $user->auth_token = null;
                $user->save();
            }
        }

        session()->flush();

        // Check if this is an API request (from /api/ routes)
        if ($request->expectsJson() || $request->is('api/*') || $request->wantsJson()) {
            return response()->json(['success' => true, 'message' => 'Logged out successfully']);
        }

        return redirect('/auth/login');
    }

    /**
     * Show forgot password form
     */
    public function showForgotPasswordForm()
    {
        return view('frontend.auth.forgot-password', ['title' => 'Forgot Password']);
    }

    /**
     * Handle forgot password
     */
    public function forgotPassword(Request $request)
    {
        try {
            $validated = $request->validate([
                'email' => 'required|email',
            ]);

            $user = User::where('email', $validated['email'])->first();
            
            if (!$user) {
                // Check if this is an API request
                if ($request->expectsJson() || $request->is('api/*')) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Email not found'
                    ], 404);
                }
                return back()->withErrors(['error' => 'Email not found']);
            }

            $token = bin2hex(random_bytes(32));
            $user->auth_token = "RESET:" . now()->addHour()->timestamp . ":" . $token;
            $user->save();

            // Try to send email, but don't fail if email sending fails
            $emailError = null;
            try {
                $this->sendPasswordResetEmail($user->email, $token, $user->username);
                $emailSent = true;
            } catch (\Exception $e) {
                // Log the error with full details
                $errorMessage = $e->getMessage();
                $errorDetails = [
                    'email' => $user->email,
                    'error' => $errorMessage,
                    'trace' => $e->getTraceAsString()
                ];
                Log::error('Failed to send password reset email', $errorDetails);
                $emailSent = false;
                $emailError = $errorMessage;
            }

            // Check if this is an API request
            if ($request->expectsJson() || $request->is('api/*')) {
                if ($emailSent) {
                    return response()->json([
                        'success' => true,
                        'message' => 'Password reset link sent to your email'
                    ]);
                } else {
                    // Return error with details so user knows what went wrong
                    $response = [
                        'success' => false,
                        'message' => 'Failed to send password reset email. ' . ($emailError ?: 'Please check your email configuration.'),
                        'email_sent' => false
                    ];
                    
                    // Include error details in development mode
                    if (env('APP_DEBUG', false)) {
                        $response['email_error'] = $emailError;
                        $response['debug_info'] = 'Check Laravel logs (storage/logs/laravel.log) for full error details. Common issues: MAIL_PASSWORD is empty or incorrect in .env file.';
                    }
                    
                    return response()->json($response, 500);
                }
            }

            if ($emailSent) {
                return back()->with('success', 'Password reset link sent to your email');
            } else {
                return back()->with('error', 'Password reset token generated but email could not be sent. Please contact support.');
            }
        } catch (\Illuminate\Validation\ValidationException $e) {
            // Validation errors
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage(),
                    'errors' => $e->errors()
                ], 422);
            }
            throw $e;
        } catch (\Exception $e) {
            // Log any other errors
            Log::error('Forgot password error: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString()
            ]);
            
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'success' => false,
                    'message' => 'An error occurred. Please try again later.'
                ], 500);
            }
            
            return back()->withErrors(['error' => 'An error occurred. Please try again later.']);
        }
    }

    /**
     * Show reset password form
     */
    public function showResetPasswordForm(Request $request)
    {
        $token = $request->query('token');
        if (!$token) {
            return redirect('/auth/login')->withErrors(['error' => 'Invalid reset token']);
        }

        return view('frontend.auth.reset-password', [
            'title' => 'Reset Password',
            'token' => $token
        ]);
    }

    /**
     * Handle reset password
     */
    public function resetPassword(Request $request)
    {
        $validated = $request->validate([
            'token' => 'required|string',
            'password' => 'required|string|min:6|confirmed',
        ]);

        // Find user with matching reset token
        $users = User::where('auth_token', 'like', 'RESET:%')->get();
        $user = null;
        foreach ($users as $u) {
            if (strpos($u->auth_token, 'RESET:') === 0) {
                $parts = explode(':', $u->auth_token, 3);
                if (count($parts) === 3 && $parts[2] === $validated['token']) {
                    $user = $u;
                    break;
                }
            }
        }

        if (!$user) {
            // Check if this is an API request
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid or expired reset token'
                ], 400);
            }
            return back()->withErrors(['error' => 'Invalid or expired reset token']);
        }

        // Check if token is expired
        $authToken = $user->auth_token;
        if (strpos($authToken, 'RESET:') === 0) {
            $parts = explode(':', $authToken, 3);
            if (count($parts) === 3) {
                $expiresTimestamp = (int)$parts[1];
                if (time() > $expiresTimestamp) {
                    // Check if this is an API request
                    if ($request->expectsJson() || $request->is('api/*')) {
                        return response()->json([
                            'success' => false,
                            'message' => 'Reset token has expired'
                        ], 400);
                    }
                    return back()->withErrors(['error' => 'Reset token has expired']);
                }
            }
        }

        $user->password = Hash::make($validated['password']);
        $user->auth_token = null;
        $user->save();

        // Check if this is an API request
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'success' => true,
                'message' => 'Password reset successfully'
            ]);
        }

        return redirect('/auth/login')->with('success', 'Password reset successfully');
    }

    /**
     * Send OTP email
     */
    private function sendOtpEmail(string $email, string $otpCode, string $username): void
    {
        // Validate email configuration before attempting to send
        $mailHost = env('MAIL_HOST');
        $mailUsername = env('MAIL_USERNAME');
        $mailPassword = env('MAIL_PASSWORD');
        
        // Log configuration (without exposing password)
        Log::info('Email configuration check', [
            'MAIL_HOST' => $mailHost ?: 'NOT SET',
            'MAIL_USERNAME' => $mailUsername ?: 'NOT SET',
            'MAIL_PASSWORD' => $mailPassword ? (strlen($mailPassword) . ' chars') : 'NOT SET',
            'MAIL_PORT' => env('MAIL_PORT', 'NOT SET'),
            'MAIL_ENCRYPTION' => env('MAIL_ENCRYPTION', 'NOT SET')
        ]);
        
        if (empty($mailHost) || empty($mailUsername) || empty($mailPassword)) {
            Log::error('Email configuration is incomplete', [
                'MAIL_HOST' => $mailHost ? 'set' : 'missing',
                'MAIL_USERNAME' => $mailUsername ? 'set' : 'missing',
                'MAIL_PASSWORD' => $mailPassword ? 'set' : 'missing'
            ]);
            throw new PHPMailerException('Email configuration is incomplete. Please check MAIL_HOST, MAIL_USERNAME, and MAIL_PASSWORD in .env file.');
        }
        
        // Check if password is still the placeholder
        if ($mailPassword === 'your-actual-smtp-password-here' || strpos($mailPassword, 'your-actual') !== false || $mailPassword === 'YOUR_SMTP_PASSWORD_HERE') {
            Log::error('Email password is still set to placeholder value', [
                'password_value' => substr($mailPassword, 0, 20) . '...'
            ]);
            throw new PHPMailerException('Email password is not configured. Please set MAIL_PASSWORD in .env file with your actual SMTP password.');
        }
        
        // Clean the password - remove ALL spaces (Gmail app passwords should have no spaces)
        $originalPasswordLength = strlen($mailPassword);
        $mailPassword = preg_replace('/\s+/', '', $mailPassword);
        
        if ($originalPasswordLength !== strlen($mailPassword)) {
            Log::warning('Spaces were removed from email password', [
                'original_length' => $originalPasswordLength,
                'cleaned_length' => strlen($mailPassword)
            ]);
        }
        
        // Validate Gmail app password format (should be 16 characters, alphanumeric)
        if ($mailHost === 'smtp.gmail.com') {
            if (strlen($mailPassword) !== 16) {
                Log::error('Gmail app password length is incorrect', [
                    'length' => strlen($mailPassword),
                    'expected' => 16,
                    'password_preview' => substr($mailPassword, 0, 4) . '...'
                ]);
                throw new PHPMailerException('Gmail App Password must be exactly 16 characters. Current length: ' . strlen($mailPassword) . '. Please check your .env file and regenerate the App Password if needed.');
            }
        }
        
        // Get encryption and port from .env
        $mailEncryption = env('MAIL_ENCRYPTION', 'tls');
        $mailPort = (int) env('MAIL_PORT', 587);
        
        // Try sending with configured settings first
        $lastError = null;
        $configurations = [
            ['port' => $mailPort, 'encryption' => $mailEncryption, 'name' => 'configured'],
        ];
        
        // If Gmail and first attempt fails, try alternative ports
        if ($mailHost === 'smtp.gmail.com') {
            if ($mailPort === 587 && $mailEncryption === 'tls') {
                // Try port 465 with SSL as fallback
                $configurations[] = ['port' => 465, 'encryption' => 'ssl', 'name' => 'fallback-465-ssl'];
            } elseif ($mailPort === 465 && $mailEncryption === 'ssl') {
                // Try port 587 with TLS as fallback
                $configurations[] = ['port' => 587, 'encryption' => 'tls', 'name' => 'fallback-587-tls'];
            }
        }
        
        foreach ($configurations as $config) {
            try {
                $mail = new PHPMailer(true);
                $mail->isSMTP();
                $mail->Host = $mailHost;
                $mail->SMTPAuth = true;
                $mail->Username = $mailUsername;
                $mail->Password = $mailPassword; // Already cleaned
                $mail->SMTPSecure = $config['encryption'];
                $mail->Port = $config['port'];
                $mail->SMTPDebug = 0; // Always off - use Laravel logs for debugging
                $mail->CharSet = 'UTF-8';
                $mail->Timeout = 30; // Increase timeout for slow connections
                
                // Additional Gmail-specific settings for better compatibility
                if ($mailHost === 'smtp.gmail.com') {
                    // Disable SSL verification (some servers have issues)
                    $mail->SMTPOptions = [
                        'ssl' => [
                            'verify_peer' => false,
                            'verify_peer_name' => false,
                            'allow_self_signed' => true
                        ]
                    ];
                }
                
                $mail->setFrom(env('MAIL_FROM_ADDRESS', env('MAIL_FROM')), env('MAIL_FROM_NAME', 'GeoCRUD - GIS Manager'));
                $mail->addAddress($email);
                $mail->isHTML(true);
                $mail->Subject = 'Email Verification - GeoCRUD';
                
                // Include email in URL so it works even if session expires
                // Use frontend URL for GitHub Pages
                $frontendUrl = env('FRONTEND_URL', 'https://clownqqqqq.github.io/laravel-gis-frontend');
                $activationUrl = $frontendUrl . '/activate.html?email=' . urlencode($email);
                
                $mail->Body = view('frontend.emails.otp', [
                    'username' => $username,
                    'otpCode' => $otpCode,
                    'activationUrl' => $activationUrl
                ])->render();

                if ($mail->send()) {
                    Log::info('OTP email sent successfully', [
                        'email' => $email,
                        'username' => $username,
                        'config_used' => $config['name'],
                        'port' => $config['port'],
                        'encryption' => $config['encryption']
                    ]);
                    return; // Success!
                }
            } catch (\Exception $e) {
                $lastError = $e->getMessage();
                Log::warning('Email send attempt failed', [
                    'config' => $config['name'],
                    'port' => $config['port'],
                    'encryption' => $config['encryption'],
                    'error' => $lastError
                ]);
                // Continue to next configuration
            }
        }
        
        // All configurations failed
        Log::error('PHPMailer failed to send email with all configurations', [
            'email' => $email,
            'host' => $mailHost,
            'username' => $mailUsername,
            'password_length' => strlen($mailPassword),
            'password_preview' => substr($mailPassword, 0, 4) . '...',
            'last_error' => $lastError,
            'tried_configs' => $configurations,
            'MAIL_PORT' => env('MAIL_PORT'),
            'MAIL_ENCRYPTION' => env('MAIL_ENCRYPTION')
        ]);
        
        // Provide more helpful error message
        $helpMessage = 'SMTP Error: Could not authenticate. ';
        if ($mailHost === 'smtp.gmail.com') {
            $helpMessage .= 'Please verify: 1) Gmail App Password is exactly 16 characters (no spaces), 2) 2-Step Verification is enabled, 3) Config cache is cleared (php artisan config:clear), 4) .env file has correct MAIL_PASSWORD value.';
        } else {
            $helpMessage .= 'Please check your email configuration in .env file.';
        }
        
        throw new PHPMailerException($helpMessage);
    }

    /**
     * Send password reset email
     */
    private function sendPasswordResetEmail(string $email, string $token, string $username): void
    {
        // Use the same approach as sendOtpEmail
        $mailHost = env('MAIL_HOST');
        $mailUsername = env('MAIL_USERNAME');
        $mailPassword = env('MAIL_PASSWORD');
        
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $mailHost;
        $mail->SMTPAuth = true;
        $mail->Username = $mailUsername;
        $mail->Password = trim($mailPassword); // Remove any leading/trailing spaces
        $mail->SMTPSecure = env('MAIL_ENCRYPTION', 'tls'); // Use from .env, default to tls for Gmail
        $mail->Port = (int) env('MAIL_PORT', 587); // Use from .env, default to 587 for Gmail TLS
        $mail->CharSet = 'UTF-8';
        $mail->setFrom(env('MAIL_FROM_ADDRESS', env('MAIL_FROM')), env('MAIL_FROM_NAME', 'GeoCRUD - GIS Manager'));
        $mail->addAddress($email);
        $mail->isHTML(true);
        $mail->Subject = 'Password Reset Request - GeoCRUD';
        
        // Disable SMTP debug output - it interferes with JSON responses
        $mail->SMTPDebug = 0; // Always off - use Laravel logs for debugging
        
        // Use frontend URL for GitHub Pages
        $frontendUrl = rtrim(env('FRONTEND_URL', 'https://clownqqqqq.github.io/laravel-gis-frontend'), '/');
        $resetUrl = $frontendUrl . '/reset-password.html?token=' . urlencode($token);
        
        $mail->Body = view('frontend.emails.password-reset', [
            'username' => $username,
            'resetUrl' => $resetUrl
        ])->render();

        if (!$mail->send()) {
            throw new PHPMailerException('Mailer Error: ' . $mail->ErrorInfo);
        }
    }
}

