<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\EmailVerification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

class ProfileController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth.session');
    }

    /**
     * Display the user's profile
     */
    public function show()
    {
        $userId = session('user_id');
        $user = User::findOrFail($userId);

        return view('frontend.profile.view', [
            'title' => 'My Profile',
            'user' => $user,
            'current_user' => $user,
            'auth_token' => session('auth_token') ?? $user->auth_token,
        ]);
    }

    /**
     * Update the user's profile
     */
    public function update(Request $request)
    {
        $userId = session('user_id');
        $user = User::findOrFail($userId);

        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users,username,' . $userId,
            'email' => 'required|email|max:100|unique:users,email,' . $userId,
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobile_number' => 'nullable|string|max:20',
            'profile_picture' => 'nullable|image|max:2048',
        ]);

        if ($request->hasFile('profile_picture')) {
            // Delete old profile picture if exists
            if ($user->profile_picture && $user->profile_picture !== 'default-profile.svg' && file_exists(public_path('uploads/' . $user->profile_picture))) {
                unlink(public_path('uploads/' . $user->profile_picture));
            }

            $file = $request->file('profile_picture');
            $extension = $file->getClientOriginalExtension();
            $filename = 'profile-' . bin2hex(random_bytes(8)) . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $validated['profile_picture'] = $filename;
        }

        $user->update($validated);

        // Update session
        session([
            'username' => $user->username,
            'email' => $user->email,
        ]);

        return back()->with('success', 'Profile updated successfully!');
    }

    /**
     * Show change password form
     */
    public function showChangePasswordForm()
    {
        return view('frontend.profile.change-password', ['title' => 'Change Password']);
    }

    /**
     * Change password
     */
    public function changePassword(Request $request)
    {
        $userId = session('user_id');
        $user = User::findOrFail($userId);

        $validated = $request->validate([
            'current_password' => 'required',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if (!Hash::check($validated['current_password'], $user->password)) {
            return back()->withErrors(['error' => 'Current password is incorrect']);
        }

        $user->password = Hash::make($validated['password']);
        $user->save();

        return back()->with('success', 'Password changed successfully!');
    }

    /**
     * Show verification request form
     */
    public function showVerificationForm()
    {
        return view('frontend.profile.verify', ['title' => 'Verify Account']);
    }

    /**
     * Request verification
     */
    public function requestVerification(Request $request)
    {
        $userId = session('user_id');
        $user = User::findOrFail($userId);

        if ($user->isActivated()) {
            return back()->with('success', 'Account is already verified');
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
            return back()->withErrors(['error' => 'Failed to send OTP email']);
        }

        return back()->with('success', 'OTP code sent to your email');
    }

    /**
     * Verify account
     */
    public function verify(Request $request)
    {
        $validated = $request->validate([
            'otp_code' => 'required|string|size:6',
        ]);

        $userId = session('user_id');
        $verification = EmailVerification::where('user_id', $userId)
            ->where('otp_code', $validated['otp_code'])
            ->where('expires_at', '>', now())
            ->first();

        if (!$verification) {
            return back()->withErrors(['error' => 'Invalid or expired OTP code']);
        }

        $user = User::find($userId);
        $user->email_verified = true;
        $user->email_verified_at = now();
        $user->save();

        $verification->delete();

        return back()->with('success', 'Account verified successfully!');
    }

    /**
     * API: Get profile
     */
    public function apiShow($userId)
    {
        // Get user from Auth facade (middleware sets it via Auth::setUser())
        $authenticatedUser = \Illuminate\Support\Facades\Auth::user();
        
        if (!$authenticatedUser) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized - User not authenticated'
            ], 401);
        }
        
        if ($authenticatedUser->id != $userId) {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden - You can only access your own profile'
            ], 403);
        }

        $user = User::findOrFail($userId);

        return response()->json([
            'success' => true,
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
                'role' => $user->role, // Include role for permissions
                'firstname' => $user->firstname,
                'lastname' => $user->lastname,
                'mobilenum' => $user->mobile_number,
                'profile_picture' => $user->profile_picture,
                'is_activated' => $user->isActivated(),
                'created_at' => $user->created_at
            ]
        ]);
    }

    /**
     * API: Update profile
     */
    public function apiUpdate(Request $request, $userId)
    {
        $authenticatedUser = \Illuminate\Support\Facades\Auth::user();
        
        if (!$authenticatedUser) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized - User not authenticated'
            ], 401);
        }
        
        if ($authenticatedUser->id != $userId) {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden - You can only update your own profile'
            ], 403);
        }

        $user = User::findOrFail($userId);

        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users,username,' . $userId,
            'email' => 'required|email|max:100|unique:users,email,' . $userId,
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobile_number' => 'nullable|string|max:20',
            'profile_picture' => 'nullable|image|max:2048',
        ]);

        if ($request->hasFile('profile_picture')) {
            if ($user->profile_picture && $user->profile_picture !== 'default-profile.svg' && file_exists(public_path('uploads/' . $user->profile_picture))) {
                unlink(public_path('uploads/' . $user->profile_picture));
            }

            $file = $request->file('profile_picture');
            $extension = $file->getClientOriginalExtension();
            $filename = 'profile-' . bin2hex(random_bytes(8)) . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $validated['profile_picture'] = $filename;
        }

        $user->update($validated);

        return response()->json([
            'success' => true,
            'message' => 'Profile updated successfully',
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
                'firstname' => $user->firstname,
                'lastname' => $user->lastname,
                'mobilenum' => $user->mobile_number,
                'profile_picture' => $user->profile_picture,
                'is_activated' => $user->isActivated()
            ]
        ]);
    }

    /**
     * API: Change password
     */
    public function apiChangePassword(Request $request, $userId)
    {
        // Get user from Auth facade (middleware sets it via Auth::setUser())
        $authenticatedUser = \Illuminate\Support\Facades\Auth::user();
        
        if (!$authenticatedUser) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized - User not authenticated'
            ], 401);
        }
        
        if ($authenticatedUser->id != $userId) {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden - You can only change your own password'
            ], 403);
        }

        $user = User::findOrFail($userId);

        $validated = $request->validate([
            'current_password' => 'required',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if (!Hash::check($validated['current_password'], $user->password)) {
            return response()->json([
                'success' => false,
                'error' => 'Current password is incorrect'
            ], 400);
        }

        $user->password = Hash::make($validated['password']);
        $user->save();

        return response()->json([
            'success' => true,
            'message' => 'Password changed successfully'
        ]);
    }

    /**
     * Send OTP email
     */
    private function sendOtpEmail(string $email, string $otpCode, string $username): void
    {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = env('MAIL_HOST');
        $mail->SMTPAuth = true;
        $mail->Username = env('MAIL_USERNAME');
        $mail->Password = env('MAIL_PASSWORD');
        $mail->SMTPSecure = env('MAIL_ENCRYPTION', 'tls');
        $mail->Port = env('MAIL_PORT', 587);
        $mail->setFrom(env('MAIL_FROM'), env('MAIL_FROM_NAME'));
        $mail->addAddress($email);
        $mail->isHTML(true);
        $mail->Subject = 'Account Activation - OTP Code';
        
        // Include email in URL so it works even if session expires
        $activationUrl = env('APP_URL', 'http://localhost') . '/profile/verify?email=' . urlencode($email);
        
            $mail->Body = view('frontend.emails.otp', [
            'username' => $username,
            'otpCode' => $otpCode,
            'activationUrl' => $activationUrl
        ])->render();

        if (!$mail->send()) {
            throw new PHPMailerException('Mailer Error: ' . $mail->ErrorInfo);
        }
    }
}

