<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\User;

class SessionAuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (!session('user_id')) {
            if ($request->expectsJson()) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }
            // Store the intended URL so we can redirect back after login
            session(['intended_url' => $request->fullUrl()]);
            return redirect('/auth/login')->with('error', 'Please login to access this page.');
        }

        // Validate auth_token from session against database (like Slim version)
        if (session('auth_token')) {
            // Find user by token (more secure - validates token exists in DB)
            $user = User::where('auth_token', session('auth_token'))->first();
            
            // If token is invalid or doesn't match the session user_id, logout
            if (!$user || $user->id !== session('user_id')) {
                session()->flush();
                if ($request->expectsJson()) {
                    return response()->json(['error' => 'Invalid token'], 401);
                }
                return redirect('/auth/login')->withErrors(['error' => 'Invalid session']);
            }
            
            // Check if user is blocked - log them out if they are
            if ($user->isBlocked()) {
                session()->flush();
                if ($request->expectsJson()) {
                    return response()->json(['error' => 'Account is blocked'], 403);
                }
                return redirect('/auth/login')->withErrors(['error' => 'Your account has been blocked. Please contact the administrator.']);
            }
        } else {
            // If no auth_token in session, verify user exists by user_id
            $user = User::find(session('user_id'));
            if (!$user) {
                session()->flush();
                if ($request->expectsJson()) {
                    return response()->json(['error' => 'User not found'], 401);
                }
                return redirect('/auth/login')->withErrors(['error' => 'User not found']);
            }
        }

        // Check if user is blocked - log them out if they are
        if ($user->isBlocked()) {
            session()->flush();
            if ($request->expectsJson()) {
                return response()->json(['error' => 'Account is blocked'], 403);
            }
            return redirect('/auth/login')->withErrors(['error' => 'Your account has been blocked. Please contact the administrator.']);
        }

        return $next($request);
    }
}

