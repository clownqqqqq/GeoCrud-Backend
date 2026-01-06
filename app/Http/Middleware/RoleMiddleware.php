<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RoleMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string  ...$roles
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ...$roles)
    {
        $user = $request->user();
        
        if (!$user) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }
            return redirect('/auth/login');
        }

        // Check if user is blocked
        if ($user->isBlocked()) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json(['error' => 'Account is blocked'], 403);
            }
            return redirect('/auth/login')->withErrors(['error' => 'Your account has been blocked']);
        }

        // Check if user has required role
        if (!in_array($user->role, $roles)) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json(['error' => 'Insufficient permissions'], 403);
            }
            return redirect('/dashboard')->withErrors(['error' => 'You do not have permission to access this page']);
        }

        return $next($request);
    }
}

