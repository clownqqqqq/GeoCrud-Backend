<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Http\Request;

class Controller extends BaseController
{
    use AuthorizesRequests, ValidatesRequests;
    
    /**
     * Get authenticated user from request (works with ApiAuthMiddleware)
     */
    protected function getAuthenticatedUser(Request $request = null)
    {
        $request = $request ?? request();
        
        // Try request attributes FIRST (set by ApiAuthMiddleware) - this is most reliable
        $user = $request->attributes->get('user');
        if ($user) {
            \Log::info('Controller - User found in request attributes', ['user_id' => $user->id]);
            return $user;
        }
        
        // Try request()->user() 
        $user = $request->user();
        if ($user) {
            \Log::info('Controller - User found via request()->user()', ['user_id' => $user->id]);
            return $user;
        }
        
        // Try Auth facade
        try {
            $user = \Illuminate\Support\Facades\Auth::user();
            if ($user) {
                \Log::info('Controller - User found via Auth::user()', ['user_id' => $user->id]);
                return $user;
            }
        } catch (\Exception $e) {
            \Log::warning('Controller - Auth::user() failed', ['error' => $e->getMessage()]);
        }
        
        // Try request data
        $user = $request->get('user');
        if ($user) {
            \Log::info('Controller - User found in request data', ['user_id' => is_object($user) ? $user->id : 'unknown']);
            return $user;
        }
        
        \Log::warning('Controller - No user found in any location', [
            'has_attributes_user' => $request->attributes->has('user'),
            'request_user' => $request->user() ? 'exists' : 'null',
            'url' => $request->fullUrl()
        ]);
        
        return null;
    }
}

