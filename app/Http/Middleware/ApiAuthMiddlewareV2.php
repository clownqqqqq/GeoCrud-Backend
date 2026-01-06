<?php

    namespace App\Http\Middleware;

    use Closure;
    use Illuminate\Http\Request;
    use App\Models\User;
    use Illuminate\Support\Facades\Auth;

    class ApiAuthMiddlewareV2
    {
            // NEW MIDDLEWARE VERSION - NOT CACHED BY OPCACHE
            // Created to bypass OPcache issues with old middleware
            // This is a fresh file, so OPcache won't have it cached
            
            /**
             * Handle an incoming request.
             *
             * @param  \Illuminate\Http\Request  $request
             * @param  \Closure  $next
             * @return mixed
             */
            public function handle(Request $request, Closure $next)
            {
                // Log all headers for debugging
                \Log::info('API Auth Middleware V2 - Request received', [
                    'url' => $request->fullUrl(),
                    'method' => $request->method(),
                    'all_headers' => $request->headers->all(),
                ]);
                
                // Try multiple ways to get the token
                $token = $request->bearerToken();
                
                // If bearerToken() didn't work, try header directly
                if (!$token) {
                    $authHeader = $request->header('Authorization');
                    \Log::info('API Auth V2 - bearerToken() returned null, checking Authorization header', [
                        'authorization_header' => $authHeader,
                    ]);
                    if ($authHeader) {
                        // Handle "Bearer token" format (case-insensitive)
                        if (stripos($authHeader, 'Bearer ') === 0) {
                            $token = trim(substr($authHeader, 7));
                        } elseif (stripos($authHeader, 'Bearer') === 0) {
                            // Handle "Bearer token" with different spacing
                            $token = trim(substr($authHeader, 6));
                        } else {
                            $token = trim($authHeader);
                        }
                    }
                }

                // Also check query parameter as fallback
                if (!$token) {
                    $token = $request->query('token');
                }

                if (!$token) {
                    \Log::warning('API Auth V2 - No token found', [
                        'url' => $request->fullUrl(),
                        'method' => $request->method(),
                        'bearerToken' => $request->bearerToken(),
                        'authorization_header' => $request->header('Authorization'),
                    ]);
                    return response()->json([
                        'success' => false,
                        'error' => 'Unauthorized',
                        'message' => 'Authentication token required. Please log in.'
                    ], 401);
                }

                // Trim whitespace from token (headers may have whitespace)
                $token = trim($token);
                
                // Validate token format (should be 64 hex characters)
                if (strlen($token) !== 64 || !ctype_xdigit($token)) {
                    \Log::warning('API Auth V2 - Invalid token format', [
                        'token_length' => strlen($token),
                        'token_preview' => substr($token, 0, 20) . '...',
                        'is_hex' => ctype_xdigit($token),
                        'url' => $request->fullUrl()
                    ]);
                    return response()->json([
                        'success' => false,
                        'error' => 'Unauthorized',
                        'message' => 'Invalid authentication token format. Please log in again.'
                    ], 401);
                }
                
                // Log token for debugging
                \Log::info('API Auth V2 - Token received', [
                    'token_length' => strlen($token),
                    'token_preview' => substr($token, 0, 20) . '...',
                    'token_full' => $token, // Log full token for debugging
                    'url' => $request->fullUrl(),
                    'method' => $request->method(),
                ]);

                // Find user by token - use exact binary comparison
                // First try direct database query (fastest)
                $user = User::where('auth_token', $token)->first();
                
                // If not found, try with raw DB query to ensure exact match
                if (!$user) {
                    $userRow = \Illuminate\Support\Facades\DB::table('users')
                        ->where('auth_token', $token)
                        ->first();
                    
                    if ($userRow) {
                        $user = User::find($userRow->id);
                    }
                }
                
                // If still not found, check for whitespace issues in database
                if (!$user) {
                    // Get all users with tokens and compare exactly
                    $usersWithTokens = User::whereNotNull('auth_token')->get();
                    foreach ($usersWithTokens as $u) {
                        // Exact binary comparison
                        if ($u->auth_token === $token) {
                            $user = $u;
                            \Log::info('API Auth V2 - User found via exact comparison', [
                                'user_id' => $user->id,
                                'method' => 'exact_comparison'
                            ]);
                            break;
                        }
                    }
                }

                if (!$user) {
                    // Log for debugging - check all tokens in database
                    $allTokens = User::whereNotNull('auth_token')->pluck('auth_token', 'id')->toArray();
                    
                    // Check if any token is similar (for debugging)
                    $similarTokens = [];
                    foreach ($allTokens as $userId => $dbToken) {
                        if (substr($dbToken, 0, 20) === substr($token, 0, 20)) {
                            $similarTokens[$userId] = [
                                'preview' => substr($dbToken, 0, 20) . '...',
                                'length' => strlen($dbToken),
                                'full' => $dbToken,
                                'matches' => $dbToken === $token
                            ];
                        }
                    }
                    
                    \Log::warning('API Auth V2 Failed - Token not found in database', [
                        'token_length' => strlen($token),
                        'token_preview' => substr($token, 0, 20) . '...',
                        'token_full' => $token, // Log full token for comparison
                        'token_is_hex' => ctype_xdigit($token),
                        'url' => $request->fullUrl(),
                        'method' => $request->method(),
                        'users_with_tokens' => array_keys($allTokens),
                        'token_previews_in_db' => array_map(function($t) { return substr($t, 0, 20) . '...'; }, $allTokens),
                        'similar_tokens_found' => $similarTokens,
                        'total_tokens_in_db' => count($allTokens)
                    ]);
                    
                    // Return user-friendly error message
                    return response()->json([
                        'success' => false,
                        'error' => 'Unauthorized',
                        'message' => 'Invalid or expired authentication token. Please log in again.'
                    ], 401);
                }
                
                \Log::info('API Auth V2 - Token validated successfully', [
                    'user_id' => $user->id,
                    'username' => $user->username,
                    'url' => $request->fullUrl()
                ]);

                // Check if token is expired (only if column exists)
                if (isset($user->token_expires_at) && $user->token_expires_at && $user->token_expires_at < now()) {
                    \Log::warning('API Auth V2 - Token expired', ['user_id' => $user->id]);
                    return response()->json([
                        'success' => false,
                        'error' => 'Unauthorized',
                        'message' => 'Your session has expired. Please log in again.'
                    ], 401);
                }

                // Check if user is blocked
                if ($user->isBlocked()) {
                    \Log::warning('API Auth V2 - User is blocked', ['user_id' => $user->id]);
                    return response()->json([
                        'success' => false,
                        'error' => 'Forbidden',
                        'message' => 'Your account has been blocked. Please contact the administrator.'
                    ], 403);
                }

                // Attach user to request - use multiple methods to ensure it works
                // METHOD 1: Set in request attributes (most reliable)
                $request->attributes->set('user', $user);
                
                // METHOD 2: Set user resolver for request()->user()
                $request->setUserResolver(function () use ($user) {
                    return $user;
                });
                
                // METHOD 3: Set user in Auth facade
                try {
                    Auth::setUser($user);
                } catch (\Exception $e) {
                    \Log::warning('API Auth V2 - Failed to set user in Auth facade', ['error' => $e->getMessage()]);
                }
                
                // METHOD 4: Merge into request data
                $request->merge(['user' => $user]);
                
                \Log::info('API Auth V2 - User set in request, passing to controller', [
                    'user_id' => $user->id,
                    'username' => $user->username,
                    'has_attributes_user' => $request->attributes->has('user'),
                    'request_user_exists' => $request->user() ? 'yes' : 'no'
                ]);

                return $next($request);
            }
    }

