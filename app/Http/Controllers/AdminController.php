<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\GisLocation;
use App\Models\Notification;
use App\Models\Report;
use App\Models\Announcement;
use App\Models\ActivityLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;

class AdminController extends Controller
{
    public function __construct()
    {
        // Only apply API auth and role middleware to API routes
        // Web routes will use session auth
    }
    
    /**
     * Handle role assignment (Web)
     */
    public function assignRoleWeb(Request $request, $id)
    {
        $admin = \App\Models\User::find(session('user_id'));
        
        if (!$admin || !$admin->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $user = User::findOrFail($id);
        
        // Prevent admin from changing their own role
        if ($user->id === $admin->id) {
            return redirect('/admin/users')->withErrors(['error' => 'You cannot change your own role.']);
        }
        
        $validated = $request->validate([
            'role' => 'required|in:admin,staff,member',
        ]);
        
        $user->role = $validated['role'];
        
        $user->save();
        
        // Log activity
        ActivityLog::create([
            'user_id' => $admin->id,
            'action' => 'assign_role',
            'description' => "Role {$validated['role']} assigned to user {$user->username}",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);
        
        return redirect('/admin/users')->with('success', "Role assigned successfully to {$user->username}");
    }
    
    /**
     * Handle toggle user status (Web)
     */
    public function toggleUserStatusWeb(Request $request, $id)
    {
        try {
            $admin = \App\Models\User::find(session('user_id'));
            
            if (!$admin || !$admin->isAdmin()) {
                return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
            }
            
            $user = User::findOrFail($id);
            
            if ($user->id === $admin->id) {
                return redirect('/admin/users')->withErrors(['error' => 'Cannot block your own account']);
            }
            
            $user->status = $user->status === 'active' ? 'blocked' : 'active';
            $user->save();
            
            // Log activity (with error handling in case table doesn't exist)
            try {
                ActivityLog::create([
                    'user_id' => $admin->id,
                    'action' => $user->status === 'blocked' ? 'block_user' : 'unblock_user',
                    'description' => "User {$user->username} was {$user->status}",
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'created_at' => now(),
                ]);
            } catch (\Exception $e) {
                // Log error but don't fail the block operation
                Log::error('Failed to create activity log', [
                    'error' => $e->getMessage(),
                    'user_id' => $admin->id,
                    'target_user_id' => $user->id
                ]);
            }
            
            return redirect('/admin/users')->with('success', "User {$user->username} {$user->status} successfully");
        } catch (\Exception $e) {
            Log::error('Error toggling user status', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'user_id' => $id,
                'admin_id' => session('user_id')
            ]);
            return redirect('/admin/users')->withErrors(['error' => 'An error occurred while updating user status: ' . $e->getMessage()]);
        }
    }
    
    /**
     * Handle delete user (Web)
     */
    public function deleteUserWeb(Request $request, $id)
    {
        try {
            $admin = \App\Models\User::find(session('user_id'));
            
            if (!$admin || !$admin->isAdmin()) {
                return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
            }
            
            $user = User::findOrFail($id);
            
            // Prevent admin from deleting their own account
            if ($user->id === $admin->id) {
                return redirect('/admin/users')->withErrors(['error' => 'You cannot delete your own account.']);
            }
            
            $username = $user->username;
            
            // Delete related records first (if any)
            // Delete favorites
            \App\Models\Favorite::where('user_id', $user->id)->delete();
            
            // Delete notifications
            \App\Models\Notification::where('user_id', $user->id)->delete();
            
            // Delete reports/suggestions
            \App\Models\Report::where('user_id', $user->id)->delete();
            
            // Delete activity logs
            \App\Models\ActivityLog::where('user_id', $user->id)->delete();
            
            // Delete GIS locations created by this user
            \App\Models\GisLocation::where('user_id', $user->id)->delete();
            
            // Finally delete the user
            $user->delete();
            
            // Log activity
            try {
                ActivityLog::create([
                    'user_id' => $admin->id,
                    'action' => 'delete_user',
                    'description' => "User {$username} was deleted",
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'created_at' => now(),
                ]);
            } catch (\Exception $e) {
                // Log error but don't fail the delete operation
                Log::error('Failed to create activity log', [
                    'error' => $e->getMessage(),
                    'user_id' => $admin->id,
                    'deleted_user_id' => $id
                ]);
            }
            
            return redirect('/admin/users')->with('success', "User {$username} has been deleted successfully");
        } catch (\Exception $e) {
            Log::error('Error deleting user', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'user_id' => $id,
                'admin_id' => session('user_id')
            ]);
            return redirect('/admin/users')->withErrors(['error' => 'An error occurred while deleting the user: ' . $e->getMessage()]);
        }
    }
    
    /**
     * Show admin dashboard (Web)
     */
    public function dashboardWeb(Request $request)
    {
        $userId = session('user_id');
        
        if (!$userId) {
            return redirect('/auth/login')->withErrors(['error' => 'Please login first']);
        }
        
        $user = User::find($userId);
        
        if (!$user) {
            return redirect('/auth/login')->withErrors(['error' => 'User not found']);
        }
        
        if (!$user->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $totalUsers = User::count();
        $totalLocations = GisLocation::count();
        $pendingRequests = GisLocation::where('status', 'pending')->count();
        $pendingSuggestions = \App\Models\Report::where('report_type', 'suggest_place')
                                                ->where('status', 'pending')
                                                ->count();
        $totalStaff = User::where('role', 'staff')->count();
        $totalMembers = User::where('role', 'member')->count();
        $blockedUsers = User::where('status', 'blocked')->count();
        
        return view('frontend.admin.dashboard', [
            'title' => 'Admin Dashboard',
            'current_user' => $user,
            'total_users' => $totalUsers,
            'total_locations' => $totalLocations,
            'pending_requests' => $pendingRequests,
            'pending_suggestions' => $pendingSuggestions,
            'total_staff' => $totalStaff,
            'total_members' => $totalMembers,
            'blocked_users' => $blockedUsers,
        ]);
    }
    
    /**
     * Show users management page (Web)
     */
    public function usersWeb(Request $request)
    {
        $userId = session('user_id');
        
        if (!$userId) {
            return redirect('/auth/login')->withErrors(['error' => 'Please login first']);
        }
        
        $user = User::find($userId);
        
        if (!$user) {
            return redirect('/auth/login')->withErrors(['error' => 'User not found']);
        }
        
        if (!$user->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $role = $request->input('role');
        $status = $request->input('status');
        $search = $request->input('search');
        
        $query = User::query();
        
        if ($role) {
            $query->where('role', $role);
        }
        
        if ($status) {
            $query->where('status', $status);
        }
        
        if ($search) {
            $query->where(function($q) use ($search) {
                $q->where('username', 'like', "%{$search}%")
                  ->orWhere('email', 'like', "%{$search}%")
                  ->orWhere('firstname', 'like', "%{$search}%")
                  ->orWhere('lastname', 'like', "%{$search}%");
            });
        }
        
        $users = $query->orderBy('created_at', 'desc')->paginate(20);
        
        return view('frontend.admin.users', [
            'title' => 'User Management',
            'current_user' => $user,
            'users' => $users,
            'filters' => [
                'role' => $role,
                'status' => $status,
                'search' => $search,
            ]
        ]);
    }

    /**
     * Show edit user form (Web)
     */
    public function editUserWeb(Request $request, $id)
    {
        $admin = User::find(session('user_id'));

        if (!$admin || !$admin->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }

        $user = User::findOrFail($id);

        return view('frontend.admin.edit-user', [
            'title' => 'Edit User',
            'current_user' => $admin,
            'user' => $user,
        ]);
    }

    /**
     * Handle update user (Web)
     */
    public function updateUserWeb(Request $request, $id)
    {
        $admin = User::find(session('user_id'));

        if (!$admin || !$admin->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }

        $user = User::findOrFail($id);

        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users,username,' . $user->id,
            'email' => 'required|email|max:100|unique:users,email,' . $user->id,
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobile_number' => 'nullable|string|max:20',
            'role' => 'required|in:admin,staff,member',
            'status' => 'required|in:active,blocked',
            'password' => 'nullable|string|min:6|confirmed',
        ]);

        $user->username = $validated['username'];
        $user->email = $validated['email'];
        $user->firstname = $validated['firstname'] ?? null;
        $user->lastname = $validated['lastname'] ?? null;
        $user->mobile_number = $validated['mobile_number'] ?? null;
        $user->role = $validated['role'];
        $user->status = $validated['status'];

        // Only update password if provided
        if (!empty($validated['password'])) {
            $user->password = Hash::make($validated['password']);
        }

        $user->save();

        // Log activity (best-effort)
        try {
            ActivityLog::create([
                'user_id' => $admin->id,
                'action' => 'update_user',
                'description' => "User {$user->username} updated by admin",
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to create activity log for updateUserWeb', [
                'error' => $e->getMessage(),
                'admin_id' => $admin->id ?? null,
                'target_user_id' => $user->id,
            ]);
        }

        return redirect()->route('admin.users')->with('success', "User {$user->username} updated successfully");
    }

    /**
     * Get dashboard statistics
     */
    public function dashboard(Request $request)
    {
        $totalUsers = User::count();
        $totalLocations = GisLocation::count();
        $pendingRequests = GisLocation::where('status', 'pending')->count();
        $totalStaff = User::where('role', 'staff')->count();
        $totalMembers = User::where('role', 'member')->count();
        $blockedUsers = User::where('status', 'blocked')->count();

        return response()->json([
            'success' => true,
            'data' => [
                'total_users' => $totalUsers,
                'total_locations' => $totalLocations,
                'pending_requests' => $pendingRequests,
                'total_staff' => $totalStaff,
                'total_members' => $totalMembers,
                'blocked_users' => $blockedUsers,
            ]
        ]);
    }

    /**
     * Show create user form (Web)
     */
    public function showCreateUserForm(Request $request)
    {
        $userId = session('user_id');
        
        if (!$userId) {
            return redirect('/auth/login')->withErrors(['error' => 'Please login first']);
        }
        
        $user = User::find($userId);
        
        if (!$user || !$user->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        return view('frontend.admin.create-user', [
            'title' => 'Create New User',
            'current_user' => $user,
        ]);
    }
    
    /**
     * Handle create user (Web)
     */
    public function createUserWeb(Request $request)
    {
        $admin = User::find(session('user_id'));
        
        if (!$admin || !$admin->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users',
            'email' => 'required|email|max:100|unique:users',
            'password' => 'required|string|min:6',
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobile_number' => 'nullable|string|max:20',
            'role' => 'required|in:admin,staff,member',
        ]);
        
        $user = User::create([
            'username' => $validated['username'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'firstname' => $validated['firstname'] ?? null,
            'lastname' => $validated['lastname'] ?? null,
            'mobile_number' => $validated['mobile_number'] ?? null,
            'role' => $validated['role'],
            'status' => 'active',
            'email_verified' => true,
            'email_verified_at' => now(),
            'profile_picture' => 'default-profile.svg',
        ]);
        
        // Log activity
        ActivityLog::create([
            'user_id' => $admin->id,
            'action' => 'create_user',
            'description' => "User {$user->username} created with role {$user->role}",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);
        
        return redirect('/admin/users')->with('success', "User {$user->username} created successfully with role {$user->role}");
    }
    
    /**
     * Get list of users
     */
    public function getUsers(Request $request)
    {
        $role = $request->input('role');
        $status = $request->input('status');
        $search = $request->input('search');

        $query = User::query();

        if ($role) {
            $query->where('role', $role);
        }

        if ($status) {
            $query->where('status', $status);
        }

        if ($search) {
            $query->where(function($q) use ($search) {
                $q->where('username', 'like', "%{$search}%")
                  ->orWhere('email', 'like', "%{$search}%")
                  ->orWhere('firstname', 'like', "%{$search}%")
                  ->orWhere('lastname', 'like', "%{$search}%");
            });
        }

        $users = $query->select('id', 'username', 'email', 'firstname', 'lastname', 'role', 'status', 'created_at')
            ->orderBy('created_at', 'desc')
            ->paginate(20);

        return response()->json([
            'success' => true,
            'data' => $users
        ]);
    }

    /**
     * Block/Unblock user
     */
    public function toggleUserStatus(Request $request, $id)
    {
        $user = User::findOrFail($id);
        
        if ($user->id === $request->user()->id) {
            return response()->json(['error' => 'Cannot block your own account'], 400);
        }

        $user->status = $user->status === 'active' ? 'blocked' : 'active';
        $user->save();

        // Log activity
        ActivityLog::create([
            'user_id' => $request->user()->id,
            'action' => $user->status === 'blocked' ? 'block_user' : 'unblock_user',
            'description' => "User {$user->username} was {$user->status}",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return response()->json([
            'success' => true,
            'message' => "User {$user->status} successfully",
            'data' => $user
        ]);
    }

    /**
     * Assign staff role
     */
    public function assignRole(Request $request, $id)
    {
        $validated = $request->validate([
            'role' => 'required|in:admin,staff,member',
        ]);

        $user = User::findOrFail($id);
        $user->role = $validated['role'];
        
        $user->save();

        // Log activity
        ActivityLog::create([
            'user_id' => $request->user()->id,
            'action' => 'assign_role',
            'description' => "Role {$validated['role']} assigned to user {$user->username}",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Role assigned successfully',
            'data' => $user
        ]);
    }

    /**
     * Create user with specific role (Admin only)
     */
    public function createUser(Request $request)
    {
        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users',
            'email' => 'required|email|max:100|unique:users',
            'password' => 'required|string|min:6',
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobile_number' => 'nullable|string|max:20',
            'role' => 'required|in:admin,staff,member',
        ]);

        $user = User::create([
            'username' => $validated['username'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'firstname' => $validated['firstname'] ?? null,
            'lastname' => $validated['lastname'] ?? null,
            'mobile_number' => $validated['mobile_number'] ?? null,
            'role' => $validated['role'],
            'status' => 'active',
            'email_verified' => true, // Admin-created users are auto-verified
            'email_verified_at' => now(),
        ]);

        // Log activity
        ActivityLog::create([
            'user_id' => $request->user()->id,
            'action' => 'create_user',
            'description' => "User {$user->username} created with role {$user->role}",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'User created successfully',
            'data' => $user
        ], 201);
    }

    /**
     * Update user (API)
     */
    public function updateUser(Request $request, $id)
    {
        $user = User::findOrFail($id);
        $admin = $request->user();

        $validated = $request->validate([
            'username' => 'required|string|max:50|unique:users,username,' . $user->id,
            'email' => 'required|email|max:100|unique:users,email,' . $user->id,
            'firstname' => 'nullable|string|max:100',
            'lastname' => 'nullable|string|max:100',
            'mobile_number' => 'nullable|string|max:20',
            'role' => 'required|in:admin,staff,member',
            'status' => 'required|in:active,blocked',
            'password' => 'nullable|string|min:6|confirmed',
        ]);

        $user->username = $validated['username'];
        $user->email = $validated['email'];
        $user->firstname = $validated['firstname'] ?? null;
        $user->lastname = $validated['lastname'] ?? null;
        $user->mobile_number = $validated['mobile_number'] ?? null;
        $user->role = $validated['role'];
        $user->status = $validated['status'];

        // Only update password if provided
        if (!empty($validated['password'])) {
            $user->password = Hash::make($validated['password']);
        }

        $user->save();

        // Log activity (best-effort)
        try {
            ActivityLog::create([
                'user_id' => $admin->id,
                'action' => 'update_user',
                'description' => "User {$user->username} updated by admin",
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to create activity log for updateUser', [
                'error' => $e->getMessage(),
                'admin_id' => $admin->id ?? null,
                'target_user_id' => $user->id,
            ]);
        }

        return response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'data' => $user
        ]);
    }

    /**
     * Delete user (API)
     */
    public function deleteUser(Request $request, $id)
    {
        try {
            $user = User::findOrFail($id);
            $admin = $request->user();

            // Prevent admin from deleting their own account
            if ($user->id === $admin->id) {
                return response()->json([
                    'success' => false,
                    'error' => 'Cannot delete your own account'
                ], 400);
            }

            $username = $user->username;

            // Delete user's locations
            GisLocation::where('user_id', $user->id)->delete();
            
            // Delete user's notifications
            Notification::where('user_id', $user->id)->delete();
            
            // Delete user's reports
            Report::where('user_id', $user->id)->delete();
            
            // Finally delete the user
            $user->delete();

            // Log activity (best-effort)
            try {
                ActivityLog::create([
                    'user_id' => $admin->id,
                    'action' => 'delete_user',
                    'description' => "User {$username} was deleted",
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                ]);
            } catch (\Exception $e) {
                Log::error('Failed to create activity log for deleteUser', [
                    'error' => $e->getMessage(),
                    'admin_id' => $admin->id ?? null,
                    'deleted_user_id' => $id
                ]);
            }

            return response()->json([
                'success' => true,
                'message' => "User {$username} deleted successfully"
            ]);
        } catch (\Exception $e) {
            Log::error('Error deleting user', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'user_id' => $id,
                'admin_id' => $request->user()->id ?? null
            ]);
            
            return response()->json([
                'success' => false,
                'error' => 'An error occurred while deleting the user: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Approve/Reject location submission
     */
    public function reviewLocation(Request $request, $id)
    {
        $validated = $request->validate([
            'action' => 'required|in:approve,reject',
            'admin_feedback' => 'nullable|string',
        ]);

        $location = GisLocation::findOrFail($id);
        
        $location->status = $validated['action'] === 'approve' ? 'approved' : 'rejected';
        
        if (isset($validated['admin_feedback'])) {
            $location->admin_feedback = $validated['admin_feedback'];
        }
        
        $location->save();

        // Send notification to staff
        Notification::create([
            'user_id' => $location->user_id,
            'title' => 'Location Submission ' . ucfirst($location->status),
            'message' => $validated['admin_feedback'] ?? "Your location submission has been {$location->status}.",
            'type' => $location->status === 'approved' ? 'success' : 'warning',
        ]);

        // Log activity
        ActivityLog::create([
            'user_id' => $request->user()->id,
            'action' => 'review_location',
            'description' => "Location {$location->id} was {$location->status}",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return response()->json([
            'success' => true,
            'message' => "Location {$location->status} successfully",
            'data' => $location
        ]);
    }

    /**
     * Get pending location submissions
     */
    public function getPendingLocations(Request $request)
    {
        $locations = GisLocation::where('status', 'pending')
            ->with('user:id,username,email')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $locations
        ]);
    }
    
    /**
     * Show pending locations page (Web)
     */
    public function pendingLocationsWeb(Request $request)
    {
        $userId = session('user_id');
        
        if (!$userId) {
            return redirect('/auth/login')->withErrors(['error' => 'Please login first']);
        }
        
        $user = User::find($userId);
        
        if (!$user || !$user->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $locations = GisLocation::where('status', 'pending')
            ->with('user:id,username,email')
            ->orderBy('created_at', 'desc')
            ->get();
        
        return view('frontend.admin.pending-locations', [
            'title' => 'Pending Location Submissions',
            'current_user' => $user,
            'locations' => $locations,
        ]);
    }
    
    /**
     * Handle approve/reject location (Web)
     */
    public function reviewLocationWeb(Request $request, $id)
    {
        try {
            $admin = User::find(session('user_id'));
            
            if (!$admin || !$admin->isAdmin()) {
                return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
            }
            
            $validated = $request->validate([
                'action' => 'required|in:approve,reject',
                'admin_feedback' => 'nullable|string|max:500',
            ]);
            
            $location = GisLocation::findOrFail($id);
            
            $location->status = $validated['action'] === 'approve' ? 'approved' : 'rejected';
            
            if (isset($validated['admin_feedback']) && !empty($validated['admin_feedback'])) {
                $location->admin_feedback = $validated['admin_feedback'];
            }
            
            $location->save();
            
            // Store location info before potential deletion
            $locationName = $location->location;
            $locationId = $location->id;
            $locationUserId = $location->user_id;
            
            // If rejected, delete the location to clean up
            if ($location->status === 'rejected') {
                // Delete associated image if exists
                if ($location->image && file_exists(public_path('uploads/' . $location->image))) {
                    try {
                        unlink(public_path('uploads/' . $location->image));
                    } catch (\Exception $e) {
                        Log::warning('Failed to delete rejected location image', [
                            'location_id' => $location->id,
                            'image' => $location->image,
                            'error' => $e->getMessage()
                        ]);
                    }
                }
                
                // Delete the location
                $location->delete();
                
                // Notification message for deleted location
                $notificationMessage = $validated['admin_feedback'] ?? "Your location submission has been rejected and removed from the system.";
                $activityDescription = "Location '{$locationName}' (ID: {$locationId}) was rejected and deleted";
                $successMessage = "Location has been rejected and removed from the system.";
            } else {
                // Notification message for approved location
                $notificationMessage = $validated['admin_feedback'] ?? "Your location submission '{$locationName}' has been {$location->status}.";
                $activityDescription = "Location '{$locationName}' (ID: {$locationId}) was {$location->status}";
                $successMessage = "Location '{$locationName}' has been {$location->status} successfully.";
            }
        
            // Send notification to staff
            try {
                Notification::create([
                    'user_id' => $locationUserId,
                    'title' => 'Location Submission ' . ucfirst($location->status),
                    'message' => $notificationMessage,
                    'type' => $location->status === 'approved' ? 'success' : 'warning',
                    'is_read' => false,
                    'created_at' => now(),
                ]);
            } catch (\Exception $e) {
                // Log error but don't fail the review process
                Log::error('Failed to create notification', [
                    'error' => $e->getMessage(),
                    'user_id' => $locationUserId,
                    'location_id' => $locationId
                ]);
            }
            
            // Log activity
            try {
                ActivityLog::create([
                    'user_id' => $admin->id,
                    'action' => 'review_location',
                    'description' => $activityDescription,
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'created_at' => now(),
                ]);
            } catch (\Exception $e) {
                // Log error but don't fail the review process
                Log::error('Failed to create activity log', [
                    'error' => $e->getMessage(),
                    'user_id' => $admin->id,
                    'location_id' => $locationId
                ]);
            }
            
            return redirect('/admin/pending-locations')->with('success', $successMessage);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return redirect('/admin/pending-locations')->withErrors($e->errors())->withInput();
        } catch (\Exception $e) {
            Log::error('Error reviewing location', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'location_id' => $id,
                'user_id' => session('user_id')
            ]);
            return redirect('/admin/pending-locations')->withErrors(['error' => 'An error occurred while reviewing the location: ' . $e->getMessage()]);
        }
    }

    /**
     * Get system activity logs
     */
    public function getActivityLogs(Request $request)
    {
        $limit = $request->input('limit', 50);
        $action = $request->input('action');

        $query = ActivityLog::with('user:id,username');

        if ($action) {
            $query->where('action', $action);
        }

        $logs = $query->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();

        return response()->json([
            'success' => true,
            'data' => $logs
        ]);
    }

    /**
     * Get user reports
     */
    public function getReports(Request $request)
    {
        $status = $request->input('status', 'pending');
        $reportType = $request->input('report_type');

        $query = Report::where('status', $status);
        
        // Filter by report_type if provided
        if ($reportType) {
            $query->where('report_type', $reportType);
        }
        
        $reports = $query->with(['user:id,username,email', 'location:id,location'])
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $reports
        ]);
    }

    /**
     * Update report status
     */
    public function updateReport(Request $request, $id)
    {
        $validated = $request->validate([
            'status' => 'required|in:pending,reviewed,resolved,dismissed',
            'admin_response' => 'nullable|string',
        ]);

        $report = Report::findOrFail($id);
        $oldStatus = $report->status;
        $report->status = $validated['status'];
        
        if (isset($validated['admin_response'])) {
            $report->admin_response = $validated['admin_response'];
        }
        
        $report->save();

        // If this is a place suggestion being resolved, create the location
        if ($report->report_type === 'suggest_place' && $validated['status'] === 'resolved' && $oldStatus !== 'resolved') {
            // Parse the suggestion description to extract location details
            $description = $report->description;
            $lines = explode("\n", $description);
            
            $locationData = [];
            foreach ($lines as $line) {
                if (strpos($line, 'Location:') === 0) {
                    $locationData['location'] = trim(str_replace('Location:', '', $line));
                } elseif (strpos($line, 'Coordinates:') === 0) {
                    $coords = trim(str_replace('Coordinates:', '', $line));
                    $coordsArray = explode(',', $coords);
                    if (count($coordsArray) >= 2) {
                        $lat = trim($coordsArray[0]);
                        $lng = trim($coordsArray[1]);
                        
                        // Validate and convert to numeric values
                        $latNum = is_numeric($lat) ? (float)$lat : null;
                        $lngNum = is_numeric($lng) ? (float)$lng : null;
                        
                        // Validate ranges: Latitude -90 to 90, Longitude -180 to 180
                        if ($latNum !== null && $latNum >= -90 && $latNum <= 90) {
                            $locationData['latitude'] = $latNum;
                        }
                        if ($lngNum !== null && $lngNum >= -180 && $lngNum <= 180) {
                            $locationData['longitude'] = $lngNum;
                        }
                    }
                } elseif (strpos($line, 'Category:') === 0) {
                    $locationData['category'] = trim(str_replace('Category:', '', $line));
                }
            }
            
            // Create the location if we have the required data
            if (isset($locationData['location']) && isset($locationData['latitude']) && isset($locationData['longitude'])) {
                try {
                    $admin = $this->getAuthenticatedUser();
                    if (!$admin) {
                        $admin = $request->user();
                    }
                    
                    GisLocation::create([
                        'user_id' => $admin ? $admin->id : $report->user_id,
                        'location' => $locationData['location'],
                        'latitude' => $locationData['latitude'],
                        'longitude' => $locationData['longitude'],
                        'category' => $locationData['category'] ?? null,
                        'image' => $report->image, // Use the image from suggestion
                        'status' => 'approved', // Approved locations show in all dashboards
                    ]);
                    
                    // Send notification to member
                    $message = "Your place suggestion '{$locationData['location']}' has been accepted! The location has been created in the system.";
                    if ($validated['admin_response']) {
                        $message .= " Response: {$validated['admin_response']}";
                    }
                    
                    try {
                        Notification::create([
                            'user_id' => $report->user_id,
                            'title' => 'Suggestion Accepted',
                            'message' => $message,
                            'type' => 'success',
                            'is_read' => false,
                        ]);
                    } catch (\Exception $e) {
                        Log::warning('Failed to send notification for accepted suggestion', [
                            'report_id' => $report->id,
                            'error' => $e->getMessage()
                        ]);
                    }
                } catch (\Exception $e) {
                    Log::error('Failed to create location from approved suggestion', [
                        'report_id' => $report->id,
                        'error' => $e->getMessage(),
                        'trace' => $e->getTraceAsString()
                    ]);
                }
            } else {
                Log::warning('Cannot create location from suggestion - missing required data', [
                    'report_id' => $report->id,
                    'location_data' => $locationData
                ]);
            }
        } else {
            // Send notification for non-suggestion reports or other status changes
            Notification::create([
                'user_id' => $report->user_id,
                'title' => 'Report Update',
                'message' => "Your report has been {$validated['status']}." . ($validated['admin_response'] ? " Response: {$validated['admin_response']}" : ''),
                'type' => 'info',
            ]);
        }

        return response()->json([
            'success' => true,
            'message' => 'Report updated successfully',
            'data' => $report
        ]);
    }

    /**
     * Show place suggestions page (Web)
     */
    public function suggestionsWeb(Request $request)
    {
        $userId = session('user_id');
        
        if (!$userId) {
            return redirect('/auth/login')->withErrors(['error' => 'Please login first']);
        }
        
        $user = User::find($userId);
        
        if (!$user || !$user->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $suggestions = Report::where('report_type', 'suggest_place')
            ->where('status', 'pending')
            ->with('user:id,username,email')
            ->orderBy('created_at', 'desc')
            ->get();
        
        return view('frontend.admin.suggestions', [
            'title' => 'Place Suggestions',
            'current_user' => $user,
            'suggestions' => $suggestions,
        ]);
    }
    
    /**
     * Handle approve/reject suggestion (Web)
     */
    public function reviewSuggestionWeb(Request $request, $id)
    {
        try {
            $admin = User::find(session('user_id'));
            
            if (!$admin || !$admin->isAdmin()) {
                return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
            }
            
            $validated = $request->validate([
                'action' => 'required|in:approve,create_location,dismiss',
                'admin_response' => 'nullable|string|max:500',
            ]);
            
            $suggestion = Report::findOrFail($id);
            
            // Handle 'approve' action - same as 'create_location'
            if ($validated['action'] === 'approve') {
                $validated['action'] = 'create_location';
            }
            
            if ($validated['action'] === 'dismiss') {
                $suggestion->status = 'dismissed';
                if (isset($validated['admin_response'])) {
                    $suggestion->admin_response = $validated['admin_response'];
                }
                $suggestion->save();
                
                // Send notification to member
                try {
                    $descLines = explode("\n", $suggestion->description);
                    $locationName = '';
                    foreach ($descLines as $line) {
                        if (strpos($line, 'Location:') === 0) {
                            $locationName = trim(str_replace('Location:', '', $line));
                            break;
                        }
                    }
                    $message = "Your place suggestion '{$locationName}' has been dismissed.";
                    if ($suggestion->admin_response) {
                        $message .= " Response: {$suggestion->admin_response}";
                    }
                    
                    Notification::create([
                        'user_id' => $suggestion->user_id,
                        'title' => 'Suggestion Update',
                        'message' => $message,
                        'type' => 'info',
                        'is_read' => false,
                    ]);
                } catch (\Exception $e) {
                    Log::warning('Failed to send notification for dismissed suggestion', [
                        'suggestion_id' => $suggestion->id,
                        'error' => $e->getMessage()
                    ]);
                }
                
                $successMessage = 'Suggestion dismissed successfully.';
            } elseif ($validated['action'] === 'create_location') {
                // Parse the suggestion description to extract location details
                $description = $suggestion->description;
                $lines = explode("\n", $description);
                
                $locationData = [];
                foreach ($lines as $line) {
                    if (strpos($line, 'Location:') === 0) {
                        $locationData['location'] = trim(str_replace('Location:', '', $line));
                    } elseif (strpos($line, 'Coordinates:') === 0) {
                        $coords = trim(str_replace('Coordinates:', '', $line));
                        $coordsArray = explode(',', $coords);
                        if (count($coordsArray) >= 2) {
                            $lat = trim($coordsArray[0]);
                            $lng = trim($coordsArray[1]);
                            
                            // Validate and convert to numeric values
                            $latNum = is_numeric($lat) ? (float)$lat : null;
                            $lngNum = is_numeric($lng) ? (float)$lng : null;
                            
                            // Validate ranges: Latitude -90 to 90, Longitude -180 to 180
                            if ($latNum !== null && $latNum >= -90 && $latNum <= 90) {
                                $locationData['latitude'] = $latNum;
                            }
                            if ($lngNum !== null && $lngNum >= -180 && $lngNum <= 180) {
                                $locationData['longitude'] = $lngNum;
                            }
                        }
                    } elseif (strpos($line, 'Category:') === 0) {
                        $locationData['category'] = trim(str_replace('Category:', '', $line));
                    }
                }
                
                // Create the location if we have valid data and coordinates
                if (isset($locationData['location']) && 
                    isset($locationData['latitude']) && 
                    isset($locationData['longitude']) &&
                    is_numeric($locationData['latitude']) &&
                    is_numeric($locationData['longitude'])) {
                    
                    // Final validation: ensure coordinates are within valid ranges
                    $lat = (float)$locationData['latitude'];
                    $lng = (float)$locationData['longitude'];
                    
                    if ($lat < -90 || $lat > 90 || $lng < -180 || $lng > 180) {
                        return redirect('/admin/suggestions')->withErrors([
                            'error' => 'Invalid coordinates. Latitude must be between -90 and 90, Longitude between -180 and 180.'
                        ]);
                    }
                    
                    GisLocation::create([
                        'user_id' => $admin->id, // Admin creates it
                        'location' => $locationData['location'],
                        'latitude' => $lat,
                        'longitude' => $lng,
                        'category' => $locationData['category'] ?? null,
                        'image' => $suggestion->image, // Use the image from suggestion
                        'status' => 'approved',
                    ]);
                    
                    $suggestion->status = 'resolved';
                    if (isset($validated['admin_response'])) {
                        $suggestion->admin_response = $validated['admin_response'];
                    }
                    $suggestion->save();
                    
                    // Send notification to member
                    try {
                        $message = "Your place suggestion '{$locationData['location']}' has been accepted! The location has been created in the system.";
                        if ($suggestion->admin_response) {
                            $message .= " Response: {$suggestion->admin_response}";
                        }
                        
                        Notification::create([
                            'user_id' => $suggestion->user_id,
                            'title' => 'Suggestion Accepted',
                            'message' => $message,
                            'type' => 'success',
                            'is_read' => false,
                        ]);
                    } catch (\Exception $e) {
                        Log::warning('Failed to send notification for accepted suggestion', [
                            'suggestion_id' => $suggestion->id,
                            'error' => $e->getMessage()
                        ]);
                    }
                    
                    $successMessage = "Location '{$locationData['location']}' has been created and is now visible in All Locations (approved status)!";
                } else {
                    return redirect('/admin/suggestions')->withErrors(['error' => 'Unable to parse suggestion details.']);
                }
            }
            
            return redirect('/admin/suggestions')->with('success', $successMessage);
        } catch (\Exception $e) {
            Log::error('Error reviewing suggestion', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'suggestion_id' => $id,
                'user_id' => session('user_id')
            ]);
            return redirect('/admin/suggestions')->withErrors(['error' => 'An error occurred while reviewing the suggestion: ' . $e->getMessage()]);
        }
    }

    /**
     * Send notification to user(s)
     */
    public function sendNotification(Request $request)
    {
        $validated = $request->validate([
            'user_id' => 'nullable|exists:users,id',
            'title' => 'required|string|max:255',
            'message' => 'required|string',
            'type' => 'nullable|in:info,success,warning,error',
        ]);

        // If user_id is null, send to all users
        if ($validated['user_id']) {
            Notification::create([
                'user_id' => $validated['user_id'],
                'title' => $validated['title'],
                'message' => $validated['message'],
                'type' => $validated['type'] ?? 'info',
            ]);
        } else {
            // Send to all active users
            $users = User::where('status', 'active')->pluck('id');
            foreach ($users as $userId) {
                Notification::create([
                    'user_id' => $userId,
                    'title' => $validated['title'],
                    'message' => $validated['message'],
                    'type' => $validated['type'] ?? 'info',
                ]);
            }
        }

        return response()->json([
            'success' => true,
            'message' => 'Notification sent successfully'
        ]);
    }

    /**
     * Create announcement
     */
    public function createAnnouncement(Request $request)
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'is_active' => 'nullable|boolean',
        ]);

        $announcement = Announcement::create([
            'admin_id' => $request->user()->id,
            'title' => $validated['title'],
            'content' => $validated['content'],
            'is_active' => $validated['is_active'] ?? true,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Announcement created successfully',
            'data' => $announcement
        ]);
    }

    /**
     * Get announcements
     */
    public function getAnnouncements(Request $request)
    {
        $announcements = Announcement::where('is_active', true)
            ->with('admin:id,username')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $announcements
        ]);
    }
    
    /**
     * Approve a location (Admin only)
     */
    public function approveLocation($id)
    {
        $admin = User::find(session('user_id'));
        
        if (!$admin || !$admin->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $location = GisLocation::findOrFail($id);
        $location->status = 'approved';
        $location->save();
        
        return redirect('/gis')->with('gis_success', 'Location "' . $location->location . '" has been approved!');
    }
    
    /**
     * Reject a location (Admin only)
     */
    public function rejectLocation($id)
    {
        $admin = User::find(session('user_id'));
        
        if (!$admin || !$admin->isAdmin()) {
            return redirect('/gis')->withErrors(['error' => 'Access denied. Admin only.']);
        }
        
        $location = GisLocation::findOrFail($id);
        $location->status = 'rejected';
        $location->save();
        
        return redirect('/gis')->with('gis_success', 'Location "' . $location->location . '" has been rejected.');
    }
}

