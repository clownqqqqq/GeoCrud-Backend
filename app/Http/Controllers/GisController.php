<?php

namespace App\Http\Controllers;

use App\Models\GisLocation;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class GisController extends Controller
{
    public function __construct()
    {
        // Only apply session auth to web routes (not API routes)
        // API routes use 'auth.api' middleware via routes/api.php
        $this->middleware('auth.session')->except([
            'apiIndex', 'apiShow', 'apiStore', 'apiUpdate', 'apiDestroy'
        ]);
    }

    /**
     * Display a listing of GIS locations
     */
    public function index(Request $request)
    {
        $userId = session('user_id');
        $searchQuery = $request->input('search', '');

        $user = User::find($userId);
        
        // All non-admin users see only approved locations (rejected locations are hidden)
        // Admin sees only approved locations by default (pending locations should be reviewed separately)
        if ($user->role === 'member') {
            // Members see only approved locations
            $query = GisLocation::where('status', 'approved');
        } elseif ($user->role === 'staff') {
            // Staff see only approved locations (not their pending ones)
            $query = GisLocation::where('status', 'approved');
        } else {
            // Admin sees only approved locations (pending locations are reviewed via /admin/pending-locations)
            $query = GisLocation::where('status', 'approved');
        }

        if (!empty($searchQuery)) {
            $query->where('location', 'like', '%' . $searchQuery . '%');
        }

        $gisLocations = $query->orderBy('created_at', 'desc')->get();

        $success = session('gis_success');
        $error = session('gis_error');
        session()->forget(['gis_success', 'gis_error']);

        return view('frontend.gis.index', [
            'title' => 'GIS Locations',
            'gis_locations' => $gisLocations,
            'success' => $success,
            'error' => $error,
            'search_query' => $searchQuery,
            'current_user' => $user,
            'auth_token' => session('auth_token') ?? $user->auth_token ?? '',
        ]);
    }

    /**
     * Show the form for creating a new GIS location
     */
    public function create()
    {
        $user = User::find(session('user_id'));
        
        // Only admin and staff can create locations
        if ($user->role === 'member') {
            return redirect('/gis')->withErrors(['error' => 'Members cannot create locations. Use "Suggest Place" feature instead.']);
        }
        
        return view('frontend.gis.create', ['title' => 'Add GIS Location']);
    }

    /**
     * Store a newly created GIS location
     */
    public function store(Request $request)
    {
        $user = User::find(session('user_id'));
        
        // Only admin and staff can create locations
        if ($user->role === 'member') {
            return redirect('/gis')->withErrors(['error' => 'Members cannot create locations. Use "Suggest Place" feature instead.']);
        }
        
        $validated = $request->validate([
            'location' => 'required|string|max:255',
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'image' => 'nullable|image|max:2048',
        ]);

        $image = null;
        if ($request->hasFile('image')) {
            $file = $request->file('image');
            $extension = $file->getClientOriginalExtension();
            $filename = 'gis-' . uniqid() . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $image = $filename;
        }

        // Set status: Admin locations are auto-approved, Staff locations are pending
        $status = $user->isAdmin() ? 'approved' : 'pending';

        // Ensure coordinates are stored as numeric values (float)
        $gisLocation = GisLocation::create([
            'user_id' => session('user_id'),
            'location' => $validated['location'],
            'latitude' => (float)$validated['latitude'],
            'longitude' => (float)$validated['longitude'],
            'image' => $image,
            'status' => $status,
        ]);

        Log::info('GIS location created', [
            'user_id' => session('user_id'),
            'gis_id' => $gisLocation->id,
            'status' => $status,
        ]);

        $message = $status === 'approved' 
            ? 'GIS location created successfully!' 
            : 'GIS location submitted successfully! Waiting for admin approval.';
            
        return redirect('/gis')->with('gis_success', $message);
    }

    /**
     * Show the form for editing a GIS location
     */
    public function edit($id)
    {
        $user = User::find(session('user_id'));
        
        // Only admin and staff can edit locations
        if ($user->role === 'member') {
            return redirect('/gis')->withErrors(['error' => 'Members cannot edit locations.']);
        }
        
        // Staff can edit any approved location, Admin can edit any location
        $query = GisLocation::where('id', $id);
        if ($user->role === 'staff') {
            // Staff can only edit approved locations (including those created from member suggestions)
            $query->where('status', 'approved');
        }
        // Admin can edit any location (no restrictions)
        
        $gisLocation = $query->firstOrFail();

        return view('frontend.gis.edit', [
            'title' => 'Edit GIS Location',
            'gis_location' => $gisLocation
        ]);
    }

    /**
     * Update the specified GIS location
     */
    public function update(Request $request, $id)
    {
        $user = User::find(session('user_id'));
        
        // Only admin and staff can update locations
        if ($user->role === 'member') {
            return redirect('/gis')->withErrors(['error' => 'Members cannot edit locations.']);
        }
        
        // Staff can update any approved location, Admin can update any location
        $query = GisLocation::where('id', $id);
        if ($user->role === 'staff') {
            // Staff can only update approved locations (including those created from member suggestions)
            $query->where('status', 'approved');
        }
        // Admin can update any location (no restrictions)
        
        $gisLocation = $query->firstOrFail();

        $validated = $request->validate([
            'location' => 'required|string|max:255',
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'image' => 'nullable|image|max:2048',
        ]);

        if ($request->hasFile('image')) {
            // Delete old image if exists
            if ($gisLocation->image && file_exists(public_path('uploads/' . $gisLocation->image))) {
                unlink(public_path('uploads/' . $gisLocation->image));
            }

            $file = $request->file('image');
            $extension = $file->getClientOriginalExtension();
            $filename = 'gis-' . uniqid() . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $validated['image'] = $filename;
        }

        // Ensure coordinates are stored as numeric values (float)
        $validated['latitude'] = (float)$validated['latitude'];
        $validated['longitude'] = (float)$validated['longitude'];
        $gisLocation->update($validated);

        return redirect('/gis')->with('gis_success', 'GIS location updated successfully!');
    }

    /**
     * Remove the specified GIS location
     */
    public function destroy($id)
    {
        try {
            $user = User::find(session('user_id'));
            
            if (!$user) {
                return redirect('/auth/login')->withErrors(['error' => 'Please login first']);
            }
            
            // Only admin and staff can delete locations
            if ($user->role === 'member') {
                return redirect('/gis')->withErrors(['error' => 'Members cannot delete locations.']);
            }
            
            // Staff can only delete their own locations (pending or approved), Admin can delete any
            $query = GisLocation::where('id', $id);
            if ($user->role === 'staff') {
                // Staff can delete their own locations regardless of status (pending, approved, or even rejected if they still exist)
                $query->where('user_id', $user->id);
            } elseif ($user->role === 'admin') {
                // Admin can delete any location (including rejected if they exist)
                // No additional restrictions for admin
            }
            
            $gisLocation = $query->first();
            
            if (!$gisLocation) {
                // Log for debugging
                Log::warning('Delete location failed', [
                    'location_id' => $id,
                    'user_id' => $user->id,
                    'user_role' => $user->role,
                    'location_exists' => GisLocation::where('id', $id)->exists(),
                    'location_user_id' => GisLocation::where('id', $id)->value('user_id'),
                ]);
                return redirect('/gis')->withErrors(['error' => 'Location not found, already deleted, or you do not have permission to delete it.']);
            }
            
            // Additional check: Staff can only delete their own locations
            if ($user->role === 'staff' && $gisLocation->user_id !== $user->id) {
                return redirect('/gis')->withErrors(['error' => 'You can only delete your own locations.']);
            }

            // Store location name for success message
            $locationName = $gisLocation->location;

            // Delete image if exists
            if ($gisLocation->image && file_exists(public_path('uploads/' . $gisLocation->image))) {
                try {
                    unlink(public_path('uploads/' . $gisLocation->image));
                } catch (\Exception $e) {
                    Log::warning('Failed to delete location image', [
                        'location_id' => $id,
                        'image' => $gisLocation->image,
                        'error' => $e->getMessage()
                    ]);
                }
            }

            $gisLocation->delete();

            return redirect('/gis')->with('gis_success', "Location '{$locationName}' deleted successfully!");
        } catch (\Exception $e) {
            Log::error('Error deleting location', [
                'error' => $e->getMessage(),
                'location_id' => $id,
                'user_id' => session('user_id')
            ]);
            return redirect('/gis')->withErrors(['error' => 'An error occurred while deleting the location.']);
        }
    }

    /**
     * API: List GIS locations
     */
    public function apiIndex(Request $request)
    {
        // Get user using base controller method (tries multiple ways)
        $user = $this->getAuthenticatedUser();
        
        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized',
                'message' => 'User not authenticated. Please log in again.'
            ], 401);
        }
        
        // Role-based access - rejected locations are always hidden from all users
        // All users (including admin) see only approved locations in the dashboard
        // Only show locations with status = 'approved' (exclude NULL, pending, rejected)
        // Use whereNotNull to ensure status column exists and is not NULL
        // Use whereRaw with LOWER() for case-insensitive matching in case of data inconsistencies
        $query = GisLocation::whereNotNull('status')
            ->whereRaw('LOWER(status) = ?', ['approved']);
        
        // Note: We don't allow status filtering in the dashboard - only approved locations are shown
        // If someone tries to filter by status, we ignore it and still show only approved
        
        // Search functionality
        if ($request->has('search') && !empty($request->input('search'))) {
            $searchTerm = $request->input('search');
            $query->where('location', 'like', '%' . $searchTerm . '%');
        }
        
        $gisLocations = $query->with('user:id,username,email')
            ->orderBy('created_at', 'desc')
            ->get();

        // Log for debugging (remove in production if needed)
        Log::info('Dashboard locations query', [
            'user_id' => $user->id,
            'user_role' => $user->role,
            'locations_count' => $gisLocations->count(),
            'location_ids' => $gisLocations->pluck('id')->toArray(),
            'location_statuses' => $gisLocations->pluck('status')->toArray(),
        ]);

        return response()->json([
            'success' => true,
            'data' => $gisLocations
        ]);
    }

    /**
     * API: Get a single GIS location
     */
    public function apiShow($id)
    {
        $gisLocation = GisLocation::findOrFail($id);
        
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized',
                'message' => 'User not authenticated. Please log in again.'
            ], 401);
        }
        
        // Admin can view any location, Staff can view any approved location, others can only view their own
        if ($user->isAdmin()) {
            // Admin can view any location (no restriction)
        } elseif ($user->isStaff()) {
            // Staff can view any approved location (for editing)
            if ($gisLocation->status !== 'approved' && $gisLocation->user_id !== $user->id) {
                return response()->json([
                    'success' => false,
                    'error' => 'Forbidden',
                    'message' => 'You can only view approved locations or your own submissions.'
                ], 403);
            }
        } else {
            // Members and others can only view their own locations
            if ($gisLocation->user_id !== $user->id) {
                return response()->json([
                    'success' => false,
                    'error' => 'Forbidden',
                    'message' => 'You do not have permission to access this location.'
                ], 403);
            }
        }

        // Ensure we return a proper JSON object with all fields
        return response()->json([
            'id' => $gisLocation->id,
            'user_id' => $gisLocation->user_id,
            'location' => $gisLocation->location,
            'latitude' => (string) $gisLocation->latitude,
            'longitude' => (string) $gisLocation->longitude,
            'image' => $gisLocation->image,
            'category' => $gisLocation->category,
            'notes' => $gisLocation->notes,
            'status' => $gisLocation->status,
            'admin_feedback' => $gisLocation->admin_feedback,
            'created_at' => $gisLocation->created_at,
            'updated_at' => $gisLocation->updated_at,
        ]);
    }

    /**
     * API: Create GIS location
     */
    public function apiStore(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        
        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized',
                'message' => 'User not authenticated. Please log in again.'
            ], 401);
        }
        
        // Members cannot create locations directly - they must use "Suggest Place" feature
        if ($user->role === 'member') {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden',
                'message' => 'Members cannot create locations directly. Please use the "Suggest Place" feature instead.'
            ], 403);
        }
        
        $validated = $request->validate([
            'location' => 'required|string|max:255',
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'image' => 'nullable|image|max:2048',
            'category' => 'nullable|string|max:50',
            'notes' => 'nullable|string',
        ]);

        $image = null;
        if ($request->hasFile('image')) {
            $file = $request->file('image');
            $extension = $file->getClientOriginalExtension();
            $filename = 'gis-' . uniqid() . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $image = $filename;
        }

        // Admin locations are auto-approved, staff locations are pending (require admin approval)
        $status = $user->isAdmin() ? 'approved' : 'pending';

        // Ensure coordinates are stored as numeric values (float)
        $gisLocation = GisLocation::create([
            'user_id' => $user->id,
            'location' => $validated['location'],
            'latitude' => (float)$validated['latitude'],
            'longitude' => (float)$validated['longitude'],
            'image' => $image,
            'category' => $validated['category'] ?? null,
            'notes' => $validated['notes'] ?? null,
            'status' => $status,
        ]);

        return response()->json($gisLocation, 201);
    }

    /**
     * API: Update GIS location
     */
    public function apiUpdate(Request $request, $id)
    {
        $gisLocation = GisLocation::findOrFail($id);
        
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized',
                'message' => 'User not authenticated. Please log in again.'
            ], 401);
        }
        
        // Only admin and staff can update locations
        if ($user->role === 'member') {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden',
                'message' => 'Members cannot update locations.'
            ], 403);
        }
        
        // Admin can update any location, Staff can only update approved locations (any approved location)
        if ($user->role === 'staff' && $gisLocation->status !== 'approved') {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden',
                'message' => 'Staff can only update approved locations.'
            ], 403);
        }
        
        // Admin can update any location (no user_id check needed)

        $validated = $request->validate([
            'location' => 'required|string|max:255',
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'image' => 'nullable|image|max:2048',
        ]);

        if ($request->hasFile('image')) {
            if ($gisLocation->image && file_exists(public_path('uploads/' . $gisLocation->image))) {
                unlink(public_path('uploads/' . $gisLocation->image));
            }

            $file = $request->file('image');
            $extension = $file->getClientOriginalExtension();
            $filename = 'gis-' . uniqid() . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $validated['image'] = $filename;
        }

        // Ensure coordinates are stored as numeric values (float)
        $validated['latitude'] = (float)$validated['latitude'];
        $validated['longitude'] = (float)$validated['longitude'];
        $gisLocation->update($validated);

        return response()->json($gisLocation);
    }

    /**
     * API: Delete GIS location
     */
    public function apiDestroy($id)
    {
        $gisLocation = GisLocation::findOrFail($id);
        
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => 'Unauthorized',
                'message' => 'User not authenticated. Please log in again.'
            ], 401);
        }
        
        // Only admin and staff can delete locations
        if ($user->role === 'member') {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden',
                'message' => 'Members cannot delete locations.'
            ], 403);
        }
        
        // Admin can delete any location, Staff can only delete their own locations
        if ($user->role === 'staff' && $gisLocation->user_id !== $user->id) {
            return response()->json([
                'success' => false,
                'error' => 'Forbidden',
                'message' => 'You can only delete your own locations.'
            ], 403);
        }
        
        // Admin can delete any location (no user_id check needed)

        if ($gisLocation->image && file_exists(public_path('uploads/' . $gisLocation->image))) {
            unlink(public_path('uploads/' . $gisLocation->image));
        }

        $gisLocation->delete();

        return response()->json([
            'success' => true,
            'message' => 'GIS location deleted successfully'
        ]);
    }
}

