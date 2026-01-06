<?php

namespace App\Http\Controllers;

use App\Models\GisLocation;
use App\Models\Notification;
use App\Models\ActivityLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class StaffController extends Controller
{
    public function __construct()
    {
        // Don't apply middleware in constructor - let routes handle it
        // API routes use 'auth.api' middleware via routes/api.php
    }

    /**
     * Add new location (submission)
     */
    public function addLocation(Request $request)
    {
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

        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        // Ensure coordinates are stored as numeric values (float)
        $location = GisLocation::create([
            'user_id' => $user->id,
            'location' => $validated['location'],
            'latitude' => (float)$validated['latitude'],
            'longitude' => (float)$validated['longitude'],
            'image' => $image,
            'category' => $validated['category'] ?? null,
            'notes' => $validated['notes'] ?? null,
            'status' => 'pending', // Staff submissions start as pending
        ]);

        // Log activity
        ActivityLog::create([
            'user_id' => $user->id,
            'action' => 'add_location',
            'description' => "Location '{$location->location}' submitted",
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Location submitted successfully. Waiting for admin approval.',
            'data' => $location
        ], 201);
    }

    /**
     * Edit own submission
     */
    public function editLocation(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $location = GisLocation::findOrFail($id);
        
        // Only allow editing own submissions
        if ($location->user_id !== $user->id) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }

        // Only allow editing if pending or rejected
        if ($location->status === 'approved') {
            return response()->json(['error' => 'Cannot edit approved locations'], 400);
        }

        $validated = $request->validate([
            'location' => 'required|string|max:255',
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'image' => 'nullable|image|max:2048',
            'category' => 'nullable|string|max:50',
            'notes' => 'nullable|string',
        ]);

        if ($request->hasFile('image')) {
            if ($location->image && file_exists(public_path('uploads/' . $location->image))) {
                unlink(public_path('uploads/' . $location->image));
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
        // Reset status to pending after edit
        $validated['status'] = 'pending';
        $location->update($validated);

        return response()->json([
            'success' => true,
            'message' => 'Location updated successfully. Waiting for admin approval.',
            'data' => $location
        ]);
    }

    /**
     * Delete own submission
     */
    public function deleteLocation(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $location = GisLocation::findOrFail($id);
        
        // Only allow deleting own submissions
        if ($location->user_id !== $user->id) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }

        if ($location->image && file_exists(public_path('uploads/' . $location->image))) {
            unlink(public_path('uploads/' . $location->image));
        }

        $location->delete();

        return response()->json([
            'success' => true,
            'message' => 'Location deleted successfully'
        ]);
    }

    /**
     * Get own submissions with status
     */
    public function getMySubmissions(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $status = $request->input('status');
        
        $query = GisLocation::where('user_id', $user->id);
        
        if ($status) {
            $query->where('status', $status);
        }

        $locations = $query->orderBy('created_at', 'desc')->get();

        // Explicitly return all fields to ensure coordinates are included
        $locationsData = $locations->map(function ($location) {
            return [
                'id' => $location->id,
                'user_id' => $location->user_id,
                'location' => $location->location,
                'latitude' => $location->latitude !== null ? (float)$location->latitude : null,
                'longitude' => $location->longitude !== null ? (float)$location->longitude : null,
                'image' => $location->image,
                'category' => $location->category,
                'notes' => $location->notes,
                'status' => $location->status,
                'admin_feedback' => $location->admin_feedback,
                'created_at' => $location->created_at,
                'updated_at' => $location->updated_at,
            ];
        });

        return response()->json([
            'success' => true,
            'data' => $locationsData
        ]);
    }

    /**
     * Get submission status
     */
    public function getSubmissionStatus(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $location = GisLocation::where('id', $id)
            ->where('user_id', $user->id)
            ->firstOrFail();

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $location->id,
                'status' => $location->status,
                'admin_feedback' => $location->admin_feedback,
                'created_at' => $location->created_at,
                'updated_at' => $location->updated_at,
            ]
        ]);
    }

    /**
     * Get notifications
     */
    public function getNotifications(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $notifications = Notification::where('user_id', $user->id)
            ->orderBy('created_at', 'desc')
            ->limit(50)
            ->get();

        return response()->json([
            'success' => true,
            'data' => $notifications
        ]);
    }

    /**
     * Mark notification as read
     */
    public function markNotificationRead(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $notification = Notification::where('id', $id)
            ->where('user_id', $user->id)
            ->firstOrFail();

        $notification->is_read = true;
        $notification->save();

        return response()->json([
            'success' => true,
            'message' => 'Notification marked as read'
        ]);
    }


    /**
     * Get submission history
     */
    public function getSubmissionHistory(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $locations = GisLocation::where('user_id', $user->id)
            ->select('id', 'location', 'status', 'created_at', 'updated_at')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $locations
        ]);
    }
}

