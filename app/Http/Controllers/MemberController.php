<?php

namespace App\Http\Controllers;

use App\Models\GisLocation;
use App\Models\Favorite;
use App\Models\Report;
use App\Models\Announcement;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class MemberController extends Controller
{
    public function __construct()
    {
        // Don't apply middleware in constructor - let routes handle it
        // API routes use 'auth.api' middleware via routes/api.php
    }

    /**
     * View map and locations (public approved locations)
     */
    public function getLocations(Request $request)
    {
        $category = $request->input('category');
        $search = $request->input('search');
        $latitude = $request->input('latitude');
        $longitude = $request->input('longitude');
        $radius = $request->input('radius', 10); // Default 10km radius

        $query = GisLocation::where('status', 'approved');

        // Filter by category
        if ($category) {
            $query->where('category', $category);
        }

        // Search by location name
        if ($search) {
            $query->where('location', 'like', "%{$search}%");
        }

        // Filter by nearby places (if coordinates provided)
        if ($latitude && $longitude) {
            $query->selectRaw('*, (
                6371 * acos(
                    cos(radians(?)) * cos(radians(latitude)) *
                    cos(radians(longitude) - radians(?)) +
                    sin(radians(?)) * sin(radians(latitude))
                )
            ) AS distance', [$latitude, $longitude, $latitude])
            ->havingRaw('distance < ?', [$radius])
            ->orderBy('distance');
        } else {
            $query->orderBy('created_at', 'desc');
        }

        $locations = $query->with('user:id,username')->get();

        return response()->json([
            'success' => true,
            'data' => $locations
        ]);
    }

    /**
     * Get nearby places
     */
    public function getNearbyPlaces(Request $request)
    {
        $validated = $request->validate([
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'radius' => 'nullable|numeric|min:0.1|max:100',
        ]);

        $radius = $validated['radius'] ?? 10; // Default 10km

        $locations = GisLocation::selectRaw('*, (
            6371 * acos(
                cos(radians(?)) * cos(radians(latitude)) *
                cos(radians(longitude) - radians(?)) +
                sin(radians(?)) * sin(radians(latitude))
            )
        ) AS distance', [$validated['latitude'], $validated['longitude'], $validated['latitude']])
        ->where('status', 'approved')
        ->havingRaw('distance < ?', [$radius])
        ->orderBy('distance')
        ->with('user:id,username')
        ->get();

        return response()->json([
            'success' => true,
            'data' => $locations
        ]);
    }

    /**
     * Search places
     */
    public function searchPlaces(Request $request)
    {
        $validated = $request->validate([
            'query' => 'required|string|min:1',
        ]);

        $locations = GisLocation::where('status', 'approved')
            ->where(function($q) use ($validated) {
                $q->where('location', 'like', "%{$validated['query']}%")
                  ->orWhere('category', 'like', "%{$validated['query']}%")
                  ->orWhere('notes', 'like', "%{$validated['query']}%");
            })
            ->with('user:id,username')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $locations
        ]);
    }

    /**
     * Filter by category
     */
    public function filterByCategory(Request $request)
    {
        $validated = $request->validate([
            'category' => 'required|string',
        ]);

        $locations = GisLocation::where('status', 'approved')
            ->where('category', $validated['category'])
            ->with('user:id,username')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $locations
        ]);
    }

    /**
     * Get categories list
     */
    public function getCategories(Request $request)
    {
        $categories = GisLocation::where('status', 'approved')
            ->whereNotNull('category')
            ->distinct()
            ->pluck('category')
            ->filter()
            ->values();

        return response()->json([
            'success' => true,
            'data' => $categories
        ]);
    }

    /**
     * View location details
     */
    public function viewLocation(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $location = GisLocation::where('id', $id)
            ->where('status', 'approved')
            ->with('user:id,username,email')
            ->firstOrFail();

        // Check if favorited by current user
        $isFavorite = Favorite::where('user_id', $user->id)
            ->where('location_id', $id)
            ->exists();

        $location->is_favorite = $isFavorite;

        return response()->json([
            'success' => true,
            'data' => $location
        ]);
    }

    /**
     * Save favorite location
     */
    public function addFavorite(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $location = GisLocation::where('id', $id)
            ->where('status', 'approved')
            ->firstOrFail();

        $favorite = Favorite::firstOrCreate([
            'user_id' => $user->id,
            'location_id' => $id,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Location added to favorites',
            'data' => $favorite
        ]);
    }

    /**
     * Remove favorite location
     */
    public function removeFavorite(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $favorite = Favorite::where('user_id', $user->id)
            ->where('location_id', $id)
            ->firstOrFail();

        $favorite->delete();

        return response()->json([
            'success' => true,
            'message' => 'Location removed from favorites'
        ]);
    }

    /**
     * Get favorite locations
     */
    public function getFavorites(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $favorites = Favorite::where('user_id', $user->id)
            ->with('location')
            ->get()
            ->pluck('location')
            ->filter()
            ->values();

        return response()->json([
            'success' => true,
            'data' => $favorites
        ]);
    }

    /**
     * Suggest new place
     */
    public function suggestPlace(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $validated = $request->validate([
            'location' => 'required|string|max:255',
            'latitude' => 'required|numeric|between:-90,90',
            'longitude' => 'required|numeric|between:-180,180',
            'image' => 'nullable|image|max:2048',
        ]);

        // Handle image upload
        $image = null;
        if ($request->hasFile('image')) {
            $file = $request->file('image');
            $extension = $file->getClientOriginalExtension();
            $filename = 'suggestion-' . uniqid() . '.' . $extension;
            $file->move(public_path('uploads'), $filename);
            $image = $filename;
        }

        $report = Report::create([
            'user_id' => $user->id,
            'location_id' => null,
            'report_type' => 'suggest_place',
            'title' => 'New Place Suggestion',
            'description' => "Location: {$validated['location']}\nCoordinates: {$validated['latitude']}, {$validated['longitude']}",
            'image' => $image,
            'status' => 'pending',
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Place suggestion submitted successfully',
            'data' => $report
        ], 201);
    }

    /**
     * Report incorrect data
     */
    public function reportIncorrectData(Request $request, $id)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $validated = $request->validate([
            'description' => 'required|string',
        ]);

        $location = GisLocation::where('id', $id)
            ->where('status', 'approved')
            ->firstOrFail();

        $report = Report::create([
            'user_id' => $user->id,
            'location_id' => $id,
            'report_type' => 'incorrect_data',
            'title' => 'Incorrect Data Report',
            'description' => $validated['description'],
            'status' => 'pending',
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Report submitted successfully',
            'data' => $report
        ], 201);
    }

    /**
     * Share location link
     */
    public function shareLocation(Request $request, $id)
    {
        $location = GisLocation::where('id', $id)
            ->where('status', 'approved')
            ->firstOrFail();

        $shareLink = url("/location/{$id}");

        return response()->json([
            'success' => true,
            'data' => [
                'share_link' => $shareLink,
                'location' => $location
            ]
        ]);
    }

    /**
     * Get my suggestions
     */
    public function getMySuggestions(Request $request)
    {
        $user = $this->getAuthenticatedUser();
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $suggestions = Report::where('user_id', $user->id)
            ->where('report_type', 'suggest_place')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $suggestions
        ]);
    }

    /**
     * Get announcements
     */
    public function getAnnouncements(Request $request)
    {
        $announcements = Announcement::where('is_active', true)
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $announcements
        ]);
    }
}

