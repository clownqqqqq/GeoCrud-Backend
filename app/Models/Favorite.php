<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Favorite extends Model
{
    use HasFactory;

    public $timestamps = true;

    protected $fillable = [
        'user_id',
        'location_id',
    ];

    /**
     * Get the user that favorited the location
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the location that was favorited
     */
    public function location()
    {
        return $this->belongsTo(GisLocation::class);
    }
}

