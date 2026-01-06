<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'location_id',
        'report_type',
        'title',
        'description',
        'image',
        'status',
        'admin_response',
    ];

    /**
     * Report type constants
     */
    const TYPE_INCORRECT_DATA = 'incorrect_data';
    const TYPE_SUGGEST_PLACE = 'suggest_place';
    const TYPE_OTHER = 'other';

    /**
     * Status constants
     */
    const STATUS_PENDING = 'pending';
    const STATUS_REVIEWED = 'reviewed';
    const STATUS_RESOLVED = 'resolved';
    const STATUS_DISMISSED = 'dismissed';

    /**
     * Get the user that submitted the report
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the location being reported
     */
    public function location()
    {
        return $this->belongsTo(GisLocation::class);
    }
}

