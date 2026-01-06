<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Hash;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'username',
        'email',
        'firstname',
        'lastname',
        'mobile_number',
        'password',
        'profile_picture',
        'email_verified',
        'email_verified_at',
        'auth_token',
        'token_expires_at',
        'role',
        'status',
        'assigned_area',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'auth_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified' => 'boolean',
        'email_verified_at' => 'datetime',
        'token_expires_at' => 'datetime',
    ];
    
    /**
     * Role constants
     */
    const ROLE_ADMIN = 'admin';
    const ROLE_STAFF = 'staff';
    const ROLE_MEMBER = 'member';
    
    /**
     * Status constants
     */
    const STATUS_ACTIVE = 'active';
    const STATUS_BLOCKED = 'blocked';

    /**
     * Get the user's full name.
     */
    public function getFullNameAttribute(): string
    {
        return trim("{$this->firstname} {$this->lastname}");
    }

    /**
     * Check if user is activated.
     */
    public function isActivated(): bool
    {
        return $this->email_verified;
    }

    /**
     * Get the GIS locations for the user.
     */
    public function gisLocations()
    {
        return $this->hasMany(GisLocation::class);
    }

    /**
     * Get the email verification records for the user.
     */
    public function emailVerifications()
    {
        return $this->hasMany(EmailVerification::class);
    }

    /**
     * Get the password reset records for the user.
     */
    public function passwordResets()
    {
        return $this->hasMany(PasswordReset::class);
    }
    
    /**
     * Check if user is admin
     */
    public function isAdmin(): bool
    {
        return $this->role === self::ROLE_ADMIN;
    }
    
    /**
     * Check if user is staff
     */
    public function isStaff(): bool
    {
        return $this->role === self::ROLE_STAFF;
    }
    
    /**
     * Check if user is member
     */
    public function isMember(): bool
    {
        return $this->role === self::ROLE_MEMBER;
    }
    
    /**
     * Check if user is active
     */
    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }
    
    /**
     * Check if user is blocked
     */
    public function isBlocked(): bool
    {
        return $this->status === self::STATUS_BLOCKED;
    }
    
    /**
     * Get notifications for the user
     */
    public function notifications()
    {
        return $this->hasMany(Notification::class);
    }
    
    /**
     * Get reports submitted by the user
     */
    public function reports()
    {
        return $this->hasMany(Report::class);
    }
    
    /**
     * Get favorite locations
     */
    public function favorites()
    {
        return $this->hasMany(Favorite::class);
    }
    
    /**
     * Get activity logs
     */
    public function activityLogs()
    {
        return $this->hasMany(ActivityLog::class);
    }
    
    /**
     * Get announcements created by admin
     */
    public function announcements()
    {
        return $this->hasMany(Announcement::class, 'admin_id');
    }
}

