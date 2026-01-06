<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('email_verification', function (Blueprint $table) {
            if (!Schema::hasColumn('email_verification', 'created_at')) {
                $table->timestamp('created_at')
                    ->nullable()
                    ->useCurrent()
                    ->after('expires_at');
            }

            if (!Schema::hasColumn('email_verification', 'updated_at')) {
                $table->timestamp('updated_at')
                    ->nullable()
                    ->useCurrent()
                    ->useCurrentOnUpdate()
                    ->after('created_at');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('email_verification', function (Blueprint $table) {
            if (Schema::hasColumn('email_verification', 'updated_at')) {
                $table->dropColumn('updated_at');
            }

            if (Schema::hasColumn('email_verification', 'created_at')) {
                $table->dropColumn('created_at');
            }
        });
    }
};

