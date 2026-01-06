<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        // Share current_user with all views that use app layout
        view()->composer('frontend.layouts.app', function ($view) {
            $currentUser = null;
            if (session('user_id')) {
                $currentUser = \App\Models\User::find(session('user_id'));
            }
            $view->with('current_user', $currentUser);
        });
    }
}

