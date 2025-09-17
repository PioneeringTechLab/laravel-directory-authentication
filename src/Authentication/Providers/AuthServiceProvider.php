<?php

namespace CSUNMetaLab\Authentication\Providers;

use Illuminate\Support\ServiceProvider,
	Illuminate\Support\Facades\Auth,
	Illuminate\Support\Facades\App,
	Illuminate\Auth\Guard;

class AuthServiceProvider extends ServiceProvider
{
	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register(): void {
		// if the provider method exists then we are at least in Laravel 5.1
		if(method_exists('Illuminate\Auth\AuthManager', 'provider')) {
			// LDAP auth extension
			Auth::provider('ldap', function($app, array $config) {
				return new \CSUNMetaLab\Authentication\Providers\UserProviderLDAP();
			});

			// database auth extension
			Auth::provider('dbauth', function($app, array $config) {
				return new \CSUNMetaLab\Authentication\Providers\UserProviderDB();
			});
		}
		else
		{
			// Laravel 5.0
			Auth::extend('ldap', function() {
				return new Guard(new \CSUNMetaLab\Authentication\Providers\UserProviderLDAP,
					App::make('session.store'));
			});
			Auth::extend('dbauth', function() {
				return new Guard(new \CSUNMetaLab\Authentication\Providers\UserProviderDB,
					App::make('session.store'));
			});
		}
	}

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot(): void {
		$this->publishes([
        	__DIR__.'/../config/ldap.php' => config_path('ldap.php'),
    	]);

    	$this->publishes([
    		__DIR__.'/../config/dbauth.php' => config_path('dbauth.php'),
    	]);
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides(): array {
		return array();
	}

}
