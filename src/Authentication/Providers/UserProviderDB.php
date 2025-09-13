<?php

namespace CSUNMetaLab\Authentication\Providers;

use Exception;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
Use Illuminate\Support\Facades\Hash;

use CSUNMetaLab\Authentication\Exceptions\InvalidUserModelException;

/**
 * Service provider handler that provides database authentication operations.
 */
class UserProviderDB implements UserProvider
{
	private $ldap;
	private $modelName;
	private $allow_no_pass;

	// values for searching
	private $username;
	private $password;

	/**
	 * Constructs a new UserProviderDB object. This can throw an instance of
	 * InvalidUserModelException if the auth model configuration parameter
	 * does not exist or if the model class does not exist.
	 *
	 * @throws InvalidUserModelException
	 */
	public function __construct() {
		// set the searching and lookup attributes
		$this->username = config('dbauth.username');
		$this->password = config('dbauth.password');

		// set the model name to use as the user model (Laravel 5.2 and up)
		$this->modelName = config('auth.providers.users.model');
		if(empty($this->modelName)) {
			// try to read from the configuration value used by Laravel 5.0
			// and 5.1 as a fallback
			$this->modelName = config('auth.model');
			if(empty($this->modelName)) {
				// no valid model configuration so throw an exception immediately
				// to prevent any further problems
				throw new InvalidUserModelException(
					"No valid user model could be found in your auth configuration"
				);
			}
		}

		// next, throw an exception if the class specified does not exist
		if(!class_exists($this->modelName)) {
			throw new InvalidUserModelException(
				"The auth user model {$this->modelName} does not exist"
			);
		}

		// set whether blank passwords are allowed to be used for auth
		$this->allow_no_pass = config('dbauth.allow_no_pass');
	}

	/**
 	 * Retrieves the user with the specified credentials from the database.
 	 * Returns null if the model instance could not be found.
 	 *
 	 * @param array $credentials The credentials to use
 	 * @return User|boolean|null
 	 */
    public function retrieveByCredentials(array $credentials) {
    	$u = $credentials['username'];
    	$p = $credentials['password'];

    	$m = $this->modelName;

    	// attempt to auth with the credentials provided
    	try
    	{
    		// build the query to retrieve the model instance
    		$user = $m::where($this->username, $u)
    			->first();
    		
    		// if the user is empty then we don't even need to check the
    		// password and we can just return null
    		if(empty($user)) {
    			return null;
    		}

    		// now check the password if we need to do so
    		if(!$this->allow_no_pass) {
    			$pw_attr = $this->password;
    			if(!Hash::check($p, $user->$pw_attr)) {
    				// passwords do not match
    				return null;
    			}
    		}

    		// the authentication was successful
    		return $user;
    	}
    	catch(Exception $e)
    	{
    		// DB access failure, so bubble up the exception
    		// instead of letting it die here; this will assist in debugging
    		throw $e;
    	}
    }

	/**
	 * Retrieves the user with the specified identifier from the model.
	 *
	 * @param string $identifier The desired identifier to use
	 * @return User
	 */
    public function retrieveById($identifier) {
    	$m = $this->modelName;
    	return $m::findForAuth($identifier);
    }

    /**
	 * Returns the user with the specified identifier and Remember Me token.
	 *
	 * @param string $identifier The identifier to use
	 * @param string $token The Remember Me token to use
	 * @return User
	 */
	public function retrieveByToken($identifier, $token) {
		$m = $this->modelName;
		return $m::findForAuthToken($identifier, $token);
	}

	/**
	 * Updates the Remember Me token for the specified identifier.
	 *
	 * @param UserInterface $user The user object whose token is being updated
	 * @param string $token The Remember Me token to update
	 */
    public function updateRememberToken(AuthenticatableContract $user, $token) {
	    if(!empty($user)) {
	    	// make sure there is a remember_token field available for
	    	// updating before trying to update; otherwise we run into
	    	// an uncatchable exception
	    	if($user->canHaveRememberToken()) {
	    		$user->remember_token = $token;
	    		$user->save();
	    	}
	    }
    }

    /**
 	 * Validates that the provided credentials match the provided user.
 	 *
 	 * @param UserInterface $user The provided user object
 	 * @param array $credentials The credentials against which to check
 	 * @return boolean
 	 */
    public function validateCredentials(AuthenticatableContract $user, array $credentials) {
    	// our external service, directory, etc. has already verified whether
    	// or not the credentials are valid so the point is moot here; instead,
    	// let's either "return true" to do a pass-through or do a check for
    	// whether the user is actually active and should be allowed to auth in.
    	return true;
		//return $user->isActive();
    }
    
	/**
	 * Rehashes the user's password when required
	 * 
	 * @param UserInteface $user The provided user object
	 * @param array $credentials The credentials to check against
	 * @param bool $force Forces the rehash to take place
	 */
    public function rehashPasswordIfRequired(AuthenticatableContract $user, array $credentials, $force = false) {
		if(!isset($credentials['password'])) {
			return;
		}

		$plain = $credentials['password'];
		
		if($force || Hash::needsRehash($user->getAuthPassword())) {
			$user->forceFill([$user->getAuthPasswordName() => Hash::make($plain),])->save();	
		}
    }
}
