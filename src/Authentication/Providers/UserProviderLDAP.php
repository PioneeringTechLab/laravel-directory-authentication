<?php

namespace CSUNMetaLab\Authentication\Providers;

use Exception;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
Use Illuminate\Support\Facades\Hash;

use CSUNMetaLab\Authentication\Exceptions\InvalidUserModelException;
use CSUNMetaLab\Authentication\Factories\HandlerLDAPFactory;

/**
 * Service provider handler that provides LDAP authentication operations.
 */
class UserProviderLDAP implements UserProvider
{
	private $ldap;
	private $modelName;

	// values for searching
	private $search_user_id;
	private $search_username;
	private $search_user_mail;
	private $search_db_user_id_prefix;

	// whether to return a fake user instance for provisioning
	private $return_fake_user_instance;

	/**
	 * Constructs a new UserProviderLDAP object. This can throw an instance of
	 * InvalidUserModelException if the auth model configuration parameter
	 * does not exist or if the model class does not exist.
	 *
	 * @throws InvalidUserModelException
	 */
	public function __construct() {
		// set the searching attributes for LDAP that will be returned for user
		// provisioning and testing credentials
		$this->search_user_id = config('ldap.search_user_id');
		$this->search_username = config('ldap.search_username');
		$this->search_user_mail = config('ldap.search_user_mail');

		// create the LDAP handler using its factory
		$this->ldap = HandlerLDAPFactory::fromDefaults();

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
		$this->ldap->setAllowNoPass(config('ldap.allow_no_pass'));

		// set the custom auth search query if it exists
		$customQuery = config('ldap.search_user_query');
		if(!empty($customQuery)) {
			$this->ldap->setAuthQuery($customQuery);
		}

		// set the searching attributes in the database after LDAP
		$this->search_db_user_id_prefix = config('ldap.search_user_id_prefix');

		// should a fake user instance be returned for provisioning?
		$this->return_fake_user_instance = config('ldap.return_fake_user_instance');
	}

	/**
 	 * Retrieves the user with the specified credentials from LDAP. Returns null
     * if the user could not be found. If the optional $checkDatabaseModel flag has
     * been set to false, it will instead return true if the authentication was successful.
 	 *
 	 * @param array $credentials The credentials to use
 	 * @param boolean $checkDatabaseModel True to attempt retrieval of a matching DB model, false otherwise
 	 *
 	 * @return User|boolean|null
 	 */
    public function retrieveByCredentials(array $credentials, $checkDatabaseModel=true) {
    	$u = $credentials['username'];
    	$p = $credentials['password'];

    	$m = $this->modelName;

    	// attempt to auth with the credentials provided first
    	try
    	{
    		// attempt regular authentication
	    	if($this->testCredentials($u, $p)) {
	    		// the credentials are valid so let's do the full search with
	    		// the default DN provided through the constructor
	    		$this->ldap->connect();

	    		$result = $this->ldap->searchByAuth($u);

	    		$emplId = $this->ldap->getAttributeFromResults($result, $this->search_user_id);
	    		$uid = $this->ldap->getAttributeFromResults($result, $this->search_username);
	    		$firstName = $this->ldap->getAttributeFromResults($result, "givenName");
	    		$lastName = $this->ldap->getAttributeFromResults($result, "sn");
	    		$displayName = $this->ldap->getAttributeFromResults($result, "displayName");
	    		$email = $this->ldap->getAttributeFromResults($result, $this->search_user_mail);

	    		// grab the first user with the specified attributes; return a fake user instance
	    		// if the user does not exist in the database (but only if the configuration
	    		// has been set up to do so)
	    		$user = $m::findForAuth($this->search_db_user_id_prefix . $emplId);
	    		if(empty($user)) {
	    			if($this->return_fake_user_instance) {
	    				$user = new $m();

	    				// if the user ID is empty, we have an invalid user and should
			    		// treat it like a regular invalid authentication attempt
			    		if(empty($emplId)) {
			    			return null;
			    		}

			    		// add the LDAP search attributes
			    		$user->searchAttributes = [
			    			'uid' => $uid,
			    			'user_id' => $emplId,
			    			'first_name' => $firstName,
			    			'last_name' => $lastName,
			    			'display_name' => $displayName,
			    			'email' => $email,
			    		];
	    			}
	    			else
	    			{
	    				// the configuration has specified that a new user instance should
	    				// not be returned on an unsuccessful database lookup
	    				return null;
	    			}
	    		}

	    		// the authentication was successful
	    		return $user;
	    	}
    	}
    	catch(Exception $e)
    	{
    		// LDAP connection or DB access failure, so bubble up the exception
    		// instead of letting it die here; this will assist in debugging
    		throw $e;
    	}

    	// invalid login attempt
    	return null;
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
	 * Returns whether the credentials provided can be used to authenticate
	 * against the directory.
	 *
	 * @param string $username The username to check
	 * @param string $password The password to check
	 * @return boolean
	 */
	protected function testCredentials($username, $password) {
		// we have to do something different with the bind to
		// check the credentials
		$this->ldap->connect();

		$result = $this->ldap->searchByAuth($username);

		// now we have to retrieve the DN and use that to bind
		$dn = $this->ldap->getAttributeFromResults($result, 'dn');

		// perform the bind with the DN/password combination
		return $this->ldap->connectByDN($dn, $password);
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
	public function rehashPasswordIfRequired(AuthenticableContract $user, array $credentials, $force = false) {
		if(!isset($credentials['password'])) {
			return;
		}

		$plain = $credentials['password'];
		
		if($force || Hash::needsRehash($user->getAuthPassword())) {
			$user->forceFill([$user->getAuthPasswordName() => Hash::make($plain),])->save();	
		}
    }
}