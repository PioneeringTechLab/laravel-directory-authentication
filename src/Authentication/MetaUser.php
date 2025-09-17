<?php

namespace CSUNMetaLab\Authentication;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use CSUNMetaLab\Authentication\Interfaces\MetaAuthenticatableContract;

use Illuminate\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;

use Illuminate\Foundation\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;

/**
 * Base class used with the META+Lab authentication mechanism. This can be
 * used on its own or subclassed for a specific application. If used on its
 * own it expects a table called "users" with a primary key of "user_id".
 */
class MetaUser extends Model implements AuthenticatableContract, AuthorizableContract, MetaAuthenticatableContract {
	use Authenticatable;
	use Authorizable;

	/**
	 * The database table used by the model.
	 *
	 * @var string
	 */
	const META_USER_TABLE = "users";

	/**
	 * The primary key used by the database table.
	 *
	 * @var string
	 */
	const META_USER_PRIMARY_KEY = "user_id";

	/**
	 * The database table used by the model.
	 *
	 * @var string
	 */
	protected $table = self::META_USER_TABLE;

	/**
	 * The primary key used by the database table.
	 *
	 * @var string
	 */
	protected $primaryKey = self::META_USER_PRIMARY_KEY;

	/**
	 * The attributes returned by the search from the remote directory server.
	 *
	 * @var array
	 */
	public $searchAttributes = [];

	/**
	 * Returns whether this model supports having a remember_token attribute.
	 *
	 * @return boolean
	 */
	public function canHaveRememberToken(): bool {
		return Schema::hasColumn($this->table, 'remember_token');
	}

    /**
     * implements MetaAuthenticatableContract#findForAuth
     *
     * @param string $identifier
     * @return Model
     */
    public static function findForAuth(string $identifier): Model {
		return self::where(self::META_USER_PRIMARY_KEY, '=', $identifier)
			->first();
	}

    /**
     * implements MetaAuthenticatableContract#findForAuthToken
     *
     * @param string $identifier
     * @param string $token
     * @return Model
     */
    public static function findForAuthToken(string $identifier, string $token): Model {
		return self::where(self::META_USER_PRIMARY_KEY, '=', $identifier)
			->where('remember_token', '=', $token)
			->first();
	}

	/**
	 * Dynamic attribute that returns whether this record is valid within the
	 * database. If the column represented by the primary key is NULL then this
	 * method returns false as the record would not fundamentally exist.
	 *
	 * @example $user->is_valid
	 *
	 * @return boolean
	 */
	public function getIsValidAttribute(): bool {
		return $this->exists;
	}

	/**
	 * Returns the currently-masquerading user instance. This is not the user
	 * the authenticated user is masquerading as. Returns null if there is no
	 * masquerade curently taking place.
	 *
	 * @return Model|null
	 */
	public function getMasqueradingUser(): ?Model {
		if($this->isMasquerading()) {
			return session('masquerading_user');
		}

		return null;
	}

	/**
     * Returns whether this user instance is currently masquerading as another
     * user.
     *
     * @return boolean
     */
    public function isMasquerading(): bool {
        return session('masquerading_user') != null;
    }

	/**
     * Allows a logged-in user to masquerade as the passed User. Returns true
     * on success or false otherwise.
     *
     * @param MetaUser $user The user instance to become
     * @return boolean
     */
    public function masqueradeAsUser(MetaUser $user): bool {
        // if this user is authenticated, then we can masquerade as the
        // user that has been passed as the parameter
        if(Auth::check()) {
            // write the authenticated user into the session and then
            // authenticate as the passed user instance
            session(['masquerading_user' => Auth::user()]);
            Auth::logout();
            Auth::login($user);

            // success!
            return true;
        }

        return false;
    }

    /**
     * Stops masquerading as another user if we are currently masquerading.
     * Returns true on success or false otherwise.
     *
     * @return boolean
     */
    public function stopMasquerading(): bool {
        if($this->isMasquerading()) {
            // become the real user again
            Auth::logout();
            Auth::login(session('masquerading_user'));
            session(['masquerading_user' => null]);

            // success!
            return true;
        }

        return false;
    }
}