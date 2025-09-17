<?php

namespace CSUNMetaLab\Authentication\Interfaces;

use Illuminate\Database\Eloquent\Model;

interface MetaAuthenticatableContract {

	/**
	 * Returns the user with the given identifier. This is used primarily by
	 * custom authentication service providers.
	 *
	 * @param string $identifier The identifier to use for retrieval
	 * @return Model
	 */
	public static function findForAuth(string $identifier): Model;

	/**
	 * Returns the user with the given identifier and Remember Me token. This
	 * is used primarily by custom authentication service providers.
	 *
	 * @param string $identifier The identifier to use for retrieval
	 * @param string $token The token to use for retrieval
	 *
	 * @return Model
	 */
	public static function findForAuthToken(string $identifier, string $token): Model;
}