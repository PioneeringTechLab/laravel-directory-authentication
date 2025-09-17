<?php

namespace CSUNMetaLab\Authentication\Factories;

use CSUNMetaLab\Authentication\Handlers\HandlerLDAP;

/**
 * Factory class that returns HandlerLDAP instances.
 */
class HandlerLDAPFactory
{
	/**
	 * Returns a HandlerLDAP instance based on the default configuration.
	 *
	 * @return HandlerLDAP
	 */
	public static function fromDefaults(): HandlerLDAP
    {
		$handler = new HandlerLDAP(
			config('ldap.host'),
			config('ldap.basedn'),
			config('ldap.dn'),
			config('ldap.password'),
			config('ldap.search_user_id'),
			config('ldap.search_username'),
			config('ldap.search_user_mail'),
			config('ldap.search_user_mail_array')
		);
		$handler->setVersion(config('ldap.version'));
		$handler->setOverlayDN(config('ldap.overlay_dn'));

		// configuration for add operations
		$handler->setAddBaseDN(config('ldap.add_base_dn'));
		$handler->setAddDN(config('ldap.add_dn'));
		$handler->setAddPassword(config('ldap.add_pw'));

		// configuration for modify operations
		$handler->setModifyMethod(config('ldap.modify_method'));
		$handler->setModifyBaseDN(config('ldap.modify_base_dn'));
		$handler->setModifyDN(config('ldap.modify_dn'));
		$handler->setModifyPassword(config('ldap.modify_pw'));

		return $handler;
	}
}