<?php

namespace CSUNMetaLab\Authentication\Factories;

use Exception;

/**
 * Factory class that generates and returns hashes to be used with LDAP
 * passwords.
 */
class LDAPPasswordFactory
{
    /**
     * Generates and returns a new password as a SSHA hash for use in LDAP. If
     * the salt is not specified, one will be generated using the openssl
     * extension and have a length of four bytes.
     *
     * @param string $password The plaintext password to hash
     * @param string|null $salt Optional salt for the algorithm
     *
     * @return string
     * @throws Exception
     */
	public static function SSHA(string $password, string $salt=null): string {
		if(empty($salt)) {
			if(function_exists('openssl_random_pseudo_bytes')) {
				// salts should be four bytes
				$salt = bin2hex(openssl_random_pseudo_bytes(4));
			}
			else
			{
				throw new Exception(
					"You must have the openssl extension installed and enabled to use a random salt"
				);
			}
		}
		return "{SSHA}" . base64_encode(sha1($password . $salt, true) . $salt);
	}
}