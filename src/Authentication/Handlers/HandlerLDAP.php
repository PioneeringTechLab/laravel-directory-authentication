<?php

namespace CSUNMetaLab\Authentication\Handlers;

use Exception;

use CSUNMetaLab\Authentication\Exceptions\LdapExtensionNotLoadedException;
use CSUNMetaLab\Authentication\Factories\LDAPPasswordFactory;

use Toyota\Component\Ldap\Core\Manager,
	Toyota\Component\Ldap\Core\Node,
    Toyota\Component\Ldap\Platform\Native\Driver,
    Toyota\Component\Ldap\Exception\BindException,
    Toyota\Component\Ldap\Exception\NodeNotFoundException;

use Toyota\Component\Ldap\API\ConnectionInterface;
use Toyota\Component\Ldap\Core\SearchResult;

/**
 * Handler class for LDAP operations using the Tiesa LDAP package.
 */
class HandlerLDAP
{
	private $ldap;

	// LDAP configuration
	private $host;
	private $basedn;
	private $dn;
	private $password;

	// array (potentially) of search base DNs, bind DNs, and passwords
	private $basedn_array;
	private $dn_array;
	private $password_array;

	// values for searching
	private $search_user_id;
	private $search_username;
	private $search_mail;
	private $search_mail_array;

	// the LDAP query to be executed while searching for users
	private $search_auth_query;

	// true to allow auth binds without a password
	private $allowNoPass;

	// LDAP version to use
	private $version;

	// overlay DN (if any)
	private $overlay_dn;

	// base DN and credentials for adding entries to the directory
	private $add_base_dn;
	private $add_dn;
	private $add_pw;

	// modification method
	private $modify_method;

	// base DN and credentials for modifying entries in the directory
	private $modify_base_dn;
	private $modify_dn;
	private $modify_pw;

	/**
	 * Constructs a new HandlerLDAP object.
	 *
	 * @param string $host The LDAP hostname
	 * @param string $basedn The LDAP base DN
	 * @param string $dn The full LDAP DN for binding
	 * @param string $password The password for binding
	 * @param string $search_user_id The attribute to use for searching by user ID
	 * @param string $search_username The attribute to use for searching by username
	 * @param string $search_mail Optional attribute to use for searching by email
	 * @param string $search_mail_array Optional attribute to use for searching by email array
	 */
	public function __construct(string $host, string $basedn, string $dn, string $password,
		string $search_user_id, string $search_username, string $search_mail="mail",
		string $search_mail_array="mailLocalAddress") {
		$this->host = $host;
		$this->basedn = $basedn;
		$this->dn = $dn;
		$this->password = $password;

		$this->search_user_id = $search_user_id;
		$this->search_username = $search_username;
		$this->search_mail = $search_mail;
		$this->search_mail_array = $search_mail_array;

		// false by default so we don't accidentally cause security problems
		$this->allowNoPass = false;

		// LDAPv3 by default
		$this->version = 3;

		// set the default auth search query
		$this->search_auth_query = "(|(" . $search_username . 
			"=%s)(" . $search_mail . "=%s)(" .
				$search_mail_array . "=%s))";

		// set the overlay DN
		$this->overlay_dn = "";

		// generate the various DN and bind arrays
		$this->basedn_array = explode("|", $this->basedn);
		$this->dn_array = explode("|", $this->dn);
		$this->password_array = explode("|", $this->password);

		// set defaults for the add and modify operations
		$this->setDefaultManipulationInformation();
	}

	/**
	 * Sets the base DN and credentials for add and modify operations based
	 * on the search base DN and credentials. This is done to provide sensible
	 * defaults in case the specific setter methods are not invoked.
	 * @return void
	 */
	private function setDefaultManipulationInformation(): void {
		$this->add_base_dn = $this->basedn_array[0];
		$this->add_dn = $this->dn;
		$this->add_pw = $this->password;

		$this->modify_method = "self";
		$this->modify_base_dn = $this->add_base_dn;
		$this->modify_dn = $this->add_dn;
		$this->modify_pw = $this->add_pw;
	}

	/**
	 * Attempts to bind to the LDAP server with the provided username and
	 * password. Throws a BindException if the bind operation fails.
	 *
	 * @param string $username The username with which to bind
	 * @param string $password The password with which to bind
	 * @throws BindException If the binding operation fails
	 * @return void
	 */
	public function bind(string $username, string $password): void {
		$this->ldap->bind($username, $password);
	}

	/**
	 * Returns whether blank passwords are allowed for binding.
	 *
	 * @return boolean
	 */
	public function canAllowNoPass(): bool {
		return $this->allowNoPass;
	}

	/**
	 * Connects and binds to the LDAP server. An optional username and password
	 * can be supplied to override the default credentials. Returns whether the
	 * connection and binding was successful.
	 *
	 * @param string $username The override username to use
	 * @param string $password The override password to use
	 *
	 * @throws LdapExtensionNotLoadedException If the LDAP extension has not
	 * been installed and loaded
	 * @throws Exception If the LDAP connection fails
	 * @return boolean
	 */
	public function connect(string $username="", string $password=""): bool {
		// make sure the ldap extension has been loaded
		if(!extension_loaded('ldap')) {
			throw new LdapExtensionNotLoadedException();
		}

		$params = array(
		    'hostname'  => $this->host,
		    'base_dn' => $this->basedn,
		    'options' => [
		    	ConnectionInterface::OPT_PROTOCOL_VERSION => $this->version,
		    ],
		);

		// if there is an overlay, use that as the base DN instead
		if(!empty($this->overlay_dn)) {
			$params['base_dn'] = $this->overlay_dn;
		}

		$this->ldap = new Manager($params, new Driver());

		// connect to the server and bind with the credentials
		try
		{
			$this->ldap->connect();

			// if override parameters have been specified then use those
			// for the binding operation
			if(!empty($username)) {
				foreach($this->basedn_array as $basedn) {
					try
					{
						// bind by uid; append the overlay DN if one has been specified
						$selectedUsername = $this->search_username . "=" .
							$username;
						if(!empty($basedn)) {
							$selectedUsername .= "," . $basedn;
						}

						$selectedPassword = "";

						// do we allow empty passwords for bind attempts?
						if(empty($password)) {
							if($this->allowNoPass) {
								// yes so use the constructor-provided DN and password
								$selectedUsername = $this->dn;
								$selectedPassword = $this->password;
							}
						}
						else
						{
							// password provided so use what we were given
							$selectedPassword = $password;
						}

						// append the overlay DN if it exists
						if(!empty($this->overlay_dn)) {
							$selectedUsername .= "," . $this->overlay_dn;
						}

						// now perform the bind
						$this->bind($selectedUsername, $selectedPassword);

						// if we get here without hitting an exception, the bind
						// was successful
						return true;
					}
					catch(BindException $e) {
						// just because we hit a bind exception it doesn't mean
						// that there was an error; this could have been the
						// result of bad credentials so we will continue with
						// the next element in the array
					}
				}
			}
			else
			{
				// use the admin bind credentials
				$dn = $this->dn;
				if(!empty($this->overlay_dn)) {
					$dn .= "," . $this->overlay_dn;
				}
				$this->bind($dn, $this->password);
			}

			// if it hits this return then the connection was successful and
			// the binding was also successful
			return true;
		}
		catch(BindException $be)
		{
			// could not bind with the provided credentials (admin bind)
			return false;
		}
		catch(Exception $e)
		{
			throw $e;
		}

		// could not bind with the provided credentials (regular user bind) or
		// something else went wrong
		return false;
	}

	/**
	 * Connects and binds to the LDAP server based on the provided DN and an
	 * optional password. Returns whether the connection and binding were
	 * successful.
	 *
	 * @param string $dn The bind DN to use
	 * @param string $password An optional password to use
	 *
	 * @throws LdapExtensionNotLoadedException If the LDAP extension has not
	 * been installed and loaded
	 * @throws Exception If the LDAP connection fails
	 * @return boolean
	 */
	public function connectByDN(string $dn, string $password=""): bool {
		// make sure the ldap extension has been loaded
		if(!extension_loaded('ldap')) {
			throw new LdapExtensionNotLoadedException();
		}

		$params = array(
		    'hostname'  => $this->host,
		    'base_dn' => $this->basedn,
		    'options' => [
		    	ConnectionInterface::OPT_PROTOCOL_VERSION => $this->version,
		    ],
		);

		// if there is an overlay, use that as the base DN instead
		if(!empty($this->overlay_dn)) {
			$params['base_dn'] = $this->overlay_dn;
		}

		$this->ldap = new Manager($params, new Driver());

		// connect to the server and bind with the credentials
		try
		{
			$this->ldap->connect();

			// if we do not have a password specified, use the admin DN and
			// password for the connection operation
			if(empty($password)) {
				if($this->allowNoPass) {
					// yes so use the constructor-provided DN and password
					$dn = $this->dn;
					if(!empty($this->overlay_dn)) {
						$dn .= "," . $this->overlay_dn;
					}
					$password = $this->password;
				}
			}

			$this->bind($dn, $password);

			// if it hits this return then the connection was successful and
			// the binding was also successful
			return true;
		}
		catch(BindException $be)
		{
			// could not bind with the provided credentials
			return false;
		}
		catch(Exception $e)
		{
			throw $e;
		}

		// something else went wrong
		return false;
	}

	/**
	 * Returns the value of the specified attribute from the result set. Returns
	 * null if the attribute could not be found.
	 *
	 * @param SearchResult $results The result-set to search through
	 * @param string $attr_name The attribute name to look for
	 * @return string|integer|boolean|null
	 */
    public function getAttributeFromResults(SearchResult $results, string $attr_name) {
        foreach($results as $node) {
        	if($attr_name == "dn") {
        		return $node->getDn();
        	}

            foreach($node->getAttributes() as $attribute) {
                if (strtolower($attribute->getName()) == strtolower($attr_name)) {
                    return $attribute->getValues()[0]; // attribute found
                }
            }
        }
        return null;
    }

    /**
     * Returns whether the result set passed has at least one valid record in it.
     *
     * @param SearchResult $results The set of results to check
     * @return boolean
     */
    public function isValidResult(SearchResult $results): bool {
    	return $results->valid();
    }

    /**
	 * Queries LDAP for the record with the specified value for attributes
	 * matching what could commonly be used for authentication. For the
	 * purposes of this method, uid, mail and mailLocalAddress are searched by
	 * default unless their values have been overridden.
	 *
	 * @param string $value The value to use for searching
	 * @return SearchResult
	 */
	public function searchByAuth(string $value): ?SearchResult
    {
		// figure out how many times the placeholder occurs, then fill an
		// array that number of times with the search value
		$numArgs = substr_count($this->search_auth_query, "%s");
		$args = array_fill(0, $numArgs, $value);

		// format the string and then perform the search for each base DN
		$searchStr = vsprintf($this->search_auth_query, $args);

		// iterate over the array of base DNs and perform the searches; we will
		// return the first result set that matches our query
		$results = null;
		foreach($this->basedn_array as $basedn) {
			// add the overlay if it exists
			if(!empty($this->overlay_dn)) {
				// append the overlay if we do have a base DN or use the
				// overlay as the base DN if not
				if(!empty($basedn)) {
					$basedn .= ',' . $this->overlay_dn;
				}
				else
				{
					$basedn = $this->overlay_dn;
				}
			}

			$results = $this->ldap->search($basedn, $searchStr);
			if($this->isValidResult($results)) {
				return $results;
			}
		}

		// ensures that there is some result set that is returned based upon
		// one of the loop iterations even if we did not match our desired
		// condition
		return $results;
	}

	/**
	 * Queries LDAP for the record with the specified email.
	 *
	 * @param string $email The email to use for searching
	 * @return SearchResult
	 */
	public function searchByEmail(string $email): SearchResult
    {
		$results = $this->ldap->search($this->basedn,
			$this->search_mail . '=' . $email);
		return $results;
	}

	/**
	 * Queries LDAP for the record with the specified mailLocalAddress.
	 *
	 * @param string $email The mailLocalAddress to use for searching
	 * @return SearchResult
	 */
	public function searchByEmailArray(string $email): SearchResult
    {
		$results = $this->ldap->search($this->basedn,
			$this->search_mail_array . '=' . $email);
		return $results;
	}

	/**
	 * Queries LDAP for the records using the specified query.
	 *
	 * @param string $query Any valid LDAP query to use for searching
	 * @return SearchResult
	 */
	public function searchByQuery(string $query): SearchResult
    {
		$results = $this->ldap->search($this->basedn, $query);
		return $results;
	}

	/**
	 * Queries LDAP for the record with the specified uid.
	 *
	 * @param string $uid The uid to use for searching
	 * @return SearchResult
	 */
	public function searchByUid(string $uid): SearchResult
    {
		$results = $this->ldap->search($this->basedn,
			$this->search_username . '=' . $uid);
		return $results;
	}

	/**
	 * Adds an object into the add subtree using the specified identifier and
	 * an associative array of attributes. Returns a boolean describing whether
	 * the operation was successful. Throws an exception if the bind fails.
	 *
	 * @param string $identifier The value to use as the "username" identifier
	 * @param array $attributes Associative array of attributes to add
	 *
	 * @return bool
	 * @throws BindException
	 */
	public function addObject(string $identifier, array $attributes): bool {
		// bind using the add credentials
		$this->bind(
			$this->add_dn,
			$this->add_pw
		);

		// generate a new node and set its DN within the add subtree
		$node = new Node();

		// if the identifier contains a comma, it's likely a DN
		if(strpos($identifier, ',') !== FALSE) {
			$dn = $identifier;
		}
		else
		{
			// generate the DN from the identifier
			$dn = $this->search_username . '=' . $identifier . ',' .
				$this->add_base_dn;
		}
		
		$node->setDn($dn);

		// if the node already exists we want to return false to prevent any
		// potential updates (as updates would be performed by modifyObject())
		try {
			$this->ldap->getNode($dn);
			return false;
		}
		catch(NodeNotFoundException $e) {
			// iterate over the attributes and add them to the node
			foreach($attributes as $key => $value) {
				// this can handle both arrays of values as well as single values
				// to be added for the record
				$node->get($key, true)->add($value);
			}

			// save the node into the store
			$this->ldap->save($node);
			return true;
		}
	}

	/**
	 * Modifies an object in the modify subtree using the specified identifier
	 * and an associative array of attributes. Returns a boolean describing
	 * whether the operation was successful. Throws an exception if the bind
	 * fails.
	 *
	 * @param string $identifier The value to use as the "username" identifier
	 * @param array $attributes Associative array of attributes to modify
	 *
	 * @return bool
	 * @throws BindException
	 */
	public function modifyObject(string $identifier, array $attributes): bool {
		// bind using the modify credentials if anything other than "self"
		// has been set as the method
		if($this->modify_method != "self") {
			$this->bind(
				$this->modify_dn,
				$this->modify_pw
			);
		}

		// if the identifier contains a comma, it's likely a DN
		if(strpos($identifier, ',') !== FALSE) {
			$dn = $identifier;
		}
		else
		{
			// generate the DN from the identifier
			$dn = $this->search_username . '=' . $identifier . ',' .
				$this->modify_base_dn;
		}

		try
		{
			// ensure the node exists before we perform an update since addition
			// of nodes would be handled by addObject() instead
			$node = $this->ldap->getNode($dn);

			// iterate over the attributes and apply the changes. If an
			// attribute already exists, set its value; otherwise, add the
			// new value
			foreach($attributes as $key => $value) {
				if($node->has($key)) {
					// if the value is either null or an empty array, just
					// remove the attribute; otherwise, set it to a value
					$node->get($key)->set($value);
				}
				else
				{
					$node->get($key, true)->add($value);
				}
			}

			// save the node into the store
			$this->ldap->save($node);
			return true;
		}
		catch(NodeNotFoundException $e) {
			// node does not exist
			return false;
		}
	}

	/**
	 * Modifies the password of an object in the modify subtree using the
	 * specified identifier and a plaintext password. The password will be
	 * hashed using the SSHA algorithm. Returns a boolean describing whether
	 * the operation was successful. Throws an exception if the bind fails.
	 *
	 * This method is merely a convenience method for modifyObject().
	 *
	 * @param string $identifier The value to use as the "username" identifier
	 * @param string $password The plaintext password to use
	 *
	 * @return bool
	 * @throws BindException
	 */
	public function modifyObjectPassword(string $identifier, string $password): bool {
		return $this->modifyObject($identifier, [
			'userPassword' => LDAPPasswordFactory::SSHA($password),
		]);
	}

	/**
	 * Sets whether blank passwords are allowed for binding attempts.
	 *
	 * @param boolean $allowNoPass Whether to allow blank passwords
	 * @return void
	 */
	public function setAllowNoPass(bool $allowNoPass): void {
		$this->allowNoPass = $allowNoPass;
	}

	/**
	 * Sets the query used within the searchByAuth() method. This should be
	 * structured in a vsprintf()-compatible format and use %s as the
	 * placeholder for the search value.
	 *
	 * @param string $search_auth_query LDAP query to use
	 * @return void
	 */
	public function setAuthQuery(string $search_auth_query): void {
		$this->search_auth_query = $search_auth_query;
	}

	/**
	 * Sets the base DN used during queries.
	 *
	 * @param string $basedn The base DN to use
	 * @return void
	 */
	public function setBaseDN(string $basedn): void {
		$this->basedn = $basedn;
		$this->basedn_array = explode("|", $basedn);
	}

	/**
	 * Sets the LDAP version to be used.
	 *
	 * @param int $version The LDAP version to use
	 * @return void
	 */
	public function setVersion(string $version): void {
		$this->version = $version;
	}

	/**
	 * Sets the overlay DN to use for search, add, and modify.
	 *
	 * @param string $overlay_dn The overlay DN to use
	 * @return void
	 */
	public function setOverlayDN(string $overlay_dn): void {
		$this->overlay_dn = $overlay_dn;
	}

	/**
	 * Sets the base DN for add operations in a subtree.
	 *
	 * @param string $add_base_dn The base DN for add operations
	 * @return void
	 */
	public function setAddBaseDN(string $add_base_dn): void {
		if(!empty($add_base_dn)) {
			$this->add_base_dn = $add_base_dn;
		}
		else
		{
			$this->add_base_dn = $this->basedn;
		}
	}

	/**
	 * Sets the admin DN for add operations in a subtree. If the parameter is
	 * left empty, the search admin DN will be used instead.
	 *
	 * @param string $add_dn The admin DN for add operations
	 */
	public function setAddDN(string $add_dn): void {
		if(!empty($add_dn)) {
			$this->add_dn = $add_dn;
		}
		else
		{
			$this->add_dn = $this->dn;
		}
	}

	/**
	 * Sets the admin password for add operations in a subtree. If the
	 * parameter is left empty, the search admin password will be used instead.
	 *
	 * @param string $add_pw The admin password for add operations
	 * @return void
	 */
	public function setAddPassword(string $add_pw): void {
		if(!empty($add_pw)) {
			$this->add_pw = $add_pw;
		}
		else
		{
			$this->add_pw = $this->password;
		}
	}

	/**
	 * Sets the modification method. This can be either "admin" or "self".
	 * If this is set to "admin" you will also need to set the modify DN
	 * as well as the modify password.
	 *
	 * @param string $modify_method The modify method to use
	 * @return void
	 */
	public function setModifyMethod(string $modify_method): void {
		if($modify_method == "admin") {
			$this->modify_method = $modify_method;
		}
		else
		{
			$this->modify_method = "self";
		}
	}

	/**
	 * Sets the base DN for modify operations in a subtree. If the parameter is
	 * left empty, the add base DN will be used instead.
	 *
	 * @param string $modify_base_dn The base DN for modify operations
	 * @return void
	 */
	public function setModifyBaseDN(string $modify_base_dn): void {
		if(!empty($modify_base_dn)) {
			$this->modify_base_dn = $modify_base_dn;
		}
		else
		{
			$this->modify_base_dn = $this->add_base_dn;
		}
	}

	/**
	 * Sets the admin DN for modify operations in a subtree. If the parameter
	 * is left empty, the add admin DN will be used instead.
	 *
	 * @param string $modify_dn The admin DN for modify operations
	 * @return void
	 */
	public function setModifyDN(string $modify_dn): void {
		if(!empty($modify_dn)) {
			$this->modify_dn = $modify_dn;
		}
		else
		{
			$this->modify_dn = $this->add_dn;
		}
	}

	/**
	 * Sets the admin password for modify operations in a subtree. If the
	 * parameter is left empty, the add admin password will be used instead.
	 *
	 * @param string $modify_dn The admin password for modify operations
	 * @return void
	 */
	public function setModifyPassword(string $modify_pw): void {
		if(!empty($modify_pw)) {
			$this->modify_pw = $modify_pw;
		}
		else
		{
			$this->modify_pw = $this->add_pw;
		}
	}
}
