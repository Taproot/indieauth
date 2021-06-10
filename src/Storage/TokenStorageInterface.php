<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Storage;

/**
 * Token Storage Interface
 * 
 * This interface defines the bare minimum methods required by the Server class in order to 
 * implement auth code issuing and exchange flows, as well as to let external code get access
 * tokens (for validating requests authenticated by an access_token) and revoke access tokens.
 * 
 * The contract made between Server and implementations of TokenStorageInterface can broadly
 * be summarized as follows:
 * 
 * * The Server class is responsible for performing all validation which is
 *   defined in the IndieAuth spec and is not implementation-specific. For example: checking
 *   validity of all the authorization request parameters, checking that client_id, request_uri
 *   and code_verifier parameters in token exchange requests match with the stored data.
 * * The TokenStorageInterface class is responsible for performing implementation-specific
 *   validation, such as assigning and checking expiry times for auth codes and access tokens.
 * 
 * Implementations of TokenStorageInterface will usually implement additional methods to allow
 * for lower-level querying, saving, updating and deletion of token data. These can be used to,
 * for example, implement a UI for users to review and revoke currently valid access tokens.
 * 
 * The behaviour of `TokenStorageInterface` is somewhat coupled with the implementation of your
 * authentication handler callback (documented in `Server::__construct`) and `AuthorizationFormInterface`,
 * so you should refer to the documentation for both while implementing `TokenStorageInterface`.
 * 
 * Periodic deletion of expired tokens is out of the scope of this interface. Implementations may
 * choose to offer a clean-up method, and potentially the option to call it once automatically 
 * on instanciation.
 */
interface TokenStorageInterface {
	/**
	 * Create Auth Code
	 * 
	 * This method is called on a valid authorization token request. The `$data`
	 * array is guaranteed to have the following keys:
	 * 
	 * * `client_id`: the validated `client_id` request parameter
	 * * `redirect_uri`: the validated `redirect_uri` request parameter
	 * * `state`: the `state` request parameter
	 * * `code_challenge`: the `code_challenge` request parameter
	 * * `code_challenge_method`: the `code_challenge_method` request parameter
	 * * `requested_scope`: the value of the `scope` request parameter
	 * * `me`: the value of the `me` key from the authentication result returned from the authentication request handler callback
	 * 
	 * It may also have additional keys, which can come from the following locations:
	 * 
	 * * All keys from the the authentication request handler callback result which do not clash 
	 *   with the keys listed above (with the exception of `me`, which is always present). Usually
	 *   this is a `profile` key, but you may choose to return additional data from the authentication
	 *   callback, which will be present in `$data`.
	 * * Any keys added by the `transformAuthorizationCode` method on the currently active instance
	 *   of `Taproot\IndieAuth\Callback\AuthorizationFormInterface`. Typically this is the `scope`
	 *   key, which is a valid scope string listing the scopes granted by the user on the consent
	 *   screen. Other implementations of `AuthorizationFormInterface` may add additional data, such
	 *   as custom token-specific settings, or a custom token lifetime.
	 * 
	 * This method should store the data passed to it, generate a corresponding authorization code,
	 * and return an instance of `Storage\Token` containing both. Implementations will usually add 
	 * an expiry time, usually under the `valid_until` key.
	 * 
	 * The method call and data is structured such that implementations have a lot of flexibility
	 * about how to store authorization code data. It could be a record in an auth code database
	 * table, a record in a table which is used for both auth codes and access tokens, or even
	 * a stateless self-encrypted token — note that in the latter case, you must persist a copy
	 * of the auth code with it’s access token to check against, in order to prevent it being
	 * exchanged for an access token more than once.
	 * 
	 * On an error, return null. The reason for the error is irrelevant for calling code, but it’s
	 * recommended to log it for reference.
	 */
	public function createAuthCode(array $data): ?Token;

	/**
	 * Exchange Authorization Code for Access Token
	 * 
	 * Attempt to exchange an authorization code identified by `$code` for
	 * an access token, returning it in a `Token` on success and null on error.
	 * 
	 * This method is responsible for ensuring that the matched auth code is
	 * not expired. If it is, it should return null, presumably after deleting
	 * the corresponding authorization code record.
	 * 
	 * If the exchanged access token should expire, this method should set its 
	 * expiry time, usually in a `valid_until` key.
	 */
	public function exchangeAuthCodeForAccessToken(string $code): ?Token;

	/**
	 * Get Access Token
	 * 
	 * Fetch access token data identified by the token `$token`, returning 
	 * null if it is expired or invalid. The data should be structured in
	 * exactly the same way it was stored by `exchangeAuthCodeForAccessToken`.
	 */
	public function getAccessToken(string $token): ?Token;

	/**
	 * Revoke Access Token
	 * 
	 * Revoke the access token identified by `$token`. Return true on success,
	 * or false on error, including if the token did not exist.
	 */
	public function revokeAccessToken(string $token): bool;
}
