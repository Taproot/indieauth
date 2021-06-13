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
 * on instantiation.
 * 
 * None of the methods defined on TokenStorageInterface should throw exceptions. Failure, for any
 * reason, is indicated by returning either `null` or `false`, depending on the method.
 */
interface TokenStorageInterface {
	/**
	 * Create Authorization Code
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
	 *   key, which is a valid space-separated scope string listing the scopes granted by the user on
	 *   the consent screen. Other implementations of `AuthorizationFormInterface` may add additional 
	 *   data, such as custom token-specific settings, or a custom token lifetime.
	 * 
	 * This method should store the data passed to it, generate a corresponding authorization code
	 * string, and return it.
	 * 
	 * The method call and data is structured such that implementations have a lot of flexibility
	 * about how to store authorization code data. It could be a record in an auth code database
	 * table, a record in a table which is used for both auth codes and access tokens, or even
	 * a stateless self-encrypted token — note that in the latter case, you must persist a copy
	 * of the auth code with its exchanged access token to check against, in order to prevent it 
	 * being exchanged more than once.
	 * 
	 * On an error, return null. The reason for the error is irrelevant for calling code, but it’s
	 * recommended to log it internally for reference. For the same reason, this method should not 
	 * throw exceptions.
	 */
	public function createAuthCode(array $data): ?string;

	/**
	 * Exchange Authorization Code for Access Token
	 * 
	 * Attempt to exchange an authorization code identified by `$code` for
	 * an access token. Return an array of access token data to be passed onto
	 * the client app on success, and null on error.
	 * 
	 * This method is called at the beginning of a code exchange request, before
	 * further error checking or validation is applied. It should proceed as
	 * follows.
	 * 
	 * * Attempt to fetch the authorization code data identified by $code. If
	 *   it does not exist or has expired, return null;
	 * * Pass the authorization code data array to $validateAuthCode for validation.
	 *   If there is a problem with the code, a `Taproot\IndieAuth\IndieAuthException`
	 *   will be thrown. This method should catch it, invalidate the authorization
	 *   code data, then re-throw the exception for handling by Server.
	 * * If the authorization code data passed all checks, convert it into an access
	 *   token, invalidate the auth code to prevent re-use, and store the access token
	 *   data internally.
	 * * Return an array of access token data to be passed onto the client app. It MUST
	 *   contain the following keys:
	 *     * `me`
	 *     * `access_token`
	 *   Additonally, it SHOULD contain the following keys:
	 *     * `scope`, if the token grants any scope
	 *   And MAY contain additional keys, such as:
	 *     * `profile`
	 *     * `expires_at`
	 * 
	 * If the authorization code was redeemed at the authorization endpoint, Server will
	 * only pass the `me` and `profile` keys onto the client. In both cases, it will filter
	 * out `code_challenge` keys to prevent that data from accidentally being leaked to
	 * clients. If an access token is present, the server will add `token_type: Bearer`
	 * automatically.
	 * 
	 * A typical implementation might look like this:
	 * 
	 * ```php
	 * function exchangeAuthCodeForAccessToken(string $code, callable $validateAuthCode): ?array {
	 *   if (is_null($authCodeData = $this->fetchAuthCode($code))) {
	 *     return null;
	 *   }
	 *   
	 *   if (isExpired($authCodeData)) {
	 *     return null;
	 *   }
	 *   
	 *   try {
	 *     $validateAuthCode($authCodeData);
	 *   } catch (IndieAuthException $e) {
	 *     $this->deleteAuthCode($code);
	 *     throw $e;
	 *   }
	 *   
	 *   return $this->newTokenFromAuthCodeData($authCodeData);
	 * }
	 * ```
	 * 
	 * Refer to reference implementations in the `Taproot\IndieAuth\Storage` namespace for
	 * reference.
	 * 
	 * @param string $code The Authorization Code to attempt to exchange.
	 * @param callable $validateAuthCode A callable to perform additional validation if valid auth code data is found. Takes `array $authCodeData`, raises `Taproot\IndieAuth\IndieAuthException` on invalid data, which should be bubbled up to the caller after any clean-up. Returns void.
	 * @return array|null An array of access token data to return to the client on success, null on any error.
	 */
	public function exchangeAuthCodeForAccessToken(string $code, callable $validateAuthCode): ?array;

	/**
	 * Get Access Token
	 * 
	 * Fetch access token data identified by the token `$token`, returning 
	 * null if it is expired or invalid.
	 */
	public function getAccessToken(string $token): ?array;

	/**
	 * Revoke Access Token
	 * 
	 * Revoke the access token identified by `$token`. Return true on success,
	 * or false on error, including if the token did not exist.
	 */
	public function revokeAccessToken(string $token): bool;
}
