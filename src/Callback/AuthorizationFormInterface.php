<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Callback;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Authorization Form Interface
 */
interface AuthorizationFormInterface {
	/**
	 * Show Form
	 * 
	 * This method is called once the IndieAuth Authorization Endpoint has confirmed that:
	 * 
	 * * The current user is authenticated
	 * * The client app (client_id) has been fetched and is valid
	 * * The client app redirect_uri is known to be valid
	 * 
	 * It should build an authorization form which the currently logged-in user can use
	 * to choose which scopes (if any) to grant the app.
	 * 
	 * Information specific to the IndieAuth authorization request can be found in
	 * `$request->getQueryParams()`. The parameters most likely to be of use to the authorization
	 * form are:
	 * 
	 * * `scope`: a space-separated list of scopes which the client app is requesting. May be absent.
	 * * `client_id`: the URL of the client app. Should be shown to the user. This also makes a good “cancel” link.
	 * * `redirect_uri`: the URI which the user will be redirected to on successful authorization. 
	 * 
	 * The form MUST submit a POST request to `$formAction`, with the `taproot_indieauth_action`
	 * parameter set to `approve`.
	 * 
	 * The form MUST additionally include any CSRF tokens required to protect the submission.
	 * Refer to whatever CSRF protection code you’re using (e.g. {@see \Taproot\IndieAuth\Middleware\DoubleSubmitCookieCsrfMiddleware})
	 * and make sure to include the required element. This will usually involve getting a
	 * CSRF token with `$request->getAttribute()` and including it in an `<input type="hidden" …/>`.
	 * 
	 * The form SHOULD offer the user the opportunity to choose which of the request scopes, 
	 * if any, they wish to grant. It should describe what effect each scope grants. If no scopes are 
	 * requested, tell the user that the app is only requesting authorization, not access to their data.
	 * 
	 * The form MAY offer the user UIs for additional token configuration, e.g. a custom token lifetime.
	 * You may have to refer to the documentation for your instance of {@see \Taproot\IndieAuth\Storage\TokenStorageInterface} to ensure
	 * that lifetime configuration works correctly. Any other additional data is not used by the IndieAuth
	 * library, but, if stored on the access token, will be available to your app for use.
	 * 
	 * {@see \Taproot\IndieAuth\Server} adds the following headers to the response returned from `showForm()`:
	 * 
	 * ```
	 * Cache-Control: no-store
	 * Pragma: no-cache
	 * X-Frame-Options: DENY
	 * Content-Security-Policy: frame-ancestors 'none'
	 * ```
	 * 
	 * These headers prevent the authorization form from being cached or embedded into a malicious webpage.
	 * It may make sense for you to add additional `Content-Security-Policy` values appropriate to your implementation,
	 * for example to prevent the execution of inline or 3rd party scripts.
	 * 
	 * @param ServerRequestInterface $request The current request.
	 * @param array $authenticationResult The array returned from the Authentication Handler. Guaranteed to contain a 'me' key, may also contain additional keys e.g. 'profile'.
	 * @param string $formAction The URL which your form MUST submit to. Can also be used as the redirect URL for a logout process.
	 * @param array|Exception|null $clientHApp If available, the microformats-2 structure representing the client app. An instance of Exception if fetching the `client_id` failed.
	 * @return ResponseInterface A response containing the authorization form.
	 */
	public function showForm(ServerRequestInterface $request, array $authenticationResult, string $formAction, $clientHAppOrException): ResponseInterface;

	/**
	 * Transform Authorization Code
	 * 
	 * This method is called on a successful authorization form submission. The `$code` array
	 * is a partially-constructed authorization code array, which is guaranteed to have the 
	 * following keys:
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
	 * 
	 * This method should add any additional data to the auth code, before it is persisted and
	 * returned to the client app. Typically, this involves setting the `scope` key to be a 
	 * valid space-separated scope string of any scopes granted by the user in the form.
	 * 
	 * If the form offers additional token configuration, this method should set any relevant
	 * keys in `$code` based on the form data in `$request`.
	 * 
	 * @param array $code The base authorization code data, to be added to.
	 * @param ServerRequestInterface $request The current request.
	 * @return array The $code data after making any necessary changes.
	 */
	public function transformAuthorizationCode(ServerRequestInterface $request, array $code): array;
}
