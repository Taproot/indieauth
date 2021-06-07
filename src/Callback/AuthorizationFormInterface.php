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
	 * The form MUST submit a POST request to $formAction, with the `taproot_indieauth_action`
	 * set to `approve`.
	 * 
	 * The form MUST additionally include any CSRF tokens required to protect the submission.
	 * Refer to whatever CSRF protection code you’re using (e.g. `\Taproot\IndieAuth\Middleware\DoubleSubmitCookieCsrfMiddleware`)
	 * and make sure to include the required element. This will usually involve getting a
	 * CSRF token with `$request->getAttribute()` and including it in an `<input type="hidden" …/>`.
	 * 
	 * The form SHOULD present 
	 * 
	 * @param ServerRequestInterface $request The current request.
	 * @param array $authenticationResult The array returned from the Authentication Handler. Guaranteed to contain a 'me' key, may also contain additional keys e.g. 'profile'.
	 * @param string $formAction The URL which your form MUST submit to. Can also be used as the redirect URL for a logout process.
	 * @param array|null $clientHApp If available, the microformats-2 structure representing the client app.
	 * @return ResponseInterface A response containing the authorization form.
	 */
	public function showForm(ServerRequestInterface $request, array $authenticationResult, string $formAction, ?array $clientHApp): ResponseInterface;

	/**
	 * Transform Authorization Code
	 * 
	 * 
	 * 
	 * @param array $code The base authorization code data, to be added to.
	 * @param ServerRequestInterface $request The current request.
	 * @return array The $code argument with any necessary changes.
	 */
	public function transformAuthorizationCode(ServerRequestInterface $request, array $code): array;
}