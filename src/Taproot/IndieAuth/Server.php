<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use Exception;
use Nyholm\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use IndieAuth\Client as IndieAuthClient;
use Psr\Http\Server\MiddlewareInterface;

/**
 * Development Reference
 *
 * Specification: https://indieauth.spec.indieweb.org/
 * Error responses: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
 * indieweb/indieauth-client: https://github.com/indieweb/indieauth-client-php
 * CSRF protection cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 * Example CSRF protection cookie middleware: https://github.com/zakirullin/csrf-middleware/blob/master/src/CSRF.php
 */

// TODO: maybe move these to a functions file so they’re usable by consumers even when the class isn’t loaded.
// Alternatively, make them static methods so they can be autoloaded.
function isIndieAuthAuthorizationCodeRedeemingRequest(ServerRequestInterface $request) {
	return strtolower($request->getMethod()) == 'post'
		&& array_key_exists('grant_type', $request->getParsedBody())
		&& $request->getParsedBody()['grant_type'] == 'authorization_code';
}

function isIndieAuthAuthorizationRequest(ServerRequestInterface $request, $permittedMethods=['get']) {
	return in_array(strtolower($request->getMethod()), array_map('strtolower', $permittedMethods))
		&& array_key_exists('response_type', $request->getQueryParams())
		&& $request->getQueryParams()['response_type'] == 'code';
}

function isAuthorizationApprovalRequest(ServerRequestInterface $request) {
	return strtolower($request->getMethod()) == 'post'
		&& array_key_exists('taproot_indieauth_action', $request->getParsedBody())
		&& $request->getParsedBody()['taproot_indieauth_action'] == 'approve';
}

function buildQueryString(array $parameters) {
	$qs = [];
	foreach ($parameters as $k => $v) {
		$qs[] = urlencode($k) . '=' . urlencode($v);
	}
	return join('&', $qs);
}

class Server {
	const CUSTOMIZE_AUTHORIZATION_CODE = 'customise_authorization_code';
	const SHOW_AUTHORIZATION_PAGE = 'show_authorization_page';
	const HANDLE_NON_INDIEAUTH_REQUEST = 'handle_non_indieauth_request';
	const HANDLE_AUTHENTICATION_REQUEST = 'handle_authentication_request';
	const DEFAULT_CSRF_KEY = 'taproot_indieauth_server_csrf';

	public $callbacks;

	public TokenStorageInterface $authorizationCodeStorage;

	public TokenStorageInterface $accessTokenStorage;

	public MiddlewareInterface $csrfMiddleware;

	public LoggerInterface $logger;

	public string $csrfKey;

	public function __construct(array $callbacks, $authorizationCodeStorage, $accessTokenStorage, $csrfMiddleware=null, string $csrfKey=self::DEFAULT_CSRF_KEY, LoggerInterface $logger=null) {
		$callbacks = array_merge([
			self::CUSTOMIZE_AUTHORIZATION_CODE => function (array $code) { return $code; }, // Default to no-op.
			self::SHOW_AUTHORIZATION_PAGE => function (ServerRequestInterface $request, array $authenticationResult, string $authenticationRedirect) {  }, // TODO: Put the default implementation here.
			self::HANDLE_NON_INDIEAUTH_REQUEST => function (ServerRequestInterface $request) { return null; }, // Default to no-op.
		], $callbacks);

		if (!(array_key_exists(self::HANDLE_AUTHENTICATION_REQUEST, $callbacks) and is_callable($callbacks[self::HANDLE_AUTHENTICATION_REQUEST]))) {
			throw new Exception('$callbacks[\'' . self::HANDLE_AUTHENTICATION_REQUEST .'\'] must be present and callable.');
		}
		$this->callbacks = $callbacks;

		if (!$authorizationCodeStorage instanceof TokenStorageInterface) {
			if (is_string($authorizationCodeStorage)) {
				$authorizationCodeStorage = new FilesystemJsonStorage($authorizationCodeStorage, 600, true);
			} else {
				throw new Exception('$authorizationCodeStorage parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.');
			}
		}
		$this->authorizationCodeStorage = $authorizationCodeStorage;

		if (!$accessTokenStorage instanceof TokenStorageInterface) {
			if (is_string($accessTokenStorage)) {
				// Create a default access token storage with a TTL of 7 days.
				$accessTokenStorage = new FilesystemJsonStorage($accessTokenStorage, 60 * 60 * 24 * 7, true);
			} else {
				throw new Exception('$accessTokenStorage parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.');
			}
		}
		$this->accessTokenStorage = $accessTokenStorage;
		
		$this->csrfKey = $csrfKey;

		if (!$csrfMiddleware instanceof MiddlewareInterface) {
			// Default to the statless Double-Submit Cookie CSRF Middleware, with default settings.
			$csrfMiddleware = new DoubleSubmitCookieCsrfMiddleware($this->csrfKey);
		}
		$this->csrfMiddleware = $csrfMiddleware;

		$this->logger = $logger ?? new NullLogger();
	}

	public function handleAuthorizationEndpointRequest(ServerRequestInterface $request): ResponseInterface {
		// If it’s a profile information request:
		if (isIndieAuthAuthorizationCodeRedeemingRequest($request)) {
			// Verify that the authorization code is valid and has not yet been used.
			$this->authorizationCodeStorage->get($request->getParsedBody()['code']);

			// Verify that it was issued for the same client_id and redirect_uri

			// Check that the supplied code_verifier hashes to the stored code_challenge

			// If everything checked out, return {"me": "https://example.com"} response
			// (a response containing any additional information must contain a valid scope value, and 
			// be handled by the token_endpoint).
			// TODO: according to the spec, it is technically permitted for the authorization endpoint
			// to additional provide profile information. Leave it up to the library consumer to decide
			// whether to add it or not.
		}

		// Because the special case above isn’t allowed to be CSRF-protected, we have to do some rather silly
		// gymnastics here to selectively-CSRF-protect requests which do need it.
		return $this->csrfMiddleware->process($request, new ClosureRequestHandler(function (ServerRequestInterface $request) {
			// If this is an authorization or approval request (allowing POST requests as well to accommodate 
			// approval requests and custom auth form submission.
			if (isIndieAuthAuthorizationRequest($request, ['get', 'post'])) {
				// Build a URL for the authentication flow to redirect to, if it needs to.
				// TODO: perhaps filter queryParams to only include the indieauth-relevant params?
				$authenticationRedirect = $request->getUri() . '?' . buildQueryString($request->getQueryParams());
				
				$authenticationResult = call_user_func($this->callbacks[self::HANDLE_AUTHENTICATION_REQUEST], $request, $authenticationRedirect);

				// If the authentication handler returned a Response, return that as-is.
				if ($authenticationResult instanceof Response) {
					return $authenticationResult;
				} elseif (is_array($authenticationResult)) {
					// Check the resulting array for errors.

					// The user is logged in.

					// If this is a POST request sent from the authorization (i.e. scope-choosing) form:
					if (isAuthorizationApprovalRequest($request)) {
						// Assemble the data for the authorization code, store it somewhere persistent.
						$code = [

						];

						// Pass it to the auth code customisation callback, if any.
						$code = call_user_func($this->callbacks[self::CUSTOMIZE_AUTHORIZATION_CODE], $code, $request);

						// Store the authorization code.
						$this->authorizationCodeStorage->put($code['code'], $code);

						// Return a redirect to the client app.
					}

					// Otherwise, the user is authenticated and needs to authorize the client app + choose scopes.

					// Fetch the client_id URL to find information about the client to present to the user.

					// If the authority of the redirect_uri does not match the client_id or one of their redirect URLs, return an error.

					// Present the authorization UI.
					return call_user_func($this->callbacks[self::SHOW_AUTHORIZATION_PAGE], $request, $authenticationResult, $authenticationRedirect);
				}
			}

			// If the request isn’t an IndieAuth Authorization or Code-redeeming request, it’s either an invalid
			// request or something to do with a custom auth handler (e.g. sending a one-time code in an email.)
			$nonIndieAuthRequestResult = call_user_func($this->callbacks[self::HANDLE_NON_INDIEAUTH_REQUEST], $request);
			if ($nonIndieAuthRequestResult instanceof ResponseInterface) {
				return $nonIndieAuthRequestResult;
			} else {
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_request'
				]));
			}
		}));
	}

	public function handleTokenEndpointRequest(ServerRequestInterface $request): ResponseInterface {
		// This is a request to redeem an authorization_code for an access_token.

		// Verify that the authorization code is valid and has not yet been used.

		// Verify that it was issued for the same client_id and redirect_uri

		// Check that the supplied code_verifier hashes to the stored code_challenge

		// If the auth code was issued with no scope, return an error.

		// If everything checks out, generate an access token and return it.
	}
}
