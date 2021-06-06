<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use Exception;
use GuzzleHttp\Exception\ServerException;
use IndieAuth\Client as IndieAuthClient;
use Mf2;
use BarnabyWalters\Mf2 as M;
use GuzzleHttp\Psr7\Header as HeaderParser;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface as HttpClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function PHPSTORM_META\type;

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

/**
 * Append Query Parameters
 * 
 * Converts `$queryParams` into a query string, then checks `$uri` for an
 * existing query string. Then appends the newly generated query string
 * with either ? or & as appropriate.
 */
function appendQueryParams(string $uri, array $queryParams) {
	$queryString = buildQueryString($queryParams);
	$separator = parse_url($uri, \PHP_URL_QUERY) ? '&' : '?';
	return "{$uri}{$separator}{$queryString}";
}

function trySetLogger($target, LoggerInterface $logger) {
	if ($target instanceof LoggerAwareInterface) {
		$target->setLogger($logger);
	}
	return $target;
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

	public HttpClientInterface $httpClient;

	public callable $httpGetWithEffectiveUrl;

	public string $csrfKey;

	public function __construct(array $config) {
		$config = array_merge_recursive([
			'csrfMiddleware' => null,
			'csrfKey' => self::DEFAULT_CSRF_KEY,
			'logger' => null,
			'callbacks' => [
				self::CUSTOMIZE_AUTHORIZATION_CODE => function (array $code) { return $code; }, // Default to no-op.
				self::SHOW_AUTHORIZATION_PAGE => function (ServerRequestInterface $request, array $authenticationResult, string $authenticationRedirect) {  }, // TODO: Put the default implementation here.
				self::HANDLE_NON_INDIEAUTH_REQUEST => function (ServerRequestInterface $request) { return null; }, // Default to no-op.
			],
			'authorizationCodeStorage' => null,
			'accessTokenStorage' => null,
			'httpGetWithEffectiveUrl' => null
		], $config);

		if (!$config['logger'] instanceof LoggerInterface) {
			throw new Exception("\$config['logger'] must be an instance of \\Psr\\Log\\LoggerInterface or null.");
		}
		$this->logger = $config['logger'] ?? new NullLogger();

		$callbacks = $config['callbacks'];
		if (!(array_key_exists(self::HANDLE_AUTHENTICATION_REQUEST, $callbacks) and is_callable($callbacks[self::HANDLE_AUTHENTICATION_REQUEST]))) {
			throw new Exception('$callbacks[\'' . self::HANDLE_AUTHENTICATION_REQUEST .'\'] must be present and callable.');
		}
		$this->callbacks = $callbacks;
		
		$authorizationCodeStorage = $config['authorizationCodeStorage'];
		if (!$authorizationCodeStorage instanceof TokenStorageInterface) {
			if (is_string($authorizationCodeStorage)) {
				$authorizationCodeStorage = new FilesystemJsonStorage($authorizationCodeStorage, 600, true);
			} else {
				throw new Exception('$authorizationCodeStorage parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.');
			}
		}
		trySetLogger($authorizationCodeStorage, $this->logger);
		$this->authorizationCodeStorage = $authorizationCodeStorage;

		$accessTokenStorage = $config['accessTokenStorage'];
		if (!$accessTokenStorage instanceof TokenStorageInterface) {
			if (is_string($accessTokenStorage)) {
				// Create a default access token storage with a TTL of 7 days.
				$accessTokenStorage = new FilesystemJsonStorage($accessTokenStorage, 60 * 60 * 24 * 7, true);
			} else {
				throw new Exception('$accessTokenStorage parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.');
			}
		}
		trySetLogger($accessTokenStorage, $this->logger);
		$this->accessTokenStorage = $accessTokenStorage;
		
		$this->csrfKey = $config['csrfKey'];

		$csrfMiddleware = $config['csrfMiddleware'];
		if (!$csrfMiddleware instanceof MiddlewareInterface) {
			// Default to the statless Double-Submit Cookie CSRF Middleware, with default settings.
			$csrfMiddleware = new DoubleSubmitCookieCsrfMiddleware($this->csrfKey);
		}
		trySetLogger($csrfMiddleware, $this->logger);
		$this->csrfMiddleware = $csrfMiddleware;

		$httpGetWithEffectiveUrl = $config['httpGetWithEffectiveUrl'];
		if (!is_callable($httpGetWithEffectiveUrl)) {
			if (class_exists('\GuzzleHttp\Client')) {
				$httpGetWithEffectiveUrl = function (string $uri) {
					$resp = (new \GuzzleHttp\Client([
						\GuzzleHttp\RequestOptions::ALLOW_REDIRECTS => [
							'max' => 10,
							'strict' => true,
							'referer' => true,
							'track_redirects' => true
						]
					]))->get($uri);
					
					$rdh = $resp->getHeader('X-Guzzle-Redirect-History');
					$effectiveUrl = empty($rdh) ? $uri : array_values($rdh)[count($rdh) - 1];

					return [$resp, $effectiveUrl];
				};
			} else {
				throw new Exception('No valid $httpGetWithEffectiveUrl was provided, and guzzlehttp/guzzle was not installed. Either require guzzlehttp/guzzle, or provide a valid callable.');
			}
		}
		trySetLogger($httpGetWithEffectiveUrl, $this->logger);
		$this->httpGetWithEffectiveUrl = $httpGetWithEffectiveUrl;
	}

	public function handleAuthorizationEndpointRequest(ServerRequestInterface $request): ResponseInterface {
		$this->logger->info('Handling an IndieAuth Authorization Endpoint request.');
		
		// If it’s a profile information request:
		if (isIndieAuthAuthorizationCodeRedeemingRequest($request)) {
			$this->logger->info('Handling a request to redeem an authorization code for profile information.');
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
				$this->logger->info('Handling an authorization request', ['method' => $request->getMethod()]);

				$queryParams = $request->getQueryParams();
				// Return an error if we’re missing required parameters.
				$requiredParameters = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method'];
				$missingRequiredParameters = array_filter($requiredParameters, function ($p) use ($queryParams) {
					return !array_key_exists($p, $queryParams) || empty($queryParams[$p]);
				});
				if (!empty($missingRequiredParameters)) {
					$this->logger->warning('The authorization request was missing required parameters. Returning an error response.', ['missing' => $missingRequiredParameters]);
					// TODO: return a better response, or at least allow the library consumer to configure a better response.
					return new Response(400, ['content-type' => 'text/plain'], 'The IndieAuth request was missing the following parameters: ' . join("\n", $missingRequiredParameters));
				}

				// Normalise the me parameter, if it exists.
				if (array_key_exists('me', $queryParams)) {
					$queryParams['me'] = IndieAuthClient::normalizeMeURL($queryParams['me']);
				}

				// Build a URL for the authentication flow to redirect to, if it needs to.
				// TODO: perhaps filter queryParams to only include the indieauth-relevant params?
				$authenticationRedirect = $request->getUri() . '?' . buildQueryString($queryParams);
				
				$this->logger->info('Calling handle_authentication_request callback');
				$authenticationResult = call_user_func($this->callbacks[self::HANDLE_AUTHENTICATION_REQUEST], $request, $authenticationRedirect);

				// If the authentication handler returned a Response, return that as-is.
				if ($authenticationResult instanceof Response) {
					return $authenticationResult;
				} elseif (is_array($authenticationResult)) {
					// Check the resulting array for errors.
					if (!array_key_exists('me', $authenticationResult)) {
						$this->logger->error('The handle_authentication_request callback returned an array with no me key.', ['array' => $authenticationResult]);
						return new Response(500, ['content-type' => 'text/plain'], 'An internal error occurred.');
					}

					// Fetch the client_id URL to find information about the client to present to the user.
					try {
						/** @var ResponseInterface $clientIdResponse */
						list($clientIdResponse, $clientIdEffectiveUrl) = call_user_func($this->httpGetWithEffectiveUrl, $queryParams['client_id']);
						$clientIdMf2 = Mf2\parse($clientIdResponse->getBody()->getContents(), $clientIdEffectiveUrl);
					} catch (ClientExceptionInterface | RequestExceptionInterface | NetworkExceptionInterface $e) {
						$this->logger->error("Caught an HTTP exception while trying to fetch the client_id. Returning an error response.", [
							'client_id' => $queryParams['client_id'],
							'exception' => $e->__toString()
						]);

						return new Response(500, ['content-type' => 'text/plain'], 'An internal error occurred.');
					} catch (Exception $e) {
						$this->logger->error("Caught an unknown exception while trying to fetch the client_id. Returning an error response.", [
							'exception' => $e->__toString()
						]);

						return new Response(500, ['content-type' => 'text/plain'], 'An internal error occurred.');
					}
					
					// Search for an h-app with u-url matching the client_id.
					$clientHApps = M\findMicroformatsByProperty(M\findMicroformatsByType($clientIdMf2, 'h-app'), 'url', $queryParams['client-id']);
					$clientHApp = empty($clientHApps) ? null : $clientHApps[0];

					// Search for all link@rel=redirect_uri at the client_id.
					$clientIdRedirectUris = [];
					if (array_key_exists('redirect_uri', $clientIdMf2['rels'])) {
						$clientIdRedirectUris = array_merge($clientIdRedirectUris, $clientIdMf2['rels']);
					}
					foreach (HeaderParser::parse($clientIdResponse->getHeader('Link')) as $link) {
						if (array_key_exists('rel', $link) and str_contains(" {$link['rel']} ", " redirect_uri ")) {
							// Strip off the < > which surround the link URL for some reason.
							$clientIdRedirectUris[] = substr($link[0], 1, strlen($link[0]) - 2);
						}
					}

					// If the authority of the redirect_uri does not match the client_id, or exactly match one of their redirect URLs, return an error.
					$cidComponents = M\parseUrl($queryParams['client_id']);
					$ruriComponents = M\parseUrl($queryParams['redirect_uri']);
					$clientIdMatchesRedirectUri = $cidComponents['scheme'] == $ruriComponents['scheme']
							&& $cidComponents['host'] == $ruriComponents['host']
							&& $cidComponents['port'] == $ruriComponents['port'];
					$redirectUriValid = $clientIdMatchesRedirectUri || in_array($queryParams['redirect_uri'], $clientIdRedirectUris);

					if (!$redirectUriValid) {
						$this->logger->warning("The provided redirect_uri did not match either the client_id, nor the discovered redirect URIs.", [
							'provided_redirect_uri' => $queryParams['redirect_uri'],
							'provided_client_id' => $queryParams['client_id'],
							'discovered_redirect_uris' => $clientIdRedirectUris
						]);

						return new Response(500, ['content-type' => 'text/plain'], 'An internal error occurred.');
					}

					// If this is a POST request sent from the authorization (i.e. scope-choosing) form:
					if (isAuthorizationApprovalRequest($request)) {
						// Assemble the data for the authorization code, store it somewhere persistent.
						$code = array_merge($authenticationResult, [
							'client_id' => $queryParams['client_id'],
							'redirect_uri' => $queryParams['redirect_uri'],
							'state' => $queryParams['state'],
							'code_challenge' => $queryParams['code_challenge'],
							'code_challenge_method' => $queryParams['code_challenge_method'],
							'requested_scope' => $queryParams['scope'] ?? '',
							'code' => generateRandomString(256)
						]);

						// Pass it to the auth code customisation callback, if any.
						$code = call_user_func($this->callbacks[self::CUSTOMIZE_AUTHORIZATION_CODE], $code, $request);

						// Store the authorization code.
						$this->authorizationCodeStorage->put($code['code'], $code);

						// Return a redirect to the client app.
						return new Response(302, ['Location' => appendQueryParams($queryParams['redirect_uri'], [
							'code' => $code['code'],
							'state' => $code['state']
						])]);
					}

					// Otherwise, the user is authenticated and needs to authorize the client app + choose scopes.

					// Present the authorization UI.
					return call_user_func($this->callbacks[self::SHOW_AUTHORIZATION_PAGE], $request, $authenticationResult, $authenticationRedirect, $clientHApp);
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
