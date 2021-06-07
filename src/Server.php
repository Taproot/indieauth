<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use Exception;
use IndieAuth\Client as IndieAuthClient;
use Mf2;
use BarnabyWalters\Mf2 as M;
use GuzzleHttp\Psr7\Header as HeaderParser;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Constraint\Callback;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface as HttpClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Taproot\IndieAuth\Callback\AuthorizationFormInterface;
use Taproot\IndieAuth\Callback\DefaultAuthorizationForm;
use Taproot\IndieAuth\Middleware\ResponseRequestHandler;

/**
 * Development Reference
 *
 * Specification: https://indieauth.spec.indieweb.org/
 * Error responses: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
 * indieweb/indieauth-client: https://github.com/indieweb/indieauth-client-php
 */

class Server {
	const HANDLE_NON_INDIEAUTH_REQUEST = 'handleNonIndieAuthRequestCallback';
	const HANDLE_AUTHENTICATION_REQUEST = 'handleAuthenticationRequestCallback';
	const HASH_QUERY_STRING_KEY = 'taproot_indieauth_server_hash';
	const DEFAULT_CSRF_KEY = 'taproot_indieauth_server_csrf';

	public $callbacks;

	public Storage\TokenStorageInterface $authorizationCodeStorage;

	public Storage\TokenStorageInterface $accessTokenStorage;

	public AuthorizationFormInterface $authorizationForm;

	public MiddlewareInterface $csrfMiddleware;

	public LoggerInterface $logger;

	public HttpClientInterface $httpClient;

	public $httpGetWithEffectiveUrl;

	public $handleAuthenticationRequestCallback;

	public $handleNonIndieAuthRequest;

	protected string $secret;

	public function __construct(array $config) {
		$config = array_merge([
			'csrfMiddleware' => null,
			'logger' => null,
			self::HANDLE_NON_INDIEAUTH_REQUEST => function (ServerRequestInterface $request) { return null; }, // Default to no-op.
			'authorizationCodeStorage' => null,
			'accessTokenStorage' => null,
			'httpGetWithEffectiveUrl' => null,
			'authorizationForm' => new DefaultAuthorizationForm(),
		], $config);

		$secret = $config['secret'] ?? '';
		if (!is_string($secret) || strlen($secret) < 64) {
			throw new Exception("\$config['secret'] must be a string with a minimum length of 64 characters.");
		}
		$this->secret = $secret;

		if (!is_null($config['logger']) && !$config['logger'] instanceof LoggerInterface) {
			throw new Exception("\$config['logger'] must be an instance of \\Psr\\Log\\LoggerInterface or null.");
		}
		$this->logger = $config['logger'] ?? new NullLogger();

		if (!(array_key_exists(self::HANDLE_AUTHENTICATION_REQUEST, $config) and is_callable($config[self::HANDLE_AUTHENTICATION_REQUEST]))) {
			throw new Exception('$callbacks[\'' . self::HANDLE_AUTHENTICATION_REQUEST .'\'] must be present and callable.');
		}
		$this->handleAuthenticationRequestCallback = $config[self::HANDLE_AUTHENTICATION_REQUEST];
		
		if (!is_callable($config[self::HANDLE_NON_INDIEAUTH_REQUEST])) {
			throw new Exception("\$config['" . self::HANDLE_NON_INDIEAUTH_REQUEST . "'] must be callable");
		}
		$this->handleNonIndieAuthRequest = $config[self::HANDLE_NON_INDIEAUTH_REQUEST];

		$authorizationCodeStorage = $config['authorizationCodeStorage'];
		if (!$authorizationCodeStorage instanceof Storage\TokenStorageInterface) {
			if (is_string($authorizationCodeStorage)) {
				$authorizationCodeStorage = new Storage\FilesystemJsonStorage($authorizationCodeStorage, 600, true);
			} else {
				throw new Exception("\$config['authorizationCodeStorage'] must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.");
			}
		}
		trySetLogger($authorizationCodeStorage, $this->logger);
		$this->authorizationCodeStorage = $authorizationCodeStorage;

		$accessTokenStorage = $config['accessTokenStorage'];
		if (!$accessTokenStorage instanceof Storage\TokenStorageInterface) {
			if (is_string($accessTokenStorage)) {
				// Create a default access token storage with a TTL of 7 days.
				$accessTokenStorage = new Storage\FilesystemJsonStorage($accessTokenStorage, 60 * 60 * 24 * 7, true);
			} else {
				throw new Exception('$accessTokenStorage parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.');
			}
		}
		trySetLogger($accessTokenStorage, $this->logger);
		$this->accessTokenStorage = $accessTokenStorage;

		$csrfMiddleware = $config['csrfMiddleware'];
		if (!$csrfMiddleware instanceof MiddlewareInterface) {
			// Default to the statless Double-Submit Cookie CSRF Middleware, with default settings.
			$csrfMiddleware = new Middleware\DoubleSubmitCookieCsrfMiddleware(self::DEFAULT_CSRF_KEY);
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

		if (!$config['authorizationForm'] instanceof AuthorizationFormInterface) {
			throw new Exception("When provided, \$config['authorizationForm'] must implement Taproot\IndieAuth\Callback\AuthorizationForm.");
		}
		$this->authorizationForm = $config['authorizationForm'];
		trySetLogger($this->authorizationForm, $this->logger);
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
		return $this->csrfMiddleware->process($request, new Middleware\ClosureRequestHandler(function (ServerRequestInterface $request) {
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

				// Build a URL containing the indieauth authorization request parameters, hashing them
				// to protect them from being changed.
				// Make a hash of the protected indieauth-specific parameters.
				$hash = hashAuthorizationRequestParameters($request, $this->secret);
				$queryParams[self::HASH_QUERY_STRING_KEY] = $hash;
				
				$authenticationRedirect = $request->getUri()->withQuery(buildQueryString($queryParams));
				
				// User-facing requests always start by calling the authentication request callback.
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
						// Authorization approval requests MUST include a hash protecting the sensitive IndieAuth
						// authorization request parameters from being changed, e.g. by a malicious script which
						// found its way onto the authorization form.
						$expectedHash = hashAuthorizationRequestParameters($request, $this->secret);
						if (is_null($expectedHash)) {
							$this->logger->warning("An authorization approval request did not have a " . self::HASH_QUERY_STRING_KEY . " parameter.");
							return new Response(400, ['content-type' => 'text/plain'], 'The ' . self::HASH_QUERY_STRING_KEY . ' parameter was missing!');
						}
						if (!hash_equals($expectedHash, $queryParams[self::HASH_QUERY_STRING_KEY])) {
							$this->logger->warning("The hash provided in the URL was invalid!", [
								'expected' => $expectedHash,
								'actual' => $queryParams[self::HASH_QUERY_STRING_KEY]
							]);
							return new Response(400, ['content-type' => 'text/plain'], 'Invalid hash!');
						}

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
						
						$code = call_user_func($this->callbacks[self::HANDLE_AUTHORIZATION_FORM], $request, $code);
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
					return call_user_func($this->callbacks[self::SHOW_AUTHORIZATION_FORM], $request, $authenticationResult, $authenticationRedirect, $clientHApp);
				}
			}

			// If the request isn’t an IndieAuth Authorization or Code-redeeming request, it’s either an invalid
			// request or something to do with a custom auth handler (e.g. sending a one-time code in an email.)
			$nonIndieAuthRequestResult = call_user_func($this->handleNonIndieAuthRequest, $request);
			if ($nonIndieAuthRequestResult instanceof ResponseInterface) {
				return $nonIndieAuthRequestResult;
			} else {
				return new Response(400, ['content-type' => 'text/plain'], 'Invalid request!');
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
