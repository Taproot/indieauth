<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use BadMethodCallException;
use BarnabyWalters\Mf2 as M;
use Exception;
use GuzzleHttp\Psr7\Header as HeaderParser;
use IndieAuth\Client as IndieAuthClient;
use Mf2;
use Nyholm\Psr7\Response;
use PDO;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Taproot\IndieAuth\Callback\AuthorizationFormInterface;
use Taproot\IndieAuth\Callback\DefaultAuthorizationForm;
use Taproot\IndieAuth\Storage\TokenStorageInterface;

/**
 * IndieAuth Server
 * 
 * A PSR-7-compatible implementation of the request-handling logic for IndieAuth authorization endpoints
 * and token endpoints.
 * 
 * Typical minimal usage looks something like this:
 *     
 *     // Somewhere in your app set-up code:
 *     $server = new Taproot\IndieAuth\Server([
 *       // A secret key, >= 64 characters long.
 *       'secret' => YOUR_APP_INDIEAUTH_SECRET,
 * 
 *       // A path to store token data, or an object implementing TokenStorageInterface.
 *       'tokenStorage' => '/../data/auth_tokens/',
 * 
 *       // An authentication callback function, which either returns data about the current user,
 *       // or redirects to/implements an authentication flow.
 *       'authenticationHandler' => function (ServerRequestInterface $request, string $authenticationRedirect, ?string $normalizedMeUrl) {
 *         // If the request is authenticated, return an array with a `me` key containing the
 *         // canonical URL of the currently logged-in user.
 *         if ($userUrl = getLoggedInUserUrl($request)) {
 *           return ['me' => $userUrl];
 *         }
 *         
 *         // Otherwise, redirect the user to a login page, ensuring that they will be redirected
 *         // back to the IndieAuth flow with query parameters intact once logged in.
 *         return new Response('302', ['Location' => 'https://example.com/login?next=' . urlencode($authenticationRedirect)]);
 *       }
 *     ]);
 *     
 *     // In your authorization endpoint route:
 *     return $server->handleAuthorizationEndpointRequest($request);
 *     
 *     // In your token endpoint route:
 *     return $server->handleTokenEndpointRequest($request);
 *     
 *     // In another route (e.g. a micropub route), to authenticate the request:
 *     // (assuming $bearerToken is a token parsed from an “Authorization: Bearer XXXXXX” header
 *     // or access_token property from a request body)
 *     if ($accessToken = $server->getTokenStorage()->getAccessToken($bearerToken)) {
 *       // Request is authenticated as $accessToken['me'], and is allowed to
 *       // act according to the scopes listed in $accessToken['scope'].
 *       $scopes = explode(' ', $accessToken['scope']);
 *     }
 * 
 * Refer to the `__construct` documentation for further configuration options, and to the
 * documentation for both handling methods for further documentation about them.
 * 
 * @link https://indieauth.spec.indieweb.org/
 * @link https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
 * @link https://github.com/indieweb/indieauth-client-php
 * @link https://github.com/Zegnat/php-mindee/blob/development/index.php
 */
class Server {
	const HANDLE_NON_INDIEAUTH_REQUEST = 'handleNonIndieAuthRequestCallback';
	const HANDLE_AUTHENTICATION_REQUEST = 'authenticationHandler';

	/**
	 * The query string parameter key used for storing the hash used for validating authorization request parameters.
	 */
	const HASH_QUERY_STRING_KEY = 'taproot_indieauth_server_hash';

	/**
	 * The key used to store the CSRF token everywhere it’s used: Request parameters, Request body, and Cookies.
	 */
	const DEFAULT_CSRF_KEY = 'taproot_indieauth_server_csrf';

	/**
	 * The form data key used for identifying a request as an authorization (consent screen) form submissions.
	 */
	const APPROVE_ACTION_KEY = 'taproot_indieauth_action';

	/**
	 * The form data value used for identifying a request as an authorization (consent screen) form submissions.
	 */
	const APPROVE_ACTION_VALUE = 'approve';

	protected Storage\TokenStorageInterface $tokenStorage;

	protected AuthorizationFormInterface $authorizationForm;

	protected MiddlewareInterface $csrfMiddleware;

	protected LoggerInterface $logger;

	protected $httpGetWithEffectiveUrl;

	protected $handleAuthenticationRequestCallback;

	protected $handleNonIndieAuthRequest;

	protected string $exceptionTemplatePath;

	protected string $secret;

	/**
	 * Constructor
	 * 
	 * Server instances are configured by passing a config array to the constructor.
	 * 
	 * The following keys are required:
	 * 
	 * * `authenticationHandler`: a callable with the signature
	 *   `function (ServerRequestInterface $request, string $authenticationRedirect, ?string $normalizedMeUrl): array|ResponseInterface`.
	 *   This function is called on IndieAuth authorization requests, after validating the query parameters.
	 *   
	 *   It should check to see if $request is authenticated, then:
	 *     * If it is authenticated, return an array which MUST have a `me` key, mapping to the 
	 *       canonical URL of the currently logged-in user. It may additionally have a `profile` key. These
	 *       keys will be stored in the authorization code and sent to the client, if successful.
	 *     * If it is not authenticated, either present or redirect to an authentication flow. This flow MUST
	 *       redirect the logged-in used back to `$authenticationRedirect`.
	 *   
	 *   If the request has a valid `me` parameter, the canonicalized version of it is passed as
	 *   `$normalizedMeUrl`. Otherwise, this parameter is null. This parameter can optionally be used 
	 *   as a suggestion for which user to log in as in a multi-user authentication flow, but should NOT
	 *   be considered valid data.
	 *   
	 *   If redirecting to an existing authentication flow, this callable can usually be implemented as a
	 *   closure. The callable may also implement its own authentication logic. For an example, see 
	 *   `Callback\SingleUserPasswordAuthenticationCallback`.
	 * * `secret`: A cryptographically random string with a minimum length of 64 characters. Used
	 *   to hash and subsequently verify request query parameters which get passed around.
	 * * `tokenStorage`: Either an object implementing `Storage\TokenStorageInterface`, or a string path,
	 *   which will be passed to `Storage\FilesystemJsonStorage`. This object handles persisting authorization
	 *   codes and access tokens, as well as implementation-specific parts of the exchange process which are 
	 *   out of the scope of the Server class (e.g. lifetimes and expiry). Refer to the `Storage\TokenStorageInterface`
	 *   documentation for more details.
	 * 
	 * The following keys may be required depending on which packages you have installed:
	 * 
	 * * `httpGetWithEffectiveUrl`: must be a callable with the following signature:
	 *   `function (string $url): array [ResponseInterface $response, string $effectiveUrl]`, where 
	 *   `$effectiveUrl` is the final URL after following any redirects (unfortunately, neither the PSR-7
	 *   Response nor the PSR-18 Client interfaces offer a standard way of getting this very important
	 *   data, hence the unusual return signature).  If `guzzlehttp/guzzle` is installed, this parameter
	 *   will be created automatically. Otherwise, the user must provide their own callable.
	 * 
	 * The following keys are optional:
	 * 
	 * * `authorizationForm`: an instance of `AuthorizationFormInterface`. Defaults to `DefaultAuthorizationForm`.
	 *   Refer to that implementation if you wish to replace the consent screen/scope choosing/authorization form.
	 * * `csrfMiddleware`: an instance of `MiddlewareInterface`, which will be used to CSRF-protect the
	 *   user-facing authorization flow. By default an instance of `DoubleSubmitCookieCsrfMiddleware`.
	 *   Refer to that implementation if you want to replace it with your own middleware — you will 
	 *   likely have to either make sure your middleware sets the same request attribute, or alter your
	 *   templates accordingly.
	 * * `exceptionTemplatePath`: string, path to a template which will be used for displaying user-facing
	 *   errors. Defaults to `../templates/default_exception_response.html.php`, refer to that if you wish
	 *   to write your own template.
	 * * `handleNonIndieAuthRequestCallback`: A callback with the following signature:
	 *   `function (ServerRequestInterface $request): ?ResponseInterface` which will be called if the
	 *   authorization endpoint gets a request which is not identified as an IndieAuth request or authorization
	 *   form submission request. You could use this to handle various requests e.g. client-side requests
	 *   made by your authentication or authorization pages, if it’s not convenient to put them elsewhere.
	 *   Returning `null` will result in a standard `invalid_request` error being returned.
	 * * `logger`: An instance of `LoggerInterface`. Will be used for internal logging, and will also be set
	 *   as the logger for any objects passed in config which implement `LoggerAwareInterface`.
	 * 
	 * @param array $config An array of configuration variables
	 * @return self
	 */
	public function __construct(array $config) {
		$config = array_merge([
			'csrfMiddleware' => new Middleware\DoubleSubmitCookieCsrfMiddleware(self::DEFAULT_CSRF_KEY),
			'logger' => null,
			self::HANDLE_NON_INDIEAUTH_REQUEST => function (ServerRequestInterface $request) { return null; }, // Default to no-op.
			'tokenStorage' => null,
			'httpGetWithEffectiveUrl' => null,
			'authorizationForm' => new DefaultAuthorizationForm(),
			'exceptionTemplatePath' => __DIR__ . '/../templates/default_exception_response.html.php',
		], $config);

		if (!is_string($config['exceptionTemplatePath'])) {
			throw new BadMethodCallException("\$config['exceptionTemplatePath'] must be a string (path).");
		}
		$this->exceptionTemplatePath = $config['exceptionTemplatePath'];

		$secret = $config['secret'] ?? '';
		if (!is_string($secret) || strlen($secret) < 64) {
			throw new BadMethodCallException("\$config['secret'] must be a string with a minimum length of 64 characters.");
		}
		$this->secret = $secret;

		if (!is_null($config['logger']) && !$config['logger'] instanceof LoggerInterface) {
			throw new BadMethodCallException("\$config['logger'] must be an instance of \\Psr\\Log\\LoggerInterface or null.");
		}
		$this->logger = $config['logger'] ?? new NullLogger();

		if (!(array_key_exists(self::HANDLE_AUTHENTICATION_REQUEST, $config) and is_callable($config[self::HANDLE_AUTHENTICATION_REQUEST]))) {
			throw new BadMethodCallException('$callbacks[\'' . self::HANDLE_AUTHENTICATION_REQUEST .'\'] must be present and callable.');
		}
		$this->handleAuthenticationRequestCallback = $config[self::HANDLE_AUTHENTICATION_REQUEST];
		
		if (!is_callable($config[self::HANDLE_NON_INDIEAUTH_REQUEST])) {
			throw new BadMethodCallException("\$config['" . self::HANDLE_NON_INDIEAUTH_REQUEST . "'] must be callable");
		}
		$this->handleNonIndieAuthRequest = $config[self::HANDLE_NON_INDIEAUTH_REQUEST];

		$tokenStorage = $config['tokenStorage'];
		if (!$tokenStorage instanceof Storage\TokenStorageInterface) {
			if (is_string($tokenStorage)) {
				// Create a default access token storage with a TTL of 7 days.
				$tokenStorage = new Storage\FilesystemJsonStorage($tokenStorage, $this->secret);
			} else {
				throw new BadMethodCallException("\$config['tokenStorage'] parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.");
			}
		}
		trySetLogger($tokenStorage, $this->logger);
		$this->tokenStorage = $tokenStorage;

		$csrfMiddleware = $config['csrfMiddleware'];
		if (!$csrfMiddleware instanceof MiddlewareInterface) {
			throw new BadMethodCallException("\$config['csrfMiddleware'] must be null or implement MiddlewareInterface.");
		}
		trySetLogger($csrfMiddleware, $this->logger);
		$this->csrfMiddleware = $csrfMiddleware;

		$httpGetWithEffectiveUrl = $config['httpGetWithEffectiveUrl'];
		if (is_null($httpGetWithEffectiveUrl)) {
			if (class_exists('\GuzzleHttp\Client')) {
				$httpGetWithEffectiveUrl = function (string $uri) {
					// This code can’t be tested, ignore it for coverage purposes.
					// @codeCoverageIgnoreStart
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
				throw new BadMethodCallException("\$config['httpGetWithEffectiveUrl'] was not provided, and guzzlehttp/guzzle was not installed. Either require guzzlehttp/guzzle, or provide a valid callable.");
				// @codeCoverageIgnoreEnd
			}
		} else {
			if (!is_callable($httpGetWithEffectiveUrl)) {
				throw new BadMethodCallException("\$config['httpGetWithEffectiveUrl'] must be callable.");
			}
		}
		trySetLogger($httpGetWithEffectiveUrl, $this->logger);
		$this->httpGetWithEffectiveUrl = $httpGetWithEffectiveUrl;

		if (!$config['authorizationForm'] instanceof AuthorizationFormInterface) {
			throw new BadMethodCallException("When provided, \$config['authorizationForm'] must implement Taproot\IndieAuth\Callback\AuthorizationForm.");
		}
		$this->authorizationForm = $config['authorizationForm'];
		trySetLogger($this->authorizationForm, $this->logger);
	}

	public function getTokenStorage(): TokenStorageInterface {
		return $this->tokenStorage;
	}

	/**
	 * Handle Authorization Endpoint Request
	 * 
	 * This method handles all requests to your authorization endpoint, passing execution off to
	 * other callbacks when necessary. The logical flow can be summarised as follows:
	 * 
	 * * If this request an **auth code exchange for profile information**, validate the request
	 *   and return a response or error response.
	 * * Otherwise, proceed, wrapping all execution in CSRF-protection middleware.
	 * * Validate the request’s indieauth authorization code request parameters, returning an 
	 *   error response if any are missing or invalid.
	 * * Call the authentication callback
	 *     * If the callback returned an instance of ResponseInterface, the user is not currently
	 *       logged in. Return the Response, which will presumably start an authentication flow.
	 *     * Otherwise, the callback returned information about the currently logged-in user. Continue.
	 * * If this request is an authorization form submission, validate the data, store and authorization
	 *   code and return a redirect response to the client redirect_uri with code data. On an error, return
	 *   an appropriate error response.
	 * * Otherwise, fetch the client_id, parse app data if present, validate the `redirect_uri` and present
	 *   the authorization form/consent screen to the user.
	 * * If none of the above apply, try calling the non-indieauth request handler. If it returns a Response,
	 *   return that, otherwise return an error response.
	 * 
	 * This route should NOT be wrapped in additional CSRF-protection, due to the need to handle API 
	 * POST requests from the client. Make sure you call it from a route which is excluded from any
	 * CSRF-protection you might be using. To customise the CSRF protection used internally, refer to the
	 * `__construct` config array documentation for the `csrfMiddleware` key.
	 * 
	 * Most user-facing errors are thrown as instances of `IndieAuthException`, which are passed off to
	 * `handleException` to be turned into an instance of `ResponseInterface`. If you want to customise
	 * error behaviour, one way to do so is to subclass `Server` and override that method.
	 * 
	 * @param ServerRequestInterface $request
	 * @return ResponseInterface
	 */
	public function handleAuthorizationEndpointRequest(ServerRequestInterface $request): ResponseInterface {
		$this->logger->info('Handling an IndieAuth Authorization Endpoint request.');
		
		// If it’s a profile information request:
		if (isIndieAuthAuthorizationCodeRedeemingRequest($request)) {
			$this->logger->info('Handling a request to redeem an authorization code for profile information.');
			
			$bodyParams = $request->getParsedBody();

			if (!isset($bodyParams['code'])) {
				$this->logger->warning('The exchange request was missing the code parameter. Returning an error response.');
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_request',
					'error_description' => 'The code parameter was missing.'
				]));
			}

			// Attempt to internally exchange the provided auth code for an access token.
			// We do this before anything else so that the auth code is invalidated as soon as the request starts,
			// and the resulting access token is revoked if we encounter an error. This ends up providing a simpler
			// and more flexible interface for TokenStorage implementors.
			try {
				// Call the token exchange method, passing in a callback which performs additional validation
				// on the auth code before it gets exchanged.
				$tokenData = $this->tokenStorage->exchangeAuthCodeForAccessToken($bodyParams['code'], function (array $authCode) use ($request, $bodyParams) {
					// Verify that all required parameters are included.
					$requiredParameters = ['client_id', 'redirect_uri', 'code_verifier'];
					$missingRequiredParameters = array_filter($requiredParameters, function ($p) use ($bodyParams) {
						return !array_key_exists($p, $bodyParams) || empty($bodyParams[$p]);
					});
					if (!empty($missingRequiredParameters)) {
						$this->logger->warning('The exchange request was missing required parameters. Returning an error response.', ['missing' => $missingRequiredParameters]);
						throw IndieAuthException::create(IndieAuthException::INVALID_REQUEST, $request);
					}

					// Verify that it was issued for the same client_id and redirect_uri
					if ($authCode['client_id'] !== $bodyParams['client_id']
						|| $authCode['redirect_uri'] !== $bodyParams['redirect_uri']) {
						$this->logger->error("The provided client_id and/or redirect_uri did not match those stored in the token.");
						throw IndieAuthException::create(IndieAuthException::INVALID_GRANT, $request);
					}

					// Check that the supplied code_verifier hashes to the stored code_challenge
					// TODO: support method = plain as well as S256.
					if (!hash_equals($authCode['code_challenge'], generatePKCECodeChallenge($bodyParams['code_verifier']))) {
						$this->logger->error("The provided code_verifier did not hash to the stored code_challenge");
						throw IndieAuthException::create(IndieAuthException::INVALID_GRANT, $request);
					}

					// Check that this token either grants at most the profile scope.
					$requestedScopes = explode(' ', $authCode['scope'] ?? '');
					if (!empty($requestedScopes) && $requestedScopes != ['profile']) {
						$this->logger->error("An exchange request for a token granting scopes other than “profile” was sent to the authorization endpoint.");
						throw IndieAuthException::create(IndieAuthException::INVALID_GRANT, $request);
					}
				});
			} catch (IndieAuthException $e) {
				// If an exception was thrown, return a corresponding error response.
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => $e->getInfo()['error'],
					'error_description' => $e->getMessage()
				]));
			}

			if (is_null($tokenData)) {
				$this->logger->error('Attempting to exchange an auth code for a token resulted in null.', $bodyParams);
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// TODO: return an error if the token doesn’t contain a me key.

			// If everything checked out, return {"me": "https://example.com"} response
			return new Response(200, [
				'content-type' => 'application/json',
				'cache-control' => 'no-store',
			], json_encode(array_filter($tokenData, function ($k) {
				// Prevent codes exchanged at the authorization endpoint from returning any information other than
				// me and profile.
				return in_array($k, ['me', 'profile']);
			}, ARRAY_FILTER_USE_KEY)));
		}

		// Because the special case above isn’t allowed to be CSRF-protected, we have to do some rather silly
		// closure gymnastics here to selectively-CSRF-protect requests which do need it.
		return $this->csrfMiddleware->process($request, new Middleware\ClosureRequestHandler(function (ServerRequestInterface $request) {
			// Wrap the entire user-facing handler in a try/catch block which catches any exception, converts it
			// to IndieAuthException if necessary, then passes it to $this->handleException() to be turned into a
			// response.
			try {
				$queryParams = $request->getQueryParams();

				/** @var ResponseInterface|null $clientIdResponse */
				/** @var string|null $clientIdEffectiveUrl */
				/** @var array|null $clientIdMf2 */
				list($clientIdResponse, $clientIdEffectiveUrl, $clientIdMf2) = [null, null, null];

				// If this is an authorization or approval request (allowing POST requests as well to accommodate 
				// approval requests and custom auth form submission.
				if (isIndieAuthAuthorizationRequest($request, ['get', 'post'])) {
					$this->logger->info('Handling an authorization request', ['method' => $request->getMethod()]);

					// Validate the Client ID.
					if (!isset($queryParams['client_id']) || false === filter_var($queryParams['client_id'], FILTER_VALIDATE_URL) || !isClientIdentifier($queryParams['client_id'])) {
						$this->logger->warning("The client_id provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_CLIENT_ID, $request);
					}

					// Validate the redirect URI.
					if (!isset($queryParams['redirect_uri']) || false === filter_var($queryParams['redirect_uri'], FILTER_VALIDATE_URL)) {
						$this->logger->warning("The client_id provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_REDIRECT_URI, $request);
					}

					// How most errors are handled depends on whether or not the request has a valid redirect_uri. In
					// order to know that, we need to also validate, fetch and parse the client_id.
					// If the request lacks a hash, or if the provided hash was invalid, perform the validation.
					if (!array_key_exists(self::HASH_QUERY_STRING_KEY, $queryParams) || !hash_equals(hashAuthorizationRequestParameters($request, $this->secret), $queryParams[self::HASH_QUERY_STRING_KEY])) {
						// All we need to know at this stage is whether the redirect_uri is valid. If it
						// sufficiently matches the client_id, we don’t (yet) need to fetch the client_id.
						if (!urlComponentsMatch($queryParams['client_id'], $queryParams['redirect_uri'], [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PORT])) {
							// If we do need to fetch the client_id, store the response and effective URL in variables
							// we defined earlier, so they’re available to the approval request code path, which additionally
							// needs to parse client_id for h-app markup.
							try {
								list($clientIdResponse, $clientIdEffectiveUrl) = call_user_func($this->httpGetWithEffectiveUrl, $queryParams['client_id']);
								$clientIdMf2 = Mf2\parse((string) $clientIdResponse->getBody(), $clientIdEffectiveUrl);
							} catch (ClientExceptionInterface | RequestExceptionInterface | NetworkExceptionInterface $e) {
								$this->logger->error("Caught an HTTP exception while trying to fetch the client_id. Returning an error response.", [
									'client_id' => $queryParams['client_id'],
									'exception' => $e->__toString()
								]);

								throw IndieAuthException::create(IndieAuthException::HTTP_EXCEPTION_FETCHING_CLIENT_ID, $request, $e);
							} catch (Exception $e) {
								$this->logger->error("Caught an unknown exception while trying to fetch the client_id. Returning an error response.", [
									'exception' => $e->__toString()
								]);

								throw IndieAuthException::create(IndieAuthException::INTERNAL_EXCEPTION_FETCHING_CLIENT_ID, $request, $e);
							}
							
							// Search for all link@rel=redirect_uri at the client_id.
							$clientIdRedirectUris = [];
							if (array_key_exists('redirect_uri', $clientIdMf2['rels'])) {
								$clientIdRedirectUris = array_merge($clientIdRedirectUris, $clientIdMf2['rels']['redirect_uri']);
							}
							
							foreach (HeaderParser::parse($clientIdResponse->getHeader('Link')) as $link) {
								if (array_key_exists('rel', $link) && mb_strpos(" {$link['rel']} ", " redirect_uri ") !== false) {
									// Strip off the < > which surround the link URL for some reason.
									$clientIdRedirectUris[] = substr($link[0], 1, strlen($link[0]) - 2);
								}
							}

							// If the authority of the redirect_uri does not match the client_id, or exactly match one of their redirect URLs, return an error.
							if (!in_array($queryParams['redirect_uri'], $clientIdRedirectUris)) {
								$this->logger->warning("The provided redirect_uri did not match either the client_id, nor the discovered redirect URIs.", [
									'provided_redirect_uri' => $queryParams['redirect_uri'],
									'provided_client_id' => $queryParams['client_id'],
									'discovered_redirect_uris' => $clientIdRedirectUris
								]);

								throw IndieAuthException::create(IndieAuthException::INVALID_REDIRECT_URI, $request);
							}
						}						
					}

					// From now on, we can assume that redirect_uri is valid. Any IndieAuth-related errors should be
					// reported by redirecting to redirect_uri with error parameters.

					// Validate the state parameter.
					if (!isValidState($queryParams['state'])) {
						$this->logger->warning("The state provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_STATE, $request);
					}

					// Validate code_challenge parameter.
					if (!isValidCodeChallenge($queryParams['code_challenge'])) {
						$this->logger->warning("The code_challenge provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_CODE_CHALLENGE, $request);
					}

					// From now on, any redirect error responses should include the state parameter.
					// This is handled automatically in `handleException()` and is only noted here
					// for reference.

					// Validate the scope parameter, if provided.
					if (array_key_exists('scope', $queryParams) && !isValidScope($queryParams['scope'])) {
						$this->logger->warning("The scope provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_SCOPE, $request);
					}

					// Normalise the me parameter, if it exists.
					if (array_key_exists('me', $queryParams)) {
						$queryParams['me'] = IndieAuthClient::normalizeMeURL($queryParams['me']);
						// If the me parameter is not a valid profile URL, ignore it.
						if (false === $queryParams['me'] || !isProfileUrl($queryParams['me'])) {
							$queryParams['me'] = null;
						}
					}

					// Build a URL containing the indieauth authorization request parameters, hashing them
					// to protect them from being changed.
					// Make a hash of the protected indieauth-specific parameters.
					$hash = hashAuthorizationRequestParameters($request, $this->secret);
					// Operate on a copy of $queryParams, otherwise requests will always have a valid hash!
					$redirectQueryParams = $queryParams;
					$redirectQueryParams[self::HASH_QUERY_STRING_KEY] = $hash;
					$authenticationRedirect = $request->getUri()->withQuery(buildQueryString($redirectQueryParams))->__toString();
					
					// User-facing requests always start by calling the authentication request callback.
					$this->logger->info('Calling handle_authentication_request callback');
					$authenticationResult = call_user_func($this->handleAuthenticationRequestCallback, $request, $authenticationRedirect, $queryParams['me'] ?? null);
					
					// If the authentication handler returned a Response, return that as-is.
					if ($authenticationResult instanceof ResponseInterface) {
						return $authenticationResult;
					} elseif (is_array($authenticationResult)) {
						// Check the resulting array for errors.
						if (!array_key_exists('me', $authenticationResult)) {
							$this->logger->error('The handle_authentication_request callback returned an array with no me key.', ['array' => $authenticationResult]);
							throw IndieAuthException::create(IndieAuthException::AUTHENTICATION_CALLBACK_MISSING_ME_PARAM, $request);
						}

						// If this is a POST request sent from the authorization (i.e. scope-choosing) form:
						if (isAuthorizationApprovalRequest($request)) {
							// Authorization approval requests MUST include a hash protecting the sensitive IndieAuth
							// authorization request parameters from being changed, e.g. by a malicious script which
							// found its way onto the authorization form.
							if (!array_key_exists(self::HASH_QUERY_STRING_KEY, $queryParams)) {
								$this->logger->warning("An authorization approval request did not have a " . self::HASH_QUERY_STRING_KEY . " parameter.");
								throw IndieAuthException::create(IndieAuthException::AUTHORIZATION_APPROVAL_REQUEST_MISSING_HASH, $request);
							}

							$expectedHash = hashAuthorizationRequestParameters($request, $this->secret);
							if (!hash_equals($expectedHash, $queryParams[self::HASH_QUERY_STRING_KEY])) {
								$this->logger->warning("The hash provided in the URL was invalid!", [
									'expected' => $expectedHash,
									'actual' => $queryParams[self::HASH_QUERY_STRING_KEY]
								]);
								throw IndieAuthException::create(IndieAuthException::AUTHORIZATION_APPROVAL_REQUEST_INVALID_HASH, $request);
							}
							
							// Assemble the data for the authorization code, store it somewhere persistent.
							$code = array_merge($authenticationResult, [
								'client_id' => $queryParams['client_id'],
								'redirect_uri' => $queryParams['redirect_uri'],
								'state' => $queryParams['state'],
								'code_challenge' => $queryParams['code_challenge'],
								'code_challenge_method' => $queryParams['code_challenge_method'],
								'requested_scope' => $queryParams['scope'] ?? '',
							]);

							// Pass it to the auth code customisation callback.
							$code = $this->authorizationForm->transformAuthorizationCode($request, $code);

							// Store the authorization code.
							$authCode = $this->tokenStorage->createAuthCode($code);
							if (is_null($authCode)) {
								// If saving the authorization code failed silently, there isn’t much we can do about it,
								// but should at least log and return an error.
								$this->logger->error("Saving the authorization code failed and returned false without raising an exception.");
								throw IndieAuthException::create(IndieAuthException::INTERNAL_ERROR_REDIRECT, $request);
							}
							
							// Return a redirect to the client app.
							return new Response(302, [
								'Location' => appendQueryParams($queryParams['redirect_uri'], [
									'code' => $authCode,
									'state' => $code['state']
								]),
								'Cache-control' => 'no-cache'
							]);
						}

						// Otherwise, the user is authenticated and needs to authorize the client app + choose scopes.

						// Fetch the client_id URL to find information about the client to present to the user.
						// TODO: in order to comply with https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1,
						// it may be necessary to do this before returning any other kind of error response, as, per
						// the spec, errors should only be shown to the user if the client_id and redirect_uri parameters
						// are missing or invalid. Otherwise, they should be sent back to the client with an error
						// redirect response.
						if (is_null($clientIdResponse) || is_null($clientIdEffectiveUrl) || is_null($clientIdMf2)) {
							try {
								/** @var ResponseInterface $clientIdResponse */
								list($clientIdResponse, $clientIdEffectiveUrl) = call_user_func($this->httpGetWithEffectiveUrl, $queryParams['client_id']);
								$clientIdMf2 = Mf2\parse((string) $clientIdResponse->getBody(), $clientIdEffectiveUrl);
							} catch (ClientExceptionInterface | RequestExceptionInterface | NetworkExceptionInterface $e) {
								$this->logger->error("Caught an HTTP exception while trying to fetch the client_id. Returning an error response.", [
									'client_id' => $queryParams['client_id'],
									'exception' => $e->__toString()
								]);
								
								// At this point in the flow, we’ve already guaranteed that the redirect_uri is valid,
								// so in theory we should report these errors by redirecting there.
								throw IndieAuthException::create(IndieAuthException::INTERNAL_ERROR_REDIRECT, $request, $e);
							} catch (Exception $e) {
								$this->logger->error("Caught an unknown exception while trying to fetch the client_id. Returning an error response.", [
									'exception' => $e->__toString()
								]);
	
								throw IndieAuthException::create(IndieAuthException::INTERNAL_ERROR_REDIRECT, $request, $e);
							}
						}
						
						// Search for an h-app with u-url matching the client_id.
						$clientHApps = M\findMicroformatsByProperty(M\findMicroformatsByType($clientIdMf2, 'h-app'), 'url', $queryParams['client_id']);
						$clientHApp = empty($clientHApps) ? null : $clientHApps[0];

						// Present the authorization UI.
						return $this->authorizationForm->showForm($request, $authenticationResult, $authenticationRedirect, $clientHApp)
								->withAddedHeader('Cache-control', 'no-cache');
					}
				}

				// If the request isn’t an IndieAuth Authorization or Code-redeeming request, it’s either an invalid
				// request or something to do with a custom auth handler (e.g. sending a one-time code in an email.)
				$nonIndieAuthRequestResult = call_user_func($this->handleNonIndieAuthRequest, $request);
				if ($nonIndieAuthRequestResult instanceof ResponseInterface) {
					return $nonIndieAuthRequestResult;
				} else {
					// In this code path we have not validated the redirect_uri, so show a regular error page
					// rather than returning a redirect error.
					throw IndieAuthException::create(IndieAuthException::INTERNAL_ERROR, $request);
				}
			} catch (IndieAuthException $e) {
				// All IndieAuthExceptions will already have been logged.
				return $this->handleException($e);
			} catch (Exception $e) {
				// Unknown exceptions will not have been logged; do so now.
				$this->logger->error("Caught unknown exception: {$e}");
				return $this->handleException(IndieAuthException::create(0, $request, $e));
			}
		}));	
	}

	/**
	 * Handle Token Endpoint Request
	 * 
	 * Handles requests to the IndieAuth token endpoint. The logical flow can be summarised as follows:
	 * 
	 * * Check that the request is a code redeeming request. Return an error if not.
	 * * Ensure that all required parameters are present. Return an error if not.
	 * * Attempt to exchange the `code` parameter for an access token. Return an error if it fails.
	 * * Make sure the client_id and redirect_uri request parameters match those stored in the auth code. If not, revoke the access token and return an error.
	 * * Make sure the provided code_verifier hashes to the code_challenge stored in the auth code. If not, revoke the access token and return an error.
	 * * Make sure the granted scope stored in the auth code is not empty. If it is, revoke the access token and return an error.
	 * * Otherwise, return a success response containing information about the issued access token.
	 * 
	 * This method must NOT be CSRF-protected as it accepts external requests from client apps.
	 * 
	 * @param ServerRequestInterface $request
	 * @return ResponseInterface
	 */
	public function handleTokenEndpointRequest(ServerRequestInterface $request): ResponseInterface {
		if (isIndieAuthAuthorizationCodeRedeemingRequest($request)) {
			$this->logger->info('Handling a request to redeem an authorization code for profile information.');
			
			$bodyParams = $request->getParsedBody();

			if (!isset($bodyParams['code'])) {
				$this->logger->warning('The exchange request was missing the code parameter. Returning an error response.');
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_request',
					'error_description' => 'The code parameter was missing.'
				]));
			}

			// Attempt to internally exchange the provided auth code for an access token.
			// We do this before anything else so that the auth code is invalidated as soon as the request starts,
			// and the resulting access token is revoked if we encounter an error. This ends up providing a simpler
			// and more flexible interface for TokenStorage implementors.
			try {
				// Call the token exchange method, passing in a callback which performs additional validation
				// on the auth code before it gets exchanged.
				$tokenData = $this->tokenStorage->exchangeAuthCodeForAccessToken($bodyParams['code'], function (array $authCode) use ($request, $bodyParams) {
					// Verify that all required parameters are included.
					$requiredParameters = ['client_id', 'redirect_uri', 'code_verifier'];
					$missingRequiredParameters = array_filter($requiredParameters, function ($p) use ($bodyParams) {
						return !array_key_exists($p, $bodyParams) || empty($bodyParams[$p]);
					});
					if (!empty($missingRequiredParameters)) {
						$this->logger->warning('The exchange request was missing required parameters. Returning an error response.', ['missing' => $missingRequiredParameters]);
						throw IndieAuthException::create(IndieAuthException::INVALID_REQUEST, $request);
					}

					// Verify that it was issued for the same client_id and redirect_uri
					if ($authCode['client_id'] !== $bodyParams['client_id']
						|| $authCode['redirect_uri'] !== $bodyParams['redirect_uri']) {
						$this->logger->error("The provided client_id and/or redirect_uri did not match those stored in the token.");
						throw IndieAuthException::create(IndieAuthException::INVALID_GRANT, $request);
					}

					// Check that the supplied code_verifier hashes to the stored code_challenge
					// TODO: support method = plain as well as S256.
					if (!hash_equals($authCode['code_challenge'], generatePKCECodeChallenge($bodyParams['code_verifier']))) {
						$this->logger->error("The provided code_verifier did not hash to the stored code_challenge");
						throw IndieAuthException::create(IndieAuthException::INVALID_GRANT, $request);
					}

					// Check that scope is not empty.
					if (empty($authCode['scope'])) {
						$this->logger->error("An exchange request for a token with an empty scope was sent to the token endpoint.");
						throw IndieAuthException::create(IndieAuthException::INVALID_GRANT, $request);
					}
				});
			} catch (IndieAuthException $e) {
				// If an exception was thrown, return a corresponding error response.
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => $e->getInfo()['error'],
					'error_description' => $e->getMessage()
				]));
			}

			if (is_null($tokenData)) {
				$this->logger->error('Attempting to exchange an auth code for a token resulted in null.', $bodyParams);
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// TODO: return an error if the token doesn’t contain a me key.

			// If everything checked out, return {"me": "https://example.com"} response
			return new Response(200, [
				'content-type' => 'application/json',
				'cache-control' => 'no-store',
			], json_encode(array_merge([
				// Ensure that the token_type key is present, if tokenStorage doesn’t include it.
				'token_type' => 'Bearer'
			], array_filter($tokenData, function ($k) {
				// We should be able to trust the return data from tokenStorage, but there’s no harm in
				// preventing code_challenges from leaking, per OAuth2.
				return !in_array($k, ['code_challenge', 'code_challenge_method']);
			}, ARRAY_FILTER_USE_KEY))));
		}

		return new Response(400, ['content-type' => 'application/json'], json_encode([
			'error' => 'invalid_request',
			'error_description' => 'Request to token endpoint was not a valid code exchange request.'
		]));
	}

	/**
	 * Handle Exception
	 * 
	 * Turns an instance of `IndieAuthException` into an appropriate instance of `ResponseInterface`.
	 */
	protected function handleException(IndieAuthException $exception): ResponseInterface {
		$exceptionData = $exception->getInfo();

		if ($exceptionData['statusCode'] == 302) {
			// This exception is handled by redirecting to the redirect_uri with error parameters.
			$redirectQueryParams = [
				'error' => $exceptionData['error'] ?? 'invalid_request',
				'error_description' => (string) $exception
			];

			// If the state parameter was valid, include it in the error redirect.
			if ($exception->getCode() !== IndieAuthException::INVALID_STATE) {
				$redirectQueryParams['state'] = $exception->getRequest()->getQueryParams()['state'];
			}

			return new Response($exceptionData['statusCode'], [
				'Location' => appendQueryParams((string) $exception->getRequest()->getQueryParams()['redirect_uri'], $redirectQueryParams)
			]);
		} else {
			// This exception should be shown to the user.
			return new Response($exception->getStatusCode(), ['content-type' => 'text/html'], renderTemplate($this->exceptionTemplatePath, [
				'request' => $exception->getRequest(),
				'exception' => $exception
			]));
		}
	}
}
