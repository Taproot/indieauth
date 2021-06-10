<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use Exception;
use IndieAuth\Client as IndieAuthClient;
use Mf2;
use BarnabyWalters\Mf2 as M;
use GuzzleHttp\Psr7\Header as HeaderParser;
use Nyholm\Psr7\Response;
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

/**
 * Development Reference
 * 
 * Specification: https://indieauth.spec.indieweb.org/
 * Error responses: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
 * indieweb/indieauth-client: https://github.com/indieweb/indieauth-client-php
 * Existing implementation with various validation functions and links to relevant spec portions: https://github.com/Zegnat/php-mindee/blob/development/index.php
 */

class Server {
	const HANDLE_NON_INDIEAUTH_REQUEST = 'handleNonIndieAuthRequestCallback';
	const HANDLE_AUTHENTICATION_REQUEST = 'handleAuthenticationRequestCallback';
	const HASH_QUERY_STRING_KEY = 'taproot_indieauth_server_hash';
	const DEFAULT_CSRF_KEY = 'taproot_indieauth_server_csrf';
	const APPROVE_ACTION_KEY = 'taproot_indieauth_action';
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

	public function __construct(array $config) {
		$config = array_merge([
			'csrfMiddleware' => null,
			'logger' => null,
			self::HANDLE_NON_INDIEAUTH_REQUEST => function (ServerRequestInterface $request) { return null; }, // Default to no-op.
			'tokenStorage' => null,
			'httpGetWithEffectiveUrl' => null,
			'authorizationForm' => new DefaultAuthorizationForm(),
			'exceptionTemplatePath' => __DIR__ . '/../templates/default_exception_response.html.php',
		], $config);

		if (!is_string($config['exceptionTemplatePath'])) {
			throw new Exception("\$config['secret'] must be a string (path).");
		}
		$this->exceptionTemplatePath = $config['exceptionTemplatePath'];

		$secret = $config['secret'] ?? '';
		if (!is_string($secret) || strlen($secret) < 64) {
			throw new Exception("\$config['secret'] must be a string with a minimum length of 64 characters. Make one with Taproot\IndieAuth\generateRandomString(64)");
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

		$tokenStorage = $config['tokenStorage'];
		if (!$tokenStorage instanceof Storage\TokenStorageInterface) {
			if (is_string($tokenStorage)) {
				// Create a default access token storage with a TTL of 7 days.
				$tokenStorage = new Storage\FilesystemJsonStorage($tokenStorage, $this->secret);
			} else {
				throw new Exception("\$config['tokenStorage'] parameter must be either a string (path) or an instance of Taproot\IndieAuth\TokenStorageInterface.");
			}
		}
		trySetLogger($tokenStorage, $this->logger);
		$this->tokenStorage = $tokenStorage;

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
					// @codeCoverageIgnoreEnd
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

	/**
	 * Handle Authorization Endpoint Request
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

			// Verify that all required parameters are included.
			$requiredParameters = ['client_id', 'redirect_uri', 'code', 'code_verifier'];
			$missingRequiredParameters = array_filter($requiredParameters, function ($p) use ($bodyParams) {
				return !array_key_exists($p, $bodyParams) || empty($bodyParams[$p]);
			});
			if (!empty($missingRequiredParameters)) {
				$this->logger->warning('The exchange request was missing required parameters. Returning an error response.', ['missing' => $missingRequiredParameters]);
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_request',
					'error_description' => 'The following required parameters were missing or empty: ' . join(', ', $missingRequiredParameters)
				]));
			}

			// Attempt to internally exchange the provided auth code for an access token.
			$token = $this->tokenStorage->exchangeAuthCodeForAccessToken($bodyParams['code']);

			if (is_null($token)) {
				$this->logger->error('Attempting to exchange an auth code for a token resulted in null.', $bodyParams);
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// Verify that it was issued for the same client_id and redirect_uri
			if ($token->getData()['client_id'] !== $bodyParams['client_id']
				|| $token->getData()['redirect_uri'] !== $bodyParams['redirect_uri']) {
				$this->tokenStorage->revokeAccessToken($token->getKey());
				$this->logger->error("The provided client_id and/or redirect_uri did not match those stored in the token.");
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// Check that the supplied code_verifier hashes to the stored code_challenge
			// TODO: support method = plain as well as S256.
			if (!hash_equals($token->getData()['code_challenge'], generatePKCECodeChallenge($bodyParams['code_verifier']))) {
				$this->tokenStorage->revokeAccessToken($token->getKey());
				$this->logger->error("The provided code_verifier did not hash to the stored code_challenge");
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// Check that this token either grants at most the profile scope.
			$requestedScopes = explode(' ', $token->getData()['scope'] ?? '');
			if (!empty($requestedScopes) && $requestedScopes != ['profile']) {
				$this->tokenStorage->revokeAccessToken($token->getKey());
				$this->logger->error("An exchange request for a token granting scopes other than “profile” was sent to the authorization endpoint.");
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// TODO: return an error if the token doesn’t contain a me key.

			// If everything checked out, return {"me": "https://example.com"} response
			return new Response(200, ['content-type' => 'application/json'], json_encode(array_filter($token->getData(), function ($k) {
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
						throw IndieAuthException::create(IndieAuthException::REQUEST_MISSING_PARAMETER, $request);
					}

					// Validate the Client ID.
					if (false === filter_var($queryParams['client_id'], FILTER_VALIDATE_URL) || !isClientIdentifier($queryParams['client_id'])) {
						$this->logger->warning("The client_id provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_CLIENT_ID, $request);
					}

					// Validate the redirect URI — at this stage only superficially, we’ll check it properly later if 
					// things go well.
					if (false === filter_var($queryParams['redirect_uri'], FILTER_VALIDATE_URL)) {
						$this->logger->warning("The client_id provided in an authorization request was not valid.", $queryParams);
						throw IndieAuthException::create(IndieAuthException::INVALID_REDIRECT_URI, $request);
					}

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
							$expectedHash = hashAuthorizationRequestParameters($request, $this->secret);
							if (is_null($expectedHash)) {
								// In theory this code should never be reached, as we already checked the request for valid parameters.
								// However, it’s possible for hashAuthorizationRequestParameters() to return null, and if for whatever
								// reason it does, the library should handle that case as elegantly as possible.
								// @codeCoverageIgnoreStart
								$this->logger->warning("Calculating the expected hash for an authorization approval request failed. This SHOULD NOT happen; if you encounter this error please contact the maintainers of taproot/indieauth.");
								throw IndieAuthException::create(IndieAuthException::REQUEST_MISSING_PARAMETER, $request);
								// @codeCoverageIgnoreEnd
							}
							
							if (!array_key_exists(self::HASH_QUERY_STRING_KEY, $queryParams)) {
								$this->logger->warning("An authorization approval request did not have a " . self::HASH_QUERY_STRING_KEY . " parameter.");
								throw IndieAuthException::create(IndieAuthException::AUTHORIZATION_APPROVAL_REQUEST_MISSING_HASH, $request);
							}

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
								throw IndieAuthException::create(IndieAuthException::INTERNAL_ERROR, $request);
							}
							
							// Return a redirect to the client app.
							return new Response(302, ['Location' => appendQueryParams($queryParams['redirect_uri'], [
								'code' => $authCode->getKey(),
								'state' => $code['state']
							])]);
						}

						// Otherwise, the user is authenticated and needs to authorize the client app + choose scopes.

						// Fetch the client_id URL to find information about the client to present to the user.
						try {
							/** @var ResponseInterface $clientIdResponse */
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
						
						// Search for an h-app with u-url matching the client_id.
						$clientHApps = M\findMicroformatsByProperty(M\findMicroformatsByType($clientIdMf2, 'h-app'), 'url', $queryParams['client_id']);
						$clientHApp = empty($clientHApps) ? null : $clientHApps[0];
						
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
						$clientIdMatchesRedirectUri = urlComponentsMatch($queryParams['client_id'], $queryParams['redirect_uri'], [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PORT]);
						$redirectUriValid = $clientIdMatchesRedirectUri || in_array($queryParams['redirect_uri'], $clientIdRedirectUris);

						if (!$redirectUriValid) {
							$this->logger->warning("The provided redirect_uri did not match either the client_id, nor the discovered redirect URIs.", [
								'provided_redirect_uri' => $queryParams['redirect_uri'],
								'provided_client_id' => $queryParams['client_id'],
								'discovered_redirect_uris' => $clientIdRedirectUris
							]);

							throw IndieAuthException::create(IndieAuthException::INVALID_REDIRECT_URI, $request);
						}

						// Present the authorization UI.
						return $this->authorizationForm->showForm($request, $authenticationResult, $authenticationRedirect, $clientHApp);
					}
				}

				// If the request isn’t an IndieAuth Authorization or Code-redeeming request, it’s either an invalid
				// request or something to do with a custom auth handler (e.g. sending a one-time code in an email.)
				$nonIndieAuthRequestResult = call_user_func($this->handleNonIndieAuthRequest, $request);
				if ($nonIndieAuthRequestResult instanceof ResponseInterface) {
					return $nonIndieAuthRequestResult;
				} else {
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

	public function handleTokenEndpointRequest(ServerRequestInterface $request): ResponseInterface {
		if (isIndieAuthAuthorizationCodeRedeemingRequest($request)) {
			$this->logger->info('Handling a request to redeem an authorization code for profile information.');
			
			$bodyParams = $request->getParsedBody();

			// Verify that all required parameters are included.
			$requiredParameters = ['client_id', 'redirect_uri', 'code', 'code_verifier'];
			$missingRequiredParameters = array_filter($requiredParameters, function ($p) use ($bodyParams) {
				return !array_key_exists($p, $bodyParams) || empty($bodyParams[$p]);
			});
			if (!empty($missingRequiredParameters)) {
				$this->logger->warning('The exchange request was missing required parameters. Returning an error response.', ['missing' => $missingRequiredParameters]);
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_request',
					'error_description' => 'The following required parameters were missing or empty: ' . join(', ', $missingRequiredParameters)
				]));
			}

			// Attempt to internally exchange the provided auth code for an access token.
			$token = $this->tokenStorage->exchangeAuthCodeForAccessToken($bodyParams['code']);

			if (is_null($token)) {
				$this->logger->error('Attempting to exchange an auth code for a token resulted in null.', $bodyParams);
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// Verify that it was issued for the same client_id and redirect_uri
			if ($token->getData()['client_id'] !== $bodyParams['client_id']
				|| $token->getData()['redirect_uri'] !== $bodyParams['redirect_uri']) {
				$this->tokenStorage->revokeAccessToken($token->getKey());
				$this->logger->error("The provided client_id and/or redirect_uri did not match those stored in the token.");
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// Check that the supplied code_verifier hashes to the stored code_challenge
			// TODO: support method = plain as well as S256.
			if (!hash_equals($token->getData()['code_challenge'], generatePKCECodeChallenge($bodyParams['code_verifier']))) {
				$this->tokenStorage->revokeAccessToken($token->getKey());
				$this->logger->error("The provided code_verifier did not hash to the stored code_challenge");
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// If the auth code was issued with no scope, return an error.
			if (empty($token->getData()['scope'])) {
				$this->tokenStorage->revokeAccessToken($token->getKey());
				$this->logger->error("Cannot issue an access token with no scopes.");
				return new Response(400, ['content-type' => 'application/json'], json_encode([
					'error' => 'invalid_grant',
					'error_description' => 'The provided credentials were not valid.'
				]));
			}

			// If everything checks out, generate an access token and return it.
			return new Response(200, ['content-type' => 'application/json'], json_encode(array_merge([
				'access_token' => $token->getKey(),
				'token_type' => 'Bearer'
			], array_filter($token->getData(), function ($k) {
				return in_array($k, ['me', 'profile', 'scope']);
			}, ARRAY_FILTER_USE_KEY))));
		}

		return new Response(400, ['content-type' => 'application/json'], json_encode([
			'error' => 'invalid_request',
			'error_description' => 'Request to token endpoint was not a valid code exchange request.'
		]));
	}

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
