<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use BadMethodCallException;
use DirectoryIterator;
use Exception;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Request;
use PHPUnit\Framework\TestCase;
use PHPUnit\TextUI\XmlConfiguration\File;
use Psr\Http\Message\ServerRequestInterface;
use Taproot\IndieAuth\Callback\DefaultAuthorizationForm;
use Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback;
use Taproot\IndieAuth\IndieAuthException;
use Taproot\IndieAuth\Server;
use Taproot\IndieAuth\Storage\FilesystemJsonStorage;
use Taproot\IndieAuth\Storage\Token;
use Taproot\IndieAuth\Storage\TokenStorageInterface;

use function GuzzleHttp\Promise\exception_for;
use function Taproot\IndieAuth\generatePKCECodeChallenge;
use function Taproot\IndieAuth\generateRandomString;
use function Taproot\IndieAuth\hashAuthorizationRequestParameters;
use function Taproot\IndieAuth\urlComponentsMatch;

const SERVER_SECRET = '1111111111111111111111111111111111111111111111111111111111111111';
const TOKEN_STORAGE_PATH = __DIR__ . '/tmp/tokens';
const CODE_EXCEPTION_TEMPLATE_PATH = __DIR__ . '/templates/code_exception_response.txt.php';
const AUTHORIZATION_FORM_JSON_RESPONSE_TEMPLATE_PATH = __DIR__ . '/templates/authorization_form_json_response.json.php';
const TMP_DIR = __DIR__ . '/tmp';

class ServerTest extends TestCase {

	/**
	 * Utility Methods
	 */

	protected function getDefaultServer(array $config=[]) {
		return new Server(array_merge([
			'secret' => SERVER_SECRET,
			'tokenStorage' => TOKEN_STORAGE_PATH,
			// With this template, IndieAuthException response bodies will contain only their IndieAuthException error code, for ease of comparison.
			'exceptionTemplatePath' => CODE_EXCEPTION_TEMPLATE_PATH,
			// Default to a simple single-user password authentication handler.
			Server::HANDLE_AUTHENTICATION_REQUEST => new SingleUserPasswordAuthenticationCallback(SERVER_SECRET, ['me' => 'https://example.com/'], password_hash('password', PASSWORD_DEFAULT), Server::DEFAULT_CSRF_KEY),
			'authorizationForm' => new DefaultAuthorizationForm(AUTHORIZATION_FORM_JSON_RESPONSE_TEMPLATE_PATH),
		], $config));
	}

	protected function getIARequest(array $params=[]): ServerRequestInterface {
		return (new ServerRequest('GET', 'https://example.com/'))->withQueryParams(array_merge([
			'response_type' => 'code',
			'client_id' => 'https://app.example.com/',
			'redirect_uri' => 'https://app.example.com/indieauth',
			'state' => '12345',
			'code_challenge' => hash('sha256', 'code'),
			'code_challenge_method' => 'S256'
		], $params));
	}

	protected function getApprovalRequest(bool $validCsrf=false, bool $addValidHash=false, ?array $queryParams=null, ?array $parsedBody=null): ServerRequestInterface {
		$queryParams = $queryParams ?? [];
		$parsedBody = $parsedBody ?? [];
		$cookieParams = [];

		$parsedBody[Server::APPROVE_ACTION_KEY] = Server::APPROVE_ACTION_VALUE;

		// Assume Middleware\DoubleSubmitCookieCsrfMiddleware is being used.
		$csrfVal = 'random_and_secure_csrf_value';
		if ($validCsrf) {
			$parsedBody[Server::DEFAULT_CSRF_KEY] = $csrfVal;
			$cookieParams = [
				Server::DEFAULT_CSRF_KEY => $csrfVal
			];
		}

		$req = $this->getIARequest($queryParams)
				->withMethod('POST')
				->withParsedBody($parsedBody)
				->withCookieParams($cookieParams);

		if ($addValidHash) {
			$req = $req->withQueryParams(array_merge($req->getQueryParams(), [
				Server::HASH_QUERY_STRING_KEY => hashAuthorizationRequestParameters($req, SERVER_SECRET)
			]));
		}

		return $req;
	}

	protected function setUp(): void {
		// Clean up tmp folder.
		@mkdir(TOKEN_STORAGE_PATH, 0777, true);
		foreach (new DirectoryIterator(TOKEN_STORAGE_PATH) as $fileInfo) {
			if ($fileInfo->isFile()) {
				unlink($fileInfo->getPathname());
			}
		}
		@rmdir(TOKEN_STORAGE_PATH);
	}

	protected function tearDown(): void {
		// Clean up tmp folder.
		@mkdir(TOKEN_STORAGE_PATH, 0777, true);
		foreach (new DirectoryIterator(TOKEN_STORAGE_PATH) as $fileInfo) {
			if ($fileInfo->isFile()) {
				unlink($fileInfo->getPathname());
			}
		}
		@rmdir(TOKEN_STORAGE_PATH);
	}

	/**
	 * Configuration/Instantiation Tests
	 */

	 public function testInvalidConfigRaisesException() {
		 $badConfigs = [
			 ['exceptionTemplatePath' => 21],
			 ['secret' => 12],
			 ['secret' => 'too short'],
			 ['logger' => 'not a logger'],
			 [Server::HANDLE_AUTHENTICATION_REQUEST => 'not a callable'],
			 [Server::HANDLE_NON_INDIEAUTH_REQUEST => 'again, not a callable'],
			 ['tokenStorage' => 34],
			 ['csrfMiddleware' => 'not a middleware object'],
			 ['httpGetWithEffectiveUrl' => 'not even a callable this time'],
			 ['authorizationForm' => 'not an auth form instance']
		 ];

		 foreach ($badConfigs as $testId => $badConfig) {
			 try {
				$this->getDefaultServer($badConfig);
				$this->fail("Test case {$testId} failed.");
			 } catch (BadMethodCallException $e) {
				$this->assertTrue(true);
			 }
		 }
	 }

	/**
	 * Authorization Request Tests
	 */

	public function testAuthorizationEndpointReturnsErrorOnMissingParameter() {
		$missingParameters = [
			'client_id' => 'static_error',
			'redirect_uri' => 'static_error',
			'code_challenge' => 'redirect_error',
			'code_challenge_method' => 'redirect_error',
			'state' => 'redirect_error',
		];
		$s = $this->getDefaultServer();
		foreach ($missingParameters as $missingParam => $errorType) {
			$req = $this->getIARequest();
			$qp = $req->getQueryParams();
			unset($qp[$missingParam]);
			$req = $req->withQueryParams($qp);

			$res = $s->handleAuthorizationEndpointRequest($req);

			if ($errorType == 'static_error') {
				$this->assertEquals(400, $res->getStatusCode(), $missingParam);
			} else {
				$this->assertEquals(302, $res->getStatusCode(), $missingParam);
			}
		}
	}

	public function testRequestsMissingBothPkceParametersReturnsError() {
		$s = $this->getDefaultServer();
		$req = $this->getIARequest();
		$qp = $req->getQueryParams();
		unset($qp['code_challenge']);
		unset($qp['code_challenge_method']);
		$req = $req->withQueryParams($qp);

		$res = $s->handleAuthorizationEndpointRequest($req);
		$this->assertEquals(302, $res->getStatusCode());
	}
	
	public function testAuthorizationRequestWithInvalidClientIdOrRedirectUriShowsErrorToUser() {
		$testCases = [
			'client_id not a URI' => [
				'expectedError' => IndieAuthException::INVALID_CLIENT_ID,
				'queryParams' => ['client_id' => 'this string is definitely not a valid URI']
			],
			'client_id host was an IP address' => [
				'expectedError' => IndieAuthException::INVALID_CLIENT_ID,
				'queryParams' => ['client_id' => 'https://12.56.12.5/']
			],
			'redirect_uri not a URI' => [
				'expectedError' => IndieAuthException::INVALID_REDIRECT_URI,
				'queryParams' => ['redirect_uri' => 'again, definitely not a valid URI.']
			]
		];

		foreach ($testCases as $testName => $testData) {
			$s = $this->getDefaultServer();
			$res = $s->handleAuthorizationEndpointRequest($this->getIARequest($testData['queryParams']));
			$this->assertEquals((string) $testData['expectedError'], (string) $res->getBody(), "Case “{$testName}” did not result in expected error {$testData['expectedError']}.");
		}
	}

	public function testInvalidStateCodeChallengeOrScopeReturnErrorRedirects() {
		$testCases = [
			'Invalid state' => [
				'expectedError' => IndieAuthException::INVALID_STATE,
				'queryParams' => ['state' => "This unprintable ASCII character is not allowed in state: \x19"]
			],
			'Invalid code_challenge' => [
				'expectedError' => IndieAuthException::INVALID_CODE_CHALLENGE,
				'queryParams' => ['code_challenge' => 'has_bad_characters_in_*%#ü____']
			],
			'Invalid scope' => [
				'expectedError' => IndieAuthException::INVALID_SCOPE,
				'queryParams' => ['scope' => '" is not a permitted scope character']
			]
		];

		foreach ($testCases as $testName => $testData) {
			$s = $this->getDefaultServer();
			$res = $s->handleAuthorizationEndpointRequest($this->getIARequest($testData['queryParams']));
			$this->assertEquals(302, $res->getStatusCode(), "Case “{$testName}” should result in a redirect error.");
			$expectedErrorName = IndieAuthException::EXC_INFO[IndieAuthException::INVALID_STATE]['error'];
			parse_str(parse_url($res->getHeaderLine('location'), PHP_URL_QUERY), $redirectQueryParams);
			$this->assertEquals($expectedErrorName, $redirectQueryParams['error']);
		}
	}

	public function testHandlesValidAndInvalidMeUrlsCorrectly() {
		$testCases = [
			'example.com' => 'http://example.com/',
			'https://example.com' => 'https://example.com/',
			'https://example.com/path?query' => 'https://example.com/path?query',
			'invalid URL' => null,
			'https://example.com/foo/../bar' => null,
			'https://example.com/#me' => null,
			'https://user:pass@example.com/' => null,
			'https://example.com:8443/' => null,
			'https://172.28.92.51/' => null
		];

		foreach ($testCases as $meUrl => $expected) {
			$s = $this->getDefaultServer([
				Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction, ?string $normalizedMeUrl) use ($expected) {
					$this->assertEquals($expected, $normalizedMeUrl);
				}
			]);
			$s->handleAuthorizationEndpointRequest($this->getIARequest(['me' => $meUrl]));
		}
	}

	public function testUnauthenticatedRequestReturnsAuthenticationResponse() {
		$expectedResponse = 'You need to authenticate before continuing!';
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) use ($expectedResponse) {
				return new Response(200, ['content-type' => 'text/plain'], $expectedResponse);
			}
		]);
		
		$res = $s->handleAuthorizationEndpointRequest($this->getIARequest());
		
		$this->assertEquals(200, $res->getStatusCode());
		$this->assertEquals($expectedResponse, (string) $res->getBody());
	}

	public function testReturnsServerErrorIfAuthenticationResultHasNoMeKey() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) {
				return [];
			}
		]);

		$req = $this->getIARequest();
		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(302, $res->getStatusCode());
		$responseLocation = $res->getHeaderLine('Location');
		$this->assertTrue(urlComponentsMatch($req->getQueryParams()['redirect_uri'], $responseLocation, [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PATH]));
		parse_str(parse_url($responseLocation, PHP_URL_QUERY), $redirectUriQueryParams);
		$this->assertEquals('internal_error', $redirectUriQueryParams['error']);
	}

	public function testReturnErrorIfFetchingClientIdThrowsException() {
		$exceptionClasses = [
			'GuzzleHttp\Exception\ConnectException' => (string) IndieAuthException::HTTP_EXCEPTION_FETCHING_CLIENT_ID,
			'GuzzleHttp\Exception\RequestException' => (string) IndieAuthException::HTTP_EXCEPTION_FETCHING_CLIENT_ID,
			'Exception' => (string) IndieAuthException::INTERNAL_EXCEPTION_FETCHING_CLIENT_ID
		];
		foreach ($exceptionClasses as $eClass => $expectedResponse) {
			$s = $this->getDefaultServer([
				Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) {
					return ['me' => 'https://example.com/'];
				},
				'httpGetWithEffectiveUrl' => function ($url) use ($eClass) {
					if ($eClass == 'Exception') { throw new Exception(); }
					throw new $eClass($eClass, new Request('GET', $url));
				}
			]);

			$req = $this->getIARequest();
			$res = $s->handleAuthorizationEndpointRequest($req);

			$this->assertEquals(302, $res->getStatusCode());
			$responseLocation = $res->getHeaderLine('Location');
			$this->assertTrue(urlComponentsMatch($req->getQueryParams()['redirect_uri'], $responseLocation, [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PATH]));
			parse_str(parse_url($responseLocation, PHP_URL_QUERY), $redirectUriQueryParams);
			$this->assertEquals('internal_error', $redirectUriQueryParams['error']);
		}
	}

	public function testReturnsErrorIfRedirectUriDoesntMatchClientIdWithNoParsedRedirectUris() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction): array {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function (string $url): array {
				// An empty response suffices for this test.
				return [
					new Response(200, ['content-type' => 'text/html'], '' ),
					$url
				];
			}
		]);

		$req = $this->getIARequest([
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://not-the-client.example.com/auth'
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals((string) IndieAuthException::INVALID_REDIRECT_URI, (string) $res->getBody());
	}

	public function testReturnsErrorIfRedirectUriDoesntMatchClientIdOrParsedRedirectUris() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction): array {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function ($url): array {
				// Pass some tricky values to test for correct rel parsing.
				return [
					new Response(200, [
							'content-type' => 'text/html',
							'link' => [
								'<https://not-the-client.example.com/auth>; rel="wrong_redirect_uri_rel"', // Matches redirect_uri but has wrong rel
								'<https://invalid.example.com/redirect>; rel="redirect_uri"' // redirect_uri is correct but url is invalid.
							]
						],
						<<<EOT
Rel correct, href not: <link rel="redirect_uri" href="https://yet-another-invalid.example.com/redirect" />
href matches redirect_uri, wrong rel: <link rel="another_incorrect_redirect_uri" href="https://not-the-client.example.com/auth" />
EOT
					),
					$url
				];
			}
		]);

		$req = $this->getIARequest([
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://not-the-client.example.com/auth'
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals((string) IndieAuthException::INVALID_REDIRECT_URI, (string) $res->getBody());
	}

	public function testReturnsAuthorizationFormIfClientIdSufficientlyMatchesRedirectUri() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction): array {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function ($url): array {
				return [
					new Response(200, ['content-type' => 'text/html'], ''), // An empty response suffices for this test.
					$url
				];
			}
		]);

		$req = $this->getIARequest([
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://client.example.com/auth'
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);
		
		$this->assertEquals('no-cache', $res->getHeaderLine('cache-control'));
		$this->assertEquals(200, $res->getStatusCode());
	}

	public function testReturnsAuthorizationFormIfClientIdExactlyMatchesParsedLinkHeaderRedirectUri() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction): array {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function (string $url): array {
				return [
					new Response(200, [
							'content-type' => 'text/html',
							'link' => '<https://link-header.example.com/auth>; rel="another_rel redirect_uri"'
						],
						''
					),
					$url
				];
			}
		]);

		$req = $this->getIARequest([
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://link-header.example.com/auth'
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals('no-cache', $res->getHeaderLine('cache-control'));
		$this->assertEquals(200, $res->getStatusCode());
	}

	public function testReturnsAuthorizationFormIfClientIdExactlyMatchesParsedLinkElementRedirectUri() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction): array {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function (string $url): array {
				return [
					new Response(200, ['content-type' => 'text/html'],
						'<link rel="redirect_uri another_rel" href="https://link-element.example.com/auth" />'
					),
					$url
				];
			}
		]);

		$req = $this->getIARequest([
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://link-element.example.com/auth'
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals('no-cache', $res->getHeaderLine('cache-control'));
		$this->assertEquals(200, $res->getStatusCode());
	}

	public function testFindsFirstHAppExactlyMatchingClientId() {
		$correctHAppName = 'Correct h-app!';
		$correctHAppUrl = 'https://client.example.com/';
		$correctHAppPhoto = 'https://client.example.com/logo.png';

		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function (string $url) use ($correctHAppPhoto, $correctHAppName, $correctHAppUrl): array {
				return [
					new Response(200, ['content-type' => 'text/html'],
						<<<EOT
<a class="h-app" href="https://not-the-client.example.com/">Wrong</a>

<a class="h-app" href="{$correctHAppUrl}"><img src="{$correctHAppPhoto}" alt="{$correctHAppName}" /></a>
EOT
					),
					$url
				];
			}
		]);

		$req = $this->getIARequest([
			'client_id' => $correctHAppUrl,
			'redirect_uri' => 'https://client.example.com/auth'
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(200, $res->getStatusCode());
		
		$parsedResponse = json_decode((string) $res->getBody(), true);
		$flatHApp = $parsedResponse['clientHApp'];
		$this->assertEquals($correctHAppUrl, $flatHApp['url']);
		$this->assertEquals($correctHAppName, $flatHApp['name']);
		$this->assertEquals($correctHAppPhoto, $flatHApp['photo']);
	}

	/**
	 * Test Authorization Approval Requests
	 */

	public function testReturnsErrorIfApprovalRequestHasNoHash() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) {
				return ['me' => 'https://example.com'];
			}
		]);
		
		$req = $this->getApprovalRequest(true, false);
		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(302, $res->getStatusCode());
		$responseLocation = $res->getHeaderLine('Location');
		$this->assertTrue(urlComponentsMatch($req->getQueryParams()['redirect_uri'], $responseLocation, [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PATH]));
		parse_str(parse_url($responseLocation, PHP_URL_QUERY), $redirectUriQueryParams);
		$this->assertEquals('internal_error', $redirectUriQueryParams['error']);
	}

	public function testReturnsErrorIfApprovalRequestHasInvalidHash() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) {
				return ['me' => 'https://example.com'];
			}
		]);
		$req = $this->getApprovalRequest(true, false);
		$req = $req->withQueryParams(array_merge($req->getQueryParams(), [
			Server::HASH_QUERY_STRING_KEY => 'clearly not a valid hash'
		]));
		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(302, $res->getStatusCode());
		$responseLocation = $res->getHeaderLine('Location');
		$this->assertTrue(urlComponentsMatch($req->getQueryParams()['redirect_uri'], $responseLocation, [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PATH]));
		parse_str(parse_url($responseLocation, PHP_URL_QUERY), $redirectUriQueryParams);
		$this->assertEquals('internal_error', $redirectUriQueryParams['error']);
	}

	public function testValidApprovalRequestIsHandledCorrectly() {
		// Make a valid authentication response with additional information, to make sure that it’s saved
		// in the authorization code.
		$authenticationResponse = [
			'me' => 'https://me.example.com/',
			'profile' => [
				'name' => 'Example Name'
			]
		];

		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) use ($authenticationResponse) {
				return $authenticationResponse;
			}
		]);
		
		// Make an approval request with valid CSRF tokens, a valid query parameter hash, one requested scope 
		// (different from the two granted scopes, so that we can test that requested and granted scopes are 
		// stored separately) and a redirect URI with a query string (so we can test that our IA query string
		// parameters are appended correctly).
		$grantedScopes = ['create', 'update'];
		$req = $this->getApprovalRequest(true, true, [
			'scope' => 'create',
			'redirect_uri' => 'https://app.example.com/indieauth?client_redirect_query_string_param=value'
		], [
			'taproot_indieauth_server_scope[]' => $grantedScopes
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);
		
		$this->assertEquals('no-cache', $res->getHeaderLine('cache-control'));
		$this->assertEquals(302, $res->getStatusCode(), 'The Response from a successful approval request must be a 302 redirect.');
		
		$responseLocation = $res->getHeaderLine('location');
		$queryParams = $req->getQueryParams();
		parse_str(parse_url($responseLocation, PHP_URL_QUERY), $redirectUriQueryParams);
		
		$this->assertTrue(urlComponentsMatch($responseLocation, $queryParams['redirect_uri'], [PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_USER, PHP_URL_PORT, PHP_URL_HOST, PHP_URL_PORT, PHP_URL_PATH]), 'The successful redirect response location did not match the redirect URI up to the path.');
		$this->assertEquals($redirectUriQueryParams['state'], $queryParams['state'], 'The redirect URI state parameter did not match the authorization request state parameter.');
		$this->assertEquals('value', $redirectUriQueryParams['client_redirect_query_string_param'], 'Query string params in the client app redirect_uri were not correctly preserved.');
		
		$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SECRET);
		$storedCode = $storage->get(hash_hmac('sha256', $redirectUriQueryParams['code'], SECRET));

		$this->assertNotNull($storedCode, 'An authorization code should be stored after a successful approval request.');
		
		foreach (['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method'] as $p) {
			$this->assertEquals($queryParams[$p], $storedCode[$p], "Parameter $p in the stored code ({$storedCode[$p]}) was not the same as the request parameter ($queryParams[$p]).");
		}

		$this->assertTrue(scopeEquals($queryParams['scope'], $storedCode['requested_scope']), "The requested scopes in the stored code ({$storedCode['requested_scope']}) did not match the scopes in the scope query parameter ({$queryParams['scope']}).");
		$this->assertTrue(scopeEquals($grantedScopes, $storedCode['scope']), "The granted scopes in the stored code ({$storedCode['scope']}) did not match the granted scopes from the authorization form response (" . join(' ', $grantedScopes) . ").");

		$this->assertEquals($authenticationResponse['me'], $storedCode['me'], "The “me” value in the stored code ({$storedCode['me']}) did not match the “me” value from the authentication response ({$authenticationResponse['me']}).");
		$this->assertEquals($authenticationResponse['profile'], $storedCode['profile'], "The “profile” value in the stored code did not match the “profile” value from the authentication response.");
	}

	public function testReturnsInternalServerErrorIfAuthCodeCannotBeStored() {
		$s = $this->getDefaultServer([
			'tokenStorage' => new NullTokenStorage(),
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction): array {
				return ['me' => 'https://me.example.com'];
			},
			'httpGetWithEffectiveUrl' => function ($url): array {
				return [
					new Response(200, ['content-type' => 'text/html'], ''),
					$url
				];
			}
		]);

		$req = $this->getApprovalRequest(true, true);

		$res = $s->handleAuthorizationEndpointRequest($req);
		
		$this->assertEquals(302, $res->getStatusCode());
		$expectedErrorName = IndieAuthException::EXC_INFO[IndieAuthException::INTERNAL_ERROR_REDIRECT]['error'];
		parse_str(parse_url($res->getHeaderLine('location'), PHP_URL_QUERY), $redirectQueryParams);
		$this->assertEquals($expectedErrorName, $redirectQueryParams['error']);
	}

	/**
	 * Test Authorization Token Exchange Requests
	 */

	public function testExchangeFlowsReturnErrorsIfCodeParameterIsMissing() {
		$s = $this->getDefaultServer();

		$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
			'grant_type' => 'authorization_code'
		]);

		$authEndpointResponse = $s->handleAuthorizationEndpointRequest($req);
		$this->assertEquals(400, $authEndpointResponse->getStatusCode());
		$authEndpointJson = json_decode((string) $authEndpointResponse->getBody(), true);
		$this->assertEquals('invalid_request', $authEndpointJson['error']);

		$tokenEndpointResponse = $s->handleTokenEndpointRequest($req);
		$this->assertEquals(400, $tokenEndpointResponse->getStatusCode());
		$tokenEndpointJson = json_decode((string) $tokenEndpointResponse->getBody(), true);
		$this->assertEquals('invalid_request', $tokenEndpointJson['error']);
	}

	public function testExchangeFlowsReturnErrorsIfParametersAreMissing() {
		$s = $this->getDefaultServer();

		foreach ([
			[$s, 'handleAuthorizationEndpointRequest'],
			[$s, 'handleTokenEndpointRequest']
		] as $exchangeEndpoint) {
			$authCode = $s->getTokenStorage()->createAuthCode([
				'client_id' => 'https://client.example.com/',
				'redirect_uri' => 'https://client.example.com/auth',
				'code_challenge' => generatePKCECodeChallenge(generateRandomString(32)),
				'state' => '12345',
				'code_challenge_method' => 'S256',
				'scope' => 'create update'
			]);
	
			$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
				'grant_type' => 'authorization_code',
				'code' => $authCode
			]);
	
			$res = $exchangeEndpoint($req);
			$this->assertEquals(400, $res->getStatusCode());
			$resJson = json_decode((string) $res->getBody(), true);
			$this->assertEquals('invalid_request', $resJson['error']);
		}
	}

	public function testExchangeFlowsReturnErrorOnInvalidParameters() {
		$s = $this->getDefaultServer();
		$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SERVER_SECRET);

		$testCases = [
			'Mismatched client_id' => ['client_id' => 'https://invalid-client.example.com/'],
			'Mismatched redirect_uri' => ['redirect_uri' => 'https://invalid-client.example.com/auth'],
			'Invalid code_verifier' => ['code_verifier' => 'definitely_not_the_randomly_generated_string'],
			'Wrong auth code' => ['code' => 'yeah_thats_not_the_right_code']
		];

		foreach ($testCases as $name => $params) {
			// These cases apply to both endpoints, test against both.
			foreach ([
					[$s, 'handleAuthorizationEndpointRequest'],
					[$s, 'handleTokenEndpointRequest'],
				] as $endpointHandler) {
				// Create an auth code.
				$codeVerifier = generateRandomString(32);
				$authCodeData = [
					'client_id' => 'https://client.example.com/',
					'redirect_uri' => 'https://client.example.com/auth',
					'code_challenge' => generatePKCECodeChallenge($codeVerifier),
					'state' => '12345',
					'code_challenge_method' => 'S256'
				];
				$authCode = $storage->createAuthCode($authCodeData);
				
				// Create what would by default be a successful request, then merge specific error-inducing params.
				$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody(array_merge([
					'grant_type' => 'authorization_code',
					'code' => $authCode,
					'client_id' => $authCodeData['client_id'],
					'redirect_uri' => $authCodeData['redirect_uri'],
					'code_verifier' => $codeVerifier
				], $params));

				$res = $endpointHandler($req);
				$this->assertEquals(400, $res->getStatusCode());
				$resJson = json_decode((string) $res->getBody(), true);
				$this->assertEquals('invalid_grant', $resJson['error']);
			}
		}
	}

	public function testAuthEndpointTokenExchangeFailsForTokensWithInvalidScope() {
		$s = $this->getDefaultServer();
		$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SERVER_SECRET);

		// Create an auth code.
		$codeVerifier = generateRandomString(32);
		$authCodeData = [
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://client.example.com/auth',
			'code_challenge' => generatePKCECodeChallenge($codeVerifier),
			'state' => '12345',
			'code_challenge_method' => 'S256',
			'scope' => 'create update'
		];
		$authCode = $storage->createAuthCode($authCodeData);
		
		// Create what would by default be a successful request, then merge specific error-inducing params.
		$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
			'grant_type' => 'authorization_code',
			'code' => $authCode,
			'client_id' => $authCodeData['client_id'],
			'redirect_uri' => $authCodeData['redirect_uri'],
			'code_verifier' => $codeVerifier
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(400, $res->getStatusCode());
		$resJson = json_decode((string) $res->getBody(), true);
		$this->assertEquals('invalid_grant', $resJson['error']);
	}

	public function testAuthEndpointTokenExchangeReturnsCorrectResponseForValidRequest() {
		$s = $this->getDefaultServer();
		$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SERVER_SECRET);

		// Create an auth code.
		$codeVerifier = generateRandomString(32);
		$authCodeData = [
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://client.example.com/auth',
			'code_challenge' => generatePKCECodeChallenge($codeVerifier),
			'state' => '12345',
			'code_challenge_method' => 'S256',
			'scope' => 'profile',
			'me' => 'https://me.example.com/',
			'profile' => [
				'name' => 'Me'
			]
		];
		$authCode = $storage->createAuthCode($authCodeData);
		
		// Create what would by default be a successful request, then merge specific error-inducing params.
		$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
			'grant_type' => 'authorization_code',
			'code' => $authCode,
			'client_id' => $authCodeData['client_id'],
			'redirect_uri' => $authCodeData['redirect_uri'],
			'code_verifier' => $codeVerifier
		]);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(200, $res->getStatusCode());
		$this->assertEquals('no-store', $res->getHeaderLine('cache-control'));
		$resJson = json_decode((string) $res->getBody(), true);
		$this->assertEquals([
			'me' => 'https://me.example.com/',
			'profile' => [
				'name' => 'Me'
			]
		], $resJson);
	}

	public function testTokenEndpointReturnsErrorOnNonIndieauthRequest() {
		$s = $this->getDefaultServer();

		$badRequests = [
			new ServerRequest('GET', 'https://example.com/'),
			new ServerRequest('POST', 'https://example.com/')
		];

		foreach ($badRequests as $badRequest) {
			$res = $s->handleTokenEndpointRequest($badRequest);
			$this->assertEquals(400, $res->getStatusCode());
			$resJson = json_decode((string) $res->getBody(), true);
			$this->assertEquals('invalid_request', $resJson['error']);
		}
	}

	public function testTokenEndpointReturnsErrorIfAccessCodeGrantsNoScopes() {
		$s = $this->getDefaultServer();
		$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SERVER_SECRET);

		// Create an auth code.
		$codeVerifier = generateRandomString(32);
		$authCodeData = [
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://client.example.com/auth',
			'code_challenge' => generatePKCECodeChallenge($codeVerifier),
			'state' => '12345',
			'code_challenge_method' => 'S256',
			'me' => 'https://me.example.com'
		];
		$authCode = $storage->createAuthCode($authCodeData);
		
		// Create what would by default be a successful request, then merge specific error-inducing params.
		$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
			'grant_type' => 'authorization_code',
			'code' => $authCode,
			'client_id' => $authCodeData['client_id'],
			'redirect_uri' => $authCodeData['redirect_uri'],
			'code_verifier' => $codeVerifier
		]);

		$res = $s->handleTokenEndpointRequest($req);

		$this->assertEquals(400, $res->getStatusCode());
		$resJson = json_decode((string) $res->getBody(), true);
		$this->assertEquals('invalid_grant', $resJson['error']);
	}

	public function testTokenEndpointReturnsAccessTokenOnValidRequest() {
		$s = $this->getDefaultServer();
		$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SERVER_SECRET);

		// Create an auth code.
		$codeVerifier = generateRandomString(32);
		$authCodeData = [
			'client_id' => 'https://client.example.com/',
			'redirect_uri' => 'https://client.example.com/auth',
			'code_challenge' => generatePKCECodeChallenge($codeVerifier),
			'state' => '12345',
			'code_challenge_method' => 'S256',
			'scope' => 'create update profile',
			'me' => 'https://me.example.com/',
			'profile' => [
				'name' => 'Me'
			]
		];
		$authCode = $storage->createAuthCode($authCodeData);
		
		// Create what would by default be a successful request, then merge specific error-inducing params.
		$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
			'grant_type' => 'authorization_code',
			'code' => $authCode,
			'client_id' => $authCodeData['client_id'],
			'redirect_uri' => $authCodeData['redirect_uri'],
			'code_verifier' => $codeVerifier
		]);

		$res = $s->handleTokenEndpointRequest($req);

		$this->assertEquals(200, $res->getStatusCode());
		$this->assertEquals('no-store', $res->getHeaderLine('cache-control'));
		$resJson = json_decode((string) $res->getBody(), true);
		$this->assertEquals(hash_hmac('sha256', $authCode, SERVER_SECRET), $resJson['access_token']);
		$this->assertEquals('Bearer', $resJson['token_type']);
		$this->assertEquals($authCodeData['me'], $resJson['me']);
		$this->assertEquals($authCodeData['profile'], $resJson['profile']);
		$this->assertTrue(scopeEquals($authCodeData['scope'], $resJson['scope']));

		// Make sure we can fetch the token from the token storage.
		$accessToken = $s->getTokenStorage()->getAccessToken($resJson['access_token']);
		$this->assertNotNull($accessToken);
		$this->assertEquals($accessToken['me'], $authCodeData['me']);
		$this->assertEquals($accessToken['scope'], $authCodeData['scope']);

		// Make sure we can revoke the token and no longer fetch it.
		$this->assertTrue($s->getTokenStorage()->revokeAccessToken($resJson['access_token']));
		$this->assertNull($s->getTokenStorage()->getAccessToken($resJson['access_token']));
	}

	/**
	 * Test Non-Indieauth Requests.
	 */

	public function testNonIndieAuthRequestWithDefaultHandlerReturnsError() {
		$res = $this->getDefaultServer()->handleAuthorizationEndpointRequest(new ServerRequest('GET', 'https://example.com'));

		$this->assertEquals((string) IndieAuthException::INTERNAL_ERROR, (string) $res->getBody());
	}

	public function testResponseReturnedFromNonIndieAuthRequestHandler() {
		$responseBody = 'A response to a non-indieauth request.';
		
		$res = $this->getDefaultServer([
			Server::HANDLE_NON_INDIEAUTH_REQUEST => function (ServerRequestInterface $request) use ($responseBody) {
				return new Response(200, ['content-type' => 'text/plain'], $responseBody);
			}
		])->handleAuthorizationEndpointRequest(new ServerRequest('GET', 'https://example.com'));

		$this->assertEquals($responseBody, (string) $res->getBody());
	}

	/**
	 * Test Backwards-compatibility
	 */

	public function testBackCompatRequestsWithoutPkceWorkCorrectlyWithBothExchangeFlows() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request) {
				return ['me' => 'https://me.example.com/'];
			},
			'httpGetWithEffectiveUrl' => function ($url): array {
				return [new Response(200, ['content-type' => 'text/html'], ''), $url ];
			},
			'requirePKCE' => false
		]);

		foreach ([
			'Auth Endpoint Exchange' => [$s, 'handleAuthorizationEndpointRequest'],
			'Token Endpoint Exchange' => [$s, 'handleTokenEndpointRequest']
		] as $testCase => $handleExchangeRequestEndpoint) {
			// Clean up the test environment.
			$this->setUp();
			// Build a valid, hashed request without either PKCE parameter. This takes some faffing around
			// due to the supposedly elegant immutable Request objects.
			$req = $this->getApprovalRequest(true, true, null, [
				'taproot_indieauth_server_scope[]' => ['profile']
			]);
			$params = $req->getQueryParams();
			unset($params['code_challenge']);
			unset($params['code_challenge_method']);
			$req = $req->withQueryParams($params);
			$hash = hashAuthorizationRequestParameters($req, SERVER_SECRET, null, null, false);
			$params[Server::HASH_QUERY_STRING_KEY] = $hash;
			$req = $req->withQueryParams($params);

			$res = $s->handleAuthorizationEndpointRequest($req);

			$this->assertEquals(302, $res->getStatusCode(), $testCase);
			parse_str(parse_url($res->getHeaderLine('location'), PHP_URL_QUERY), $redirectQueryParams);
			$this->assertArrayNotHasKey('error', $redirectQueryParams, "$testCase");
			$this->assertNotNull($redirectQueryParams['code'], $testCase);

			// Now check that the token exchange works.
			// Build 
			$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
				'grant_type' => 'authorization_code',
				'code' => $redirectQueryParams['code'],
				'client_id' => $params['client_id'],
				'redirect_uri' => $params['redirect_uri']
			]);

			$res = $handleExchangeRequestEndpoint($req);
			$resJson = json_decode((string) $res->getBody(), true);
			$this->assertEquals(200, $res->getStatusCode(), "$testCase");
			$this->assertIsArray($resJson, $testCase);
			$this->assertArrayNotHasKey('error', $resJson, $testCase);
			$this->assertEquals('https://me.example.com/', $resJson['me'], $testCase);
			if ($testCase == 'Token Endpoint Exchange') {
				$this->assertArrayHasKey('access_token', $resJson, $testCase);
			}
		}
	}

	public function testBackCompatNonPkceRequestMustLackBothPkceParameters() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request) {
				return ['me' => 'https://me.example.com/'];
			},
			'httpGetWithEffectiveUrl' => function ($url): array {
				return [new Response(200, ['content-type' => 'text/html'], ''), $url ];
			},
			'requirePKCE' => false
		]);
		
		// Build a valid, hashed request without either PKCE parameter. This takes some faffing around
		// due to the supposedly elegant immutable Request objects.
		$req = $this->getIARequest();
		$params = $req->getQueryParams();
		unset($params['code_challenge']);
		$req = $req->withQueryParams($params);

		$res = $s->handleAuthorizationEndpointRequest($req);

		$this->assertEquals(302, $res->getStatusCode());
		parse_str(parse_url($res->getHeaderLine('location'), PHP_URL_QUERY), $redirectQueryParams);
		$this->assertEquals('invalid_request', $redirectQueryParams['error']);
	}

	public function testBackCompatAuthCodeWithoutPkceCannotBeExchangedWithCodeVerifierBothExchangeEndpoints() {
		$s = $this->getDefaultServer([
			Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request) {
				return ['me' => 'https://me.example.com/'];
			},
			'httpGetWithEffectiveUrl' => function ($url): array {
				return [new Response(200, ['content-type' => 'text/html'], ''), $url ];
			},
			'requirePKCE' => false
		]);

		foreach ([
			'Auth Endpoint Exchange' => [$s, 'handleAuthorizationEndpointRequest'],
			'Token Endpoint Exchange' => [$s, 'handleTokenEndpointRequest']
		] as $testCase => $handleExchangeRequestEndpoint) {
			// Clean up the test environment.
			$this->setUp();
			$storage = new FilesystemJsonStorage(TOKEN_STORAGE_PATH, SERVER_SECRET);

			// Create an auth code without PKCE
			$authCodeData = [
				'client_id' => 'https://client.example.com/',
				'redirect_uri' => 'https://client.example.com/auth',
				'code_challenge' => null,
				'state' => '12345',
				'code_challenge_method' => null,
				'scope' => 'create update profile',
				'me' => 'https://me.example.com/',
				'profile' => [
					'name' => 'Me'
				]
			];
			$authCode = $storage->createAuthCode($authCodeData);

			// Now check that the token exchange works.
			// Build 
			$req = (new ServerRequest('POST', 'https://example.com'))->withParsedBody([
				'grant_type' => 'authorization_code',
				'code' => $authCode,
				'client_id' => $authCodeData['client_id'],
				'redirect_uri' => $authCodeData['redirect_uri'],
				'code_verifier' => 'There is no valid value for this parameter, its mere presence should trigger an error.'
			]);

			$res = $handleExchangeRequestEndpoint($req);
			$resJson = json_decode((string) $res->getBody(), true);
			$this->assertEquals(400, $res->getStatusCode(), "$testCase");
			$this->assertIsArray($resJson, $testCase);
			$this->assertArrayHasKey('error', $resJson, $testCase);
			$this->assertEquals('invalid_grant', $resJson['error'], $testCase);
		}
	}
}

/**
 * Utility functions and classes
 */

function scopeEquals($scope1, $scope2): bool {
	$scope1 = is_string($scope1) ? explode(' ', $scope1) : $scope1;
	$scope2 = is_string($scope2) ? explode(' ', $scope2) : $scope2;
	sort($scope1);
	sort($scope2);
	return $scope1 == $scope2;
}

class NullTokenStorage implements TokenStorageInterface {
	public function createAuthCode(array $data): ?string {
		return null;
	}

	public function getAccessToken(string $token): ?array {
		return null;
	}

	public function exchangeAuthCodeForAccessToken(string $code, callable $validateAuthCode): ?array {
		return null;
	}

	public function revokeAccessToken(string $token): bool {
		return false;
	}
}
