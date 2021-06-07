<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback;
use Taproot\IndieAuth\Server;
use Taproot\IndieAuth\Storage\FilesystemJsonStorage;

const SERVER_SECRET = '1111111111111111111111111111111111111111111111111111111111111111';
const AUTH_CODE_STORAGE_PATH = __DIR__ . '/tmp/authorization_codes';
const ACCESS_TOKEN_STORAGE_PATH = __DIR__ . '/tmp/authorization_codes';
const TMP_DIR = __DIR__ . '/tmp';

class ServerTest extends TestCase {
	protected function getDefaultServer(array $config=[]) {
		return new Server(array_merge([
			'secret' => SERVER_SECRET,
			'authorizationCodeStorage' => AUTH_CODE_STORAGE_PATH,
			'accessTokenStorage' => ACCESS_TOKEN_STORAGE_PATH,
			Server::HANDLE_AUTHENTICATION_REQUEST => new SingleUserPasswordAuthenticationCallback(['me' => 'https://example.com/'], password_hash('password', PASSWORD_DEFAULT))
		], $config));
	}

	protected function getIARequest(array $params=[]) {
		return (new ServerRequest('GET', 'https://example.com/'))->withQueryParams(array_merge([
			'response_type' => 'code',
			'client_id' => 'https://app.example.com/',
			'redirect_uri' => 'https://app.example.com/indieauth',
			'state' => '12345',
			'code_challenge' => hash('sha256', 'code'),
			'code_challenge_method' => 'sha256'
		], $params));
	}

	protected function setUp(): void {
		// Clean up tmp folder.
		new FilesystemJsonStorage(AUTH_CODE_STORAGE_PATH, -1, true);
		new FilesystemJsonStorage(ACCESS_TOKEN_STORAGE_PATH, -1, true);
		@rmdir(AUTH_CODE_STORAGE_PATH);
		@rmdir(ACCESS_TOKEN_STORAGE_PATH);
	}

	protected function tearDown(): void {
		// Clean up tmp folder.
		new FilesystemJsonStorage(AUTH_CODE_STORAGE_PATH, -1, true);
		new FilesystemJsonStorage(ACCESS_TOKEN_STORAGE_PATH, -1, true);
		@rmdir(AUTH_CODE_STORAGE_PATH);
		@rmdir(ACCESS_TOKEN_STORAGE_PATH);
	}

	public function testAuthorizationRequestMissingParametersReturnsError() {
		$s = $this->getDefaultServer();

		$req = (new ServerRequest('GET', 'https://example.com/'));
		$res = $s->handleAuthorizationEndpointRequest($req);
		$this->assertEquals(400, $res->getStatusCode());
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

		$res = $s->handleAuthorizationEndpointRequest($this->getIARequest());

		$this->assertEquals(500, $res->getStatusCode());
	}

	public function testReturnServerErrorIfFetchingClientIdThrowsException() {
		$exceptionClasses = ['GuzzleHttp\Exception\ConnectException', 'GuzzleHttp\Exception\RequestException'];
		foreach ($exceptionClasses as $eClass) {
			$req = $this->getIARequest();
			$s = $this->getDefaultServer([
				Server::HANDLE_AUTHENTICATION_REQUEST => function (ServerRequestInterface $request, string $formAction) {
					return ['me' => 'https://example.com/'];
				},
				'httpGetWithEffectiveUrl' => function ($url) use ($eClass, $req) {
					throw new $eClass($eClass, $req);
				}
			]);
	
			$res = $s->handleAuthorizationEndpointRequest($req);	

			$this->assertEquals(500, $res->getStatusCode());
		}
	}

	
}
