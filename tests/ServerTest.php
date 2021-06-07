<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback;
use Taproot\IndieAuth\Server;
use Taproot\IndieAuth\Storage\FilesystemJsonStorage;

const SERVER_SECRET = '1111111111111111111111111111111111111111111111111111111111111111';
const AUTH_CODE_STORAGE_PATH = __DIR__ . '/tmp/authorization_codes';
const ACCESS_TOKEN_STORAGE_PATH = __DIR__ . '/tmp/authorization_codes';
const TMP_DIR = __DIR__ . '/tmp';

class ServerTest extends TestCase {
	protected function getDefaultServer() {
		return new Server([
			'secret' => SERVER_SECRET,
			'authorizationCodeStorage' => AUTH_CODE_STORAGE_PATH,
			'accessTokenStorage' => ACCESS_TOKEN_STORAGE_PATH,
			Server::HANDLE_AUTHENTICATION_REQUEST => new SingleUserPasswordAuthenticationCallback(['me' => 'https://example.com/'], password_hash('password', PASSWORD_DEFAULT))
		]);
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
}
