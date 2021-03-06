<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use BadMethodCallException;
use Dflydev\FigCookies;
use Exception;
use Nyholm\Psr7;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback;
use Taproot\IndieAuth\Server;

class SingleUserPasswordAuthenticationCallbackTest extends TestCase {
	public function testThrowsExceptionIfUserDataHasNoMeKey() {
		try {
			$c = new SingleUserPasswordAuthenticationCallback(SERVER_SECRET, [
				'not_me' => 'blah'
			], password_hash('password', PASSWORD_DEFAULT));
			$this->fail();
		} catch (BadMethodCallException $e) {
			$this->assertEquals('The $user array MUST contain a “me” key, the value which must be the user’s canonical URL as a string.', $e->getMessage());
		}
	}

	public function testThrowsExceptionIfSecretIsTooShort() {
		try {
			$c = new SingleUserPasswordAuthenticationCallback('not long enough', [
				'me' => 'blah'
			], password_hash('password', PASSWORD_DEFAULT));
			$this->fail();
		} catch (BadMethodCallException $e) {
			$this->assertEquals('$secret must be a string with a minimum length of 64 characters.', $e->getMessage());
		}
	}

	public function testThrowsExceptionIfHashedPasswordIsInvalid() {
		try {
			$c = new SingleUserPasswordAuthenticationCallback(SERVER_SECRET, [
				'me' => 'https://me.example.com/'
			], 'definitely not a hashed password');
			$this->fail();
		} catch (BadMethodCallException $e) {
			$this->assertTrue(true);
		}
	}

	public function testShowsAuthenticationFormOnUnauthenticatedRequest() {
		$callback = new SingleUserPasswordAuthenticationCallback(SERVER_SECRET, [
			'me' => 'https://me.example.com/'
		], password_hash('password', PASSWORD_DEFAULT));

		$formAction = 'https://example.com/formaction';

		$req = (new ServerRequest('GET', 'https://example.com/login'))->withAttribute(Server::DEFAULT_CSRF_KEY, 'csrf token');
		$res = $callback($req, $formAction);

		$this->assertEquals(200, $res->getStatusCode());
		// For the moment, just do a very naieve test.
		$this->assertStringContainsString($formAction, (string) $res->getBody());
	}

	public function testReturnsCookieRedirectOnAuthenticatedRequest() {
		$userData = [
			'me' => 'https://me.example.com',
			'profile' => ['name' => 'Me']
		];

		$password = 'my very secure password';

		$callback = new SingleUserPasswordAuthenticationCallback(SERVER_SECRET, $userData, password_hash($password, PASSWORD_DEFAULT));

		$req = (new ServerRequest('POST', 'https://example.com/login'))
				->withAttribute(Server::DEFAULT_CSRF_KEY, 'csrf token')
				->withParsedBody([
					SingleUserPasswordAuthenticationCallback::PASSWORD_FORM_PARAMETER => $password
				]);
		
		$res = $callback($req, 'form_action');

		$this->assertEquals(302, $res->getStatusCode());
		$this->assertEquals('form_action', $res->getHeaderLine('location'));
		$resCookies = FigCookies\SetCookies::fromResponse($res);
		$hashCookie = $resCookies->get(SingleUserPasswordAuthenticationCallback::LOGIN_HASH_COOKIE);
		$this->assertEquals(hash_hmac('SHA256', json_encode($userData), SERVER_SECRET), $hashCookie->getValue());
	}

	public function testReturnsUserDataOnResponseWithValidHashCookie() {
		$userData = [
			'me' => 'https://me.example.com',
			'profile' => ['name' => 'Me']
		];

		$password = 'my very secure password';

		$callback = new SingleUserPasswordAuthenticationCallback(SERVER_SECRET, $userData, password_hash($password, PASSWORD_DEFAULT));

		$req = (new ServerRequest('POST', 'https://example.com/login'))
				->withAttribute(Server::DEFAULT_CSRF_KEY, 'csrf token')
				->withCookieParams([
					SingleUserPasswordAuthenticationCallback::LOGIN_HASH_COOKIE => hash_hmac('SHA256', json_encode($userData), SERVER_SECRET)
				]);
		
		$res = $callback($req, 'form_action');

		$this->assertEquals($userData, $res);
	}
}
