<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Taproot\IndieAuth as IA;

use function Taproot\IndieAuth\generatePKCECodeChallenge;
use function Taproot\IndieAuth\isClientIdentifier;
use function Taproot\IndieAuth\isProfileUrl;
use function Taproot\IndieAuth\isValidScope;
use function Taproot\IndieAuth\isValidState;
use function Taproot\IndieAuth\isValidCodeChallenge;

class FunctionTest extends TestCase {
	public function testGenerateRandomString() {
		$len = 10;
		$rand = IA\generateRandomString($len);
		$this->assertEquals($len, strlen(hex2bin($rand)));
	}

	public function testBuildQueryString() {
		$testCases = [
			'key=value' => ['key' => 'value'],
			'k1=v1&k2=v2' => ['k1' => 'v1', 'k2' => 'v2']
		];

		foreach ($testCases as $expected => $params) {
			$this->assertEquals($expected, IA\buildQueryString($params));
		}
	}

	public function testAppendQueryParams() {
		$testCases = [
			'https://example.com/?k=v' => ['https://example.com/', ['k' => 'v']],
			'https://example.com/?k=v' => ['https://example.com/?', ['k' => 'v']],
			'https://example.com/?k=v' => ['https://example.com/?k=v', []],
			'https://example.com/?k=v&k2=v2' => ['https://example.com/?k=v', ['k2' => 'v2']]
		];

		foreach ($testCases as $expected => list($uri, $params)) {
			$this->assertEquals($expected, IA\appendQueryParams($uri, $params));
		}
	}

	public function testHashAuthorizationRequestParametersReturnsNullWhenParameterIsMissing() {
		$req = (new ServerRequest('GET', 'https://example.com'))->withQueryParams([]);
		$hash = IA\hashAuthorizationRequestParameters($req, 'super secret');
		$this->assertNull($hash);
	}

	public function testHashAuthorizationRequestParametersIgnoresExtraParameters() {
		$params = [
			'client_id' => '1',
			'redirect_uri' => '1',
			'code_challenge' => '1',
			'code_challenge_method' => '1'
		];
		$req1 = (new ServerRequest('GET', 'https://example.com'))->withQueryParams($params);
		$req2 = (new ServerRequest('GET', 'https://example.com'))->withQueryParams(array_merge($params, [
			'an_additional_parameter' => 'an additional value!'
		]));
		$this->assertEquals(IA\hashAuthorizationRequestParameters($req1, 'super secret'), IA\hashAuthorizationRequestParameters($req2, 'super secret'));
	}

	// Taken straight from https://indieauth.spec.indieweb.org/#user-profile-url-li-6
	public function testIsProfileUrl() {
		$testCases = [
			'https://example.com/' => true,
			'https://example.com/username' => true,
			'https://example.com/users?id=100' => true,
			'example.com' => false,
			'mailto:user@example.com' => false,
			'https://example.com/foo/../bar' => false,
			'https://example.com/#me' => false,
			'https://user:pass@example.com/' => false,
			'https://example.com:8443/' => false,
			'https://172.28.92.51/' => false
		];

		foreach ($testCases as $url => $expected) {
			$this->assertEquals($expected, isProfileUrl($url), "$url was not correctly validated as $expected");
		}
	}

	public function testIsClientIentifier() {
		$testCases = [
			'https://example.com/' => true,
			'https://example.com/username' => true,
			'https://example.com/users?id=100' => true,
			'https://example.com:8443/' => true,
			'https://127.0.0.1/' => true,
			'https://[1::]/' => true,
			'example.com' => false,
			'mailto:user@example.com' => false,
			'https://example.com/foo/../bar' => false,
			'https://example.com/#me' => false,
			'https://user:pass@example.com/' => false,
			'https://172.28.92.51/' => false
		];

		foreach ($testCases as $url => $expected) {
			$this->assertEquals($expected, isClientIdentifier($url), "$url was not correctly validated as $expected");
		}
	}

	public function testIsValidState() {
		$testCases = [
			'hisdfbusdgiueryb@#$%^&*(' => true,
			"\x19" => false
		];

		foreach ($testCases as $test => $expected) {
			$this->assertEquals($expected, isValidState($test), "$test was not correctly validated as $expected");
		}
	}

	public function testIsValidScope() {
		$testCases = [
			'!#[]~' => true,
			'!#[]~ scope1 another_scope moar_scopes!' => true,
			'"' => false, // ASCII 0x22 not permitted
			'\\' => false, // ASCII 0x5C not permitted
		];

		foreach ($testCases as $test => $expected) {
			$this->assertEquals($expected, isValidScope($test), "$test was not correctly validated as $expected");
		}
	}

	// https://github.com/Taproot/indieauth/issues/13
	public function testIsValidCodeChallenge() {
		$testCases = [
			generatePKCECodeChallenge('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') => true,
			'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~' => true,
			'has_bad_characters_in_*%#ü____' => false
		];

		foreach ($testCases as $test => $expected) {
			$this->assertEquals($expected, isValidCodeChallenge($test), "$test was not correctly validated as $expected");
		}
	}
}
