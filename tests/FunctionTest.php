<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Taproot\IndieAuth as IA;

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
}
