<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

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
}
