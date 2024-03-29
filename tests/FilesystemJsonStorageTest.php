<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use DirectoryIterator;
use PHPUnit\Framework\TestCase;
use Taproot\IndieAuth\Storage\FilesystemJsonStorage;

const SECRET = '1111111111111111111111111111111111111111111111111111111111111111';

class FilesystemJsonStorageTest extends TestCase {
	protected function setUp(): void {
		@mkdir(TMP_DIR);
		// Clean tmp dir.
		foreach (new DirectoryIterator(TMP_DIR) as $fileInfo) {
			if ($fileInfo->isFile()) {
				unlink($fileInfo->getPathname());
			}
		}
	}

	protected function tearDown(): void {
		// Clean tmp dir.
		foreach (new DirectoryIterator(TMP_DIR) as $fileInfo) {
			if ($fileInfo->isFile()) {
				unlink($fileInfo->getPathname());
			}
		}
	}
	
	public function testCrud() {
		$s = new FilesystemJsonStorage(TMP_DIR, SECRET);

		$t1data = ['example' => 'data'];
		$t1path = $s->getPath('t1');

		$this->assertTrue($s->put('t1', $t1data), "Saving t1 data failed");

		$this->assertFileExists($t1path, "t1 was not stored to $t1path");
		
		$this->assertEquals($t1data, $s->get('t1'), "The result of getting t1 did not match the saved data.");

		$s->delete('t1');

		$this->assertFileDoesNotExist($t1path, "t1 was not successfully deleted.");

		$this->assertNull($s->get('t1'), "Getting a nonexistent key did not return null");
	}

	public function testCleanUp() {
		$s = new FilesystemJsonStorage(TMP_DIR, SECRET);
		$s->put('t1', ['exp' => time() + 10]);
		$s->put('t2', ['exp' => time() - 10]);
		$s->deleteExpiredTokens();
		$this->assertIsArray($s->get('t1'), 't1 was not expired and should not have been deleted.');
		$this->assertNull($s->get('t2'), 't2 was not cleaned up after expiring.');
	}

	public function testMigrateFromV0_1_0ToV0_2_0() {
		$s = new FilesystemJsonStorage(TMP_DIR, SECRET);

		$oldUnexchangedCode = [
			'me' => 'https://example.com',
			'valid_until' => time() + 60 * 5
		];
		$newUnexchangedCode = array_merge($oldUnexchangedCode, [
			'code_exp' => $oldUnexchangedCode['valid_until']
		]);

		$oldExchangedCode = [
			'me' => 'https://example.com',
			'exchanged_at' => time() + 60 * 1,
			'valid_until' => time() + 60 * 5
		];
		$newExchangedCode = array_merge($oldExchangedCode, [
			'iat' => $oldExchangedCode['exchanged_at'],
			'exp' => $oldExchangedCode['valid_until']
		]);

		$s->put('t1', $oldUnexchangedCode);
		$s->put('t2', $oldExchangedCode);

		$migrationFunctions = require_once __DIR__ . '/../bin/migrate.php';

		$migrationFunctions['json_v0.1.0_v0.2.0'](TMP_DIR);

		$this->assertEquals($s->get('t1'), $newUnexchangedCode);
		$this->assertEquals($s->get('t2'), $newExchangedCode);
	}
}
