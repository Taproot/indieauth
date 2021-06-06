<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use DirectoryIterator;
use PHPUnit\Framework\TestCase;
use Taproot\IndieAuth\Storage\FilesystemJsonStorage;

const TMP_DIR = __DIR__ . '/tmp';

class FilesystemJsonStorageTest extends TestCase {
	protected function setUp(): void {
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
		$s = new FilesystemJsonStorage(TMP_DIR, 0, false);

		$t1data = ['example' => 'data'];
		$t1path = TMP_DIR . '/t1.json';

		$this->assertTrue($s->put('t1', $t1data), "Saving t1 data failed");

		$this->assertFileExists($t1path, "t1 was not stored to $t1path");
		
		$this->assertEquals($t1data, $s->get('t1'), "The result of getting t1 did not match the saved data.");

		$s->delete('t1');

		$this->assertFileDoesNotExist($t1path, "t1 was not successfully deleted.");

		$this->assertNull($s->get('t1'), "Getting a nonexistent key did not return null");
	}

	public function testCleanUp() {
		$s = new FilesystemJsonStorage(TMP_DIR, 1, false);
		$s->put('t1', ['example' => 'data']);
		sleep(2);
		$s->cleanUp();
		$this->assertNull($s->get('t1'), 't1 was not cleaned up after expiring.');
	}
}
