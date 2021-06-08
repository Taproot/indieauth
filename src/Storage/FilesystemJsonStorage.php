<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Storage;

use DirectoryIterator;

class FilesystemJsonStorage implements TokenStorageInterface {
	protected $path;
	protected $ttl;

	public function __construct(string $path, $ttl=0, $cleanUpNow=false) {
		$this->path = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
		$this->ttl = $ttl;

		@mkdir($this->path, 0777, true);

		if ($cleanUpNow) {
			$this->cleanUp();
		}
	}

	public function cleanUp($ttl=null): int {
		$ttl = $ttl ?? $this->ttl;

		$deleted = 0;

		// A TTL of 0 means the token should live until deleted. A negative TTLs means “delete everything”.
		if ($ttl !== 0) {
			foreach (new DirectoryIterator($this->path) as $fileInfo) {
				if ($fileInfo->isFile() && $fileInfo->getExtension() == 'json' && time() - max($fileInfo->getMTime(), $fileInfo->getCTime()) > $ttl) {
					unlink($fileInfo->getPathname());
					$deleted++;
				}
			}
		}

		return $deleted;
	}

	public function get(string $key): ?array {
		$path = $this->getPath($key);
		if (file_exists($path)) {
			$result = json_decode(file_get_contents($path), true);

			if (is_array($result)) {
				return $result;
			}
		}

		return null;
	}

	public function put(string $key, array $data): bool {
		// Ensure that the containing folder exists.
		@mkdir($this->path, 0777, true);
		
		return file_put_contents($this->getPath($key), json_encode($data)) !== false;
	}

	public function delete(string $key): bool {
		if (file_exists($this->getPath($key))) {
			return unlink($this->getPath($key));
		}
		return false;
	}

	public function getPath(string $key): string {
		return $this->path . "$key.json";
	}
}
