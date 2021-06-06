<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Storage;

// TODO: document.

interface TokenStorageInterface {
	public function cleanUp($ttl=null): int;

	public function get(string $key): ?array;

	public function put(string $key, array $data): bool;

	public function delete(string $key): bool;
}
