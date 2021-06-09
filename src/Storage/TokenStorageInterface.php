<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Storage;

// TODO: document.

interface TokenStorageInterface {
	public function createAuthCode(array $data): ?Token;

	public function exchangeAuthCodeForAccessToken(string $code): ?Token;

	public function revokeAccessToken(string $token);

	public function getAccessToken(string $token): ?Token;
}
