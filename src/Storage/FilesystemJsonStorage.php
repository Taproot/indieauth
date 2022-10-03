<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Storage;

use DirectoryIterator;
use Exception;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Taproot\IndieAuth\IndieAuthException;

use function Taproot\IndieAuth\generateRandomString;

/**
 * Filesystem JSON Token Storage
 * 
 * An implementation of `TokenStorageInterface` which stores authorization codes
 * and access tokens in the filesystem as JSON files, and supports custom access
 * token lifetimes.
 * 
 * This is intended as a default, example implementation with minimal requirements.
 * In practise, most people should probably be using an SQLite3 version of this
 * which I haven’t written yet. I haven’t extensively documented this class, as it
 * will likely be superceded by the SQLite version.
 * 
 * Each auth code/access token pair is stored in one file. The file name is the 
 * access token, which is also the result of `$storage->hash($authCode)`.
 * 
 * The file format is as follows:
 * 
 * ```json
 * {
 *   "code_exp": int (epoch seconds), expiry time of the auth code
 *   "_access_token_ttl": int, custom token-specific access token TTL
 *   "iat": int (epoch seconds), time of code->token exchange
 *   "exp": int (epoch seconds), access token expiry time,
 *   "scope": string, comma separated scope values
 *   "me": string, me URI
 *   "profile": {
 *     "name": string
 *     "url": string
 *     "photo": string
 *   }
 * }
 * ```
 */
class FilesystemJsonStorage implements TokenStorageInterface, LoggerAwareInterface {
	const DEFAULT_AUTH_CODE_TTL = 60 * 5; // Five minutes.
	const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60 * 24 * 7; // One week.
	
	const TOKEN_LENGTH = 64;

	/** @var string $path */
	protected $path;
	
	/** @var int $authCodeTtl */
	protected $authCodeTtl;

	/** @var int $accessTokenTtl */
	protected $accessTokenTtl;

	/** @var string $secret */
	protected $secret;

	/** @var LoggerInterface $logger */
	protected $logger;

	public function __construct(string $path, string $secret, ?int $authCodeTtl=null, ?int $accessTokenTtl=null, $cleanUpNow=false, ?LoggerInterface $logger=null) {
		$this->logger = $logger ?? new NullLogger();

		if (strlen($secret) < 64) {
			throw new Exception("\$secret must be a string with a minimum length of 64 characters. Make one with Taproot\IndieAuth\generateRandomString(64)");
		}
		$this->secret = $secret;

		$this->path = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

		$this->authCodeTtl = $authCodeTtl ?? self::DEFAULT_AUTH_CODE_TTL;
		$this->accessTokenTtl = $accessTokenTtl ?? self::DEFAULT_ACCESS_TOKEN_TTL;

		@mkdir($this->path, 0777, true);

		if ($cleanUpNow) {
			$this->deleteExpiredTokens();
		}
	}

	// LoggerAwareInterface method.

	public function setLogger(LoggerInterface $logger): void {
		$this->logger = $logger;
	}

	// TokenStorageInterface Methods.

	public function createAuthCode(array $data): ?string {
		$this->logger->info("Creating authorization code.", $data);
		$authCode = generateRandomString(self::TOKEN_LENGTH);
		$accessToken = $this->hash($authCode);

		// Store issued at and expiry times for the auth code. To keep a complete record of the history of the 
		// code/token, the auth code and access token have their own iat and exp fields.
		$data['code_iat'] = time();
		if (!array_key_exists('code_exp', $data)) {
			$data['code_exp'] = time() + $this->authCodeTtl;
		}
		
		if (!$this->put($accessToken, $data)) {
			return null;
		}
		return $authCode;
	}

	public function exchangeAuthCodeForAccessToken(string $code, callable $validateAuthCode): ?array {
		// Hash the auth code to get the theoretical matching access token filename.
		$accessToken = $this->hash($code);

		// Prevent the token file from being read, modified or deleted while we’re working with it.
		// r+ to allow reading and writing, but to make sure we don’t create the file if it doesn’t 
		// already exist.
		return $this->withLock($this->getPath($accessToken), 'r+', function ($fp) use ($accessToken, $validateAuthCode) {
			// Read the file contents.
			$fileContents = '';
			while ($d = fread($fp, 1024)) { $fileContents .= $d; }

			$data = json_decode($fileContents, true);
			
			if (!is_array($data)) { 
				$this->logger->error('Authorization Code data could not be parsed as a JSON object.');
				return null; 
			}

			// Make sure the auth code hasn’t already been redeemed.
			if ($data['iat'] ?? false) {
				$this->logger->error("This authorization code has already been exchanged.");
				return null;
			}

			// Make sure the auth code isn’t expired.
			if (($data['code_exp'] ?? 0) < time()) {
				$this->logger->error("This authorization code has expired.");
				return null;
			}

			// The auth code is valid as far as we know, pass it to the validation callback passed from the
			// Server.
			try {
				$validateAuthCode($data);
			} catch (IndieAuthException $e) {
				// If there was an issue with the auth code, delete it before bubbling the exception
				// up to the Server for handling. We currently have a lock on the file path, so pass
				// false to $observeLock to prevent a deadlock.
				$this->logger->info("Deleting authorization code, as it failed the Server-level validation.");
				$this->delete($accessToken, false);
				throw $e;
			}

			// If the access token is valid, mark it as redeemed and set a new expiry time.
			$data['iat'] = time();

			$expiresIn = null;
			if (is_int($data['_access_token_ttl'] ?? null)) {
				// This access token has a custom TTL, use that.
				$data['exp'] = time() + $data['_access_token_ttl'];
				$expiresIn = (int) $data['_access_token_ttl'];
			} elseif ($this->accessTokenTtl == 0) {
				// The token should be valid until explicitly revoked.
				$data['exp'] = null;
			} else {
				// Use the default TTL.
				$data['exp'] = time() + $this->accessTokenTtl;
				$expiresIn = $this->accessTokenTtl;
			}

			// Write the new file contents, truncating afterwards in case the new data is shorter than the old data.
			$jsonData = json_encode($data);
			if (rewind($fp) === false) { return null; }
			if (fwrite($fp, $jsonData) === false) { return null; }
			if (ftruncate($fp, strlen($jsonData)) === false) { return null; }
			
			// Return the OAuth2-compatible access token data to the Server for passing onto
			// the client app. Passed via array_filter to remove keys with null values.
			return array_filter([
				'access_token' => $accessToken,
				'scope' => ($data['scope'] ?? null),
				'me' => $data['me'],
				'profile' => ($data['profile'] ?? null),
				'expires_in' => $expiresIn
			]);
		});
	}

	public function getAccessToken(string $token): ?array {
		$data = $this->get($token);

		if (!is_array($data)) {
			$this->logger->error("The access token could not be parsed as a JSON object.");
			return null;
		}

		// Check that this is a redeemed access token.
		if (($data['iat'] ?? false) === false) {
			$this->logger->error("This authorization code has not yet been exchanged for an access token.");
			return null;
		}

		// Check that the access token is still valid. exp=null means it should live until
		// explicitly revoked.
		if (is_int($data['exp']) && $data['exp'] < time()) {
			$this->logger->error("This access token has expired.");
			return null;
		}

		// The token is valid!
		return $data;
	}

	public function revokeAccessToken(string $token): bool {
		$this->logger->info("Deleting access token {$token}");
		return $this->delete($token);
	}

	// Implementation-Specifc Methods.

	public function deleteExpiredTokens(): int {
		$deleted = 0;

		foreach (new DirectoryIterator($this->path) as $fileInfo) {
			if ($fileInfo->isFile() && $fileInfo->getExtension() == 'json') {
				// Only delete files which we can lock.
				$successfullyDeleted = $this->withLock($fileInfo->getPathname(), 'r', function ($fp) use ($fileInfo) {
					// Read the file, check expiry date! Only unlink if file is expired.
					$fileContents = '';
					while ($d = fread($fp, 1024)) { $fileContents .= $d; }

					$data = json_decode($fileContents, true);

					if (!is_array($data)) { return; }
					
					// If valid_until is a valid time, and is in the past, delete the token.
					if (is_int($data['exp'] ?? null) && $data['exp'] < time()) {
						return unlink($fileInfo->getPathname());
					}
				});

				if ($successfullyDeleted) { $deleted++; }
			}
		}

		return $deleted;
	}

	public function get(string $key): ?array {
		$path = $this->getPath($key);

		if (!file_exists($path)) {
			return null;
		}

		return $this->withLock($path, 'r', function ($fp) {
			$fileContents = '';
			while ($data = fread($fp, 1024)) {
				$fileContents .= $data;
			}
			$result = json_decode($fileContents, true);

			if (is_array($result)) {
				return $result;
			}

			return null;
		});
	}

	public function put(string $key, array $data): bool {
		// Ensure that the containing folder exists.
		@mkdir($this->path, 0777, true);
		
		return $this->withLock($this->getPath($key), 'w', function ($fp) use ($data) {
			return fwrite($fp, json_encode($data)) !== false;
		});
	}

	public function delete(string $key, $observeLock=true): bool {
		$path = $this->getPath($key);
		if (file_exists($path)) {
			if ($observeLock) {
				return $this->withLock($path, 'r', function ($fp) use ($path) {
					return unlink($path);
				});
			} else {
				return unlink($path);
			}
		}
		return false;
	}

	public function getPath(string $key): string {
		// TODO: ensure that the calculated path is a child of $this->path.
		return $this->path . "$key.json";
	}

	protected function withLock(string $path, string $mode, callable $callback) {
		$fp = @fopen($path, $mode);

		if ($fp === false) {
			return null;
		}

		// Wait for a lock.
		if (flock($fp, LOCK_EX)) {
			$return = null;
			try {
				// Perform whatever action on the file pointer.
				$return = $callback($fp);
			} finally {
				// Regardless of what happens, release the lock.
				flock($fp, LOCK_UN);
				fclose($fp);
			}
			return $return;
		}
		// It wasn’t possible to get a lock.
		return null;
	}

	protected function hash(string $token): string {
		return hash_hmac('sha256', $token, $this->secret);
	}
}
