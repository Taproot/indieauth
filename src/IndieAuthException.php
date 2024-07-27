<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

class IndieAuthException extends Exception {
	const INTERNAL_ERROR = 0;
	const INTERNAL_ERROR_REDIRECT = 1;
	const AUTHENTICATION_CALLBACK_MISSING_ME_PARAM = 2;
	const AUTHORIZATION_APPROVAL_REQUEST_MISSING_HASH = 3;
	const AUTHORIZATION_APPROVAL_REQUEST_INVALID_HASH = 4;
	const HTTP_EXCEPTION_FETCHING_CLIENT_ID = 5;
	const INTERNAL_EXCEPTION_FETCHING_CLIENT_ID = 6;
	const INVALID_REDIRECT_URI = 7;
	const INVALID_CLIENT_ID = 8;
	const INVALID_STATE = 9;
	const INVALID_CODE_CHALLENGE = 10;
	const INVALID_SCOPE = 11;
	const INVALID_GRANT = 12;
	const INVALID_REQUEST = 13;
	const INVALID_REQUEST_REDIRECT = 14;
	const AUTHENTICATION_CALLBACK_INVALID_RETURN_VALUE = 15;
	const OAUTH_METADATA_MISMATCH_CLIENT_ID = 16;
	const OAUTH_METADATA_MISMATCH_CLIENT_URI = 17;

	const EXC_INFO = [
		self::INTERNAL_ERROR => ['statusCode' => 500, 'name' => 'Internal Server Error', 'explanation' => 'An internal server error occurred.'],
		self::INTERNAL_ERROR_REDIRECT => ['statusCode' => 302, 'name' => 'Internal Server Error', 'error' => 'internal_error'],
		self::AUTHENTICATION_CALLBACK_INVALID_RETURN_VALUE => ['statusCode' => 302, 'name' => 'Internal Server Error', 'error' => 'internal_error'],
		self::AUTHENTICATION_CALLBACK_MISSING_ME_PARAM => ['statusCode' => 302, 'name' => 'Internal Server Error', 'error' => 'internal_error'],
		self::AUTHORIZATION_APPROVAL_REQUEST_MISSING_HASH => ['statusCode' => 302, 'name' => 'Request Missing Hash', 'error' => 'internal_error'],
		self::AUTHORIZATION_APPROVAL_REQUEST_INVALID_HASH => ['statusCode' => 302, 'name' => 'Request Hash Invalid', 'error' => 'internal_error'],
		// TODO: should this one be a 500 because it’s an internal server error, or a 400 because the client_id was likely invalid? Is anyone ever going to notice, or care?
		self::HTTP_EXCEPTION_FETCHING_CLIENT_ID => ['statusCode' => 500, 'name' => 'Error Fetching Client App URL',  'explanation' => 'Fetching the client app (client_id) failed.'],
		self::INTERNAL_EXCEPTION_FETCHING_CLIENT_ID => ['statusCode' => 500, 'name' => 'Internal Error fetching client app URI', 'explanation' => 'Fetching the client app (client_id) failed due to an internal error.'],
		self::INVALID_REDIRECT_URI => ['statusCode' => 400, 'name' => 'Invalid Client App Redirect URI', 'explanation' => 'The client app redirect URI (redirect_uri) either was not a valid URI, did not sufficiently match client_id, or did not exactly match any redirect URIs parsed from fetching the client_id.'],
		self::INVALID_CLIENT_ID => ['statusCode' => 400, 'name' => 'Invalid Client Identifier URI', 'explanation' => 'The Client Identifier was not valid.'],
		self::INVALID_STATE => ['statusCode' => 302, 'name' => 'Invalid state Parameter', 'error' => 'invalid_request'],
		self::INVALID_CODE_CHALLENGE => ['statusCode' => 302, 'name' => 'Invalid code_challenge Parameter', 'error' => 'invalid_request'],
		self::INVALID_SCOPE => ['statusCode' => 302, 'name' => 'Invalid scope Parameter', 'error' => 'invalid_request'],
		self::INVALID_GRANT => ['statusCode' => 400, 'name' => 'The provided credentials were not valid.', 'error' => 'invalid_grant'],
		self::INVALID_REQUEST => ['statusCode' => 400, 'name' => 'Invalid Request', 'error' => 'invalid_request'],
		self::INVALID_REQUEST_REDIRECT => ['statusCode' => 302, 'name' => 'Invalid Request', 'error' => 'invalid_request'],
		self::OAUTH_METADATA_MISMATCH_CLIENT_ID => ['statusCode' => 400, 'name' => 'Invalid Client Identifier URI', 'explanation' => 'client_id in OAuth Client Metadata document did not match.'],
		self::OAUTH_METADATA_MISMATCH_CLIENT_URI => ['statusCode' => 400, 'name' => 'Invalid Client URI', 'explanation' => 'client_url in OAuth Client Metadata document is not a prefix for client_id.'],
	];

	/** @var ServerRequestInterface $request */
	protected $request;

	public static function create(int $code, ServerRequestInterface $request, ?Throwable $previous=null): self {
		// Only accept known codes. Default to 0 (generic internal error) on an unrecognised code.
		if (!in_array($code, array_keys(self::EXC_INFO))) {
			$code = 0;
		}
		$message = self::EXC_INFO[$code]['name'];
		$e = new self($message, $code, $previous);
		$e->request = $request;
		return $e;
	}

	public function getStatusCode() {
		return $this->getInfo()['statusCode'] ?? 500;
	}

	public function getExplanation() {
		return $this->getInfo()['explanation'] ?? 'An unknown error occured.';
	}

	public function getInfo() {
		return self::EXC_INFO[$this->code] ?? self::EXC_INFO[self::INTERNAL_ERROR];
	}

	/**
	 * Trust Query Params
	 * 
	 * Only useful on authorization form submission requests. If this returns false,
	 * the client_id and/or request_uri have likely been tampered with, and the error
	 * page SHOULD NOT offer the user a link to them.
	 */
	public function trustQueryParams() {
		return !in_array($this->code, [self::AUTHORIZATION_APPROVAL_REQUEST_INVALID_HASH, self::AUTHORIZATION_APPROVAL_REQUEST_MISSING_HASH]);
	}

	public function getRequest() {
		return $this->request;
	}
}
