<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Middleware;

use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Dflydev\FigCookies;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Taproot\IndieAuth\generateRandomPrintableAsciiString;

/**
 * Double-Submit Cookie CSRF Middleware
 * 
 * A PSR-15-compatible Middleware for stateless Double-Submit-Cookie-based CSRF protection.
 * 
 * The `$attribute` property and first constructor argument sets the key by which the CSRF token
 * is referred to in all parameter sets (request attributes, request body parameters, cookies).
 * 
 * Generates a random token of length `$tokenLength`  (default 128), and stores it as an attribute
 * on the `ServerRequestInterface`. It’s also added to the response as a cookie.
 * 
 * On requests which may modify state (methods other than HEAD, GET or OPTIONS), the request body
 * and request cookies are checked for matching CSRF tokens. If they match, the request is passed on
 * to the handler. If they do not match, further processing is halted and an error response generated
 * from the `$errorResponse` callback is returned. Refer to the constructor argument for information
 * about customising the error response.
 * 
 * @link https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 * @link https://github.com/zakirullin/csrf-middleware/blob/master/src/CSRF.php
 */
class DoubleSubmitCookieCsrfMiddleware implements MiddlewareInterface, LoggerAwareInterface {
	const READ_METHODS = ['HEAD', 'GET', 'OPTIONS'];
	const TTL = 60 * 20;
	const ATTRIBUTE = 'csrf';
	const DEFAULT_ERROR_RESPONSE_STRING = 'Invalid or missing CSRF token!';
	const CSRF_TOKEN_LENGTH = 128;
	
	public string $attribute;

	public int $ttl;

	public $errorResponse;

	public int $tokenLength;

	public LoggerInterface $logger;

	/**
	 * Constructor
	 * 
	 * The `$errorResponse` parameter can be used to customse the error response returned when a
	 * write request has invalid CSRF parameters. It can take the following forms:
	 * 
	 * * A `string`, which will be returned as-is with a 400 Status Code and `Content-type: text/plain` header
	 * * An instance of `ResponseInterface`, which will be returned as-is
	 * * A callable with the signature `function (ServerRequestInterface $request): ResponseInterface`,
	 *   the return value of which will be returned as-is.
	 */
	public function __construct(?string $attribute=self::ATTRIBUTE, ?int $ttl=self::TTL, $errorResponse=self::DEFAULT_ERROR_RESPONSE_STRING, $tokenLength=self::CSRF_TOKEN_LENGTH, $logger=null) {
		$this->attribute = $attribute ?? self::ATTRIBUTE;
		$this->ttl = $ttl ?? self::TTL;
		$this->tokenLength = $tokenLength ?? self::CSRF_TOKEN_LENGTH;

		if (!is_callable($errorResponse)) {
			if (!$errorResponse instanceof ResponseInterface) {
				if (!is_string($errorResponse)) {
					$errorResponse = self::DEFAULT_ERROR_RESPONSE_STRING;
				}
				$errorResponse = new Response(400, ['content-type' => 'text/plain'], $errorResponse);
			}
			$errorResponse = function (ServerRequestInterface $request) use ($errorResponse) { return $errorResponse; };
		}
		$this->errorResponse = $errorResponse;

		if (!$logger instanceof LoggerInterface) {
			$logger = new NullLogger();
		}
		$this->logger = $logger;
	}

	public function setLogger(LoggerInterface $logger) {
		$this->logger = $logger;
	}

	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
		// Generate a new CSRF token, add it to the request attributes, and as a cookie on the response.
		$csrfToken = generateRandomPrintableAsciiString($this->tokenLength);
		$request = $request->withAttribute($this->attribute, $csrfToken);

		if (!in_array(strtoupper($request->getMethod()), self::READ_METHODS) && !$this->isValid($request)) {
			// This request is a write method with invalid CSRF parameters.
			$response = call_user_func($this->errorResponse, $request);
		} else {
			$response = $handler->handle($request);
		}

		// Add the new CSRF cookie, restricting its scope to match the current request.
		$response = FigCookies\FigResponseCookies::set($response, FigCookies\SetCookie::create($this->attribute)
				->withValue($csrfToken)
				->withMaxAge($this->ttl)
				->withSecure($request->getUri()->getScheme() == 'https')
				->withDomain($request->getUri()->getHost())
				->withPath($request->getUri()->getPath()));

		return $response;
	}

	protected function isValid(ServerRequestInterface $request) {
		if (array_key_exists($this->attribute, $request->getParsedBody() ?? [])) {
			if (array_key_exists($this->attribute, $request->getCookieParams() ?? [])) {
				// TODO: make sure CSRF token isn’t the empty string, possibly also check that it’s the same length
				// as defined in $this->tokenLength.
				return hash_equals($request->getParsedBody()[$this->attribute], $request->getCookieParams()[$this->attribute]);
			}
		}
		return false;
	}
}
