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
use function Taproot\IndieAuth\generateRandomString;

class DoubleSubmitCookieCsrfMiddleware implements MiddlewareInterface, LoggerAwareInterface {
	const READ_METHODS = ['HEAD', 'GET', 'OPTIONS'];
	const TTL = 60 * 20;
	const ATTRIBUTE = 'csrf';
	const DEFAULT_ERROR_RESPONSE_STRING = 'Invalid or missing CSRF token!';
	const CSRF_TOKEN_LENGTH = 128;
	
	public string $attribute;

	public int $ttl;

	public callable $errorResponse;

	public int $tokenLength;

	public LoggerInterface $logger;

	public function __construct(string $attribute=self::ATTRIBUTE, int $ttl=self::TTL, $errorResponse=self::DEFAULT_ERROR_RESPONSE_STRING, $tokenLength=self::CSRF_TOKEN_LENGTH, $logger=null) {
		$this->attribute = $attribute;
		$this->ttl = $ttl;
		$this->tokenLength = $tokenLength;

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
		if (!in_array(strtoupper($request->getMethod()), self::READ_METHODS)) {
			// This request is a write method and requires CSRF protection.
			if (!$this->isValid($request)) {
				return call_user_func($this->errorResponse, $request);
			}
		}

		// Otherwise, generate a new CSRF token, add it to the request attributes, and as a cookie on the response.
		$csrfToken = generateRandomString($this->tokenLength);
		$request = $request->withAttribute($this->attribute, $csrfToken);

		$response = $handler->handle($request);

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
		if (in_array($this->attribute, $request->getParsedBody())) {
			if (in_array($this->attribute, $request->getCookieParams())) {
				return hash_equals($request->getParsedBody()[$this->attribute], $request->getCookieParams()[$this->attribute]);
			}
		}
		return false;
	}
}
