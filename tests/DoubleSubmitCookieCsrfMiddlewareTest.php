<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Test;

use Dflydev\FigCookies\FigResponseCookies;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Taproot\IndieAuth\Middleware\ClosureRequestHandler;
use Taproot\IndieAuth\Middleware\DoubleSubmitCookieCsrfMiddleware;
use Taproot\IndieAuth\Middleware\ResponseRequestHandler;

class DoubleSubmitCookieCsrfMiddlewareTest extends TestCase {
	public function testPassesThroughNonWriteRequestsAddingAttribute() {
		$mw = new DoubleSubmitCookieCsrfMiddleware();

		foreach (['GET', 'HEAD', 'OPTIONS'] as $method) {
			$request = new ServerRequest($method, 'https://example.com');
			$preparedResponse = new Response();
			$token = null;
			$returnedResponse = $mw->process($request, new ClosureRequestHandler(function (ServerRequestInterface $request) use ($preparedResponse, $mw, &$token) {
				$this->assertNotEmpty($request->getAttribute($mw->attribute), "The $mw->attribute on \$request was empty.");
				$token = $request->getAttribute($mw->attribute);
				return $preparedResponse;
			}));
			$this->assertEquals($preparedResponse->getStatusCode(), $returnedResponse->getStatusCode(), "Prepared response was not passed through for $method request.");
			$responseCsrfCookieValue = FigResponseCookies::get($returnedResponse, $mw->attribute)->getValue();
			$this->assertNotNull($responseCsrfCookieValue, "The $mw->attribute cookie on the response should not be null.");
			$this->assertEquals($token, $responseCsrfCookieValue, "The $mw->attribute cookie attached to the response did not have the same value as the one in the request attribute.");
		}
	}

	public function testReturnsDefaultErrorResponseOnWriteRequestsWithoutToken() {
		$mw = new DoubleSubmitCookieCsrfMiddleware();

		foreach (['PUT', 'POST', 'DELETE', 'PATCH'] as $method) {
			$request = new ServerRequest($method, 'https://example.com');
			$returnedResponse = $mw->process($request, new ResponseRequestHandler(new Response(200)));
			$this->assertEquals(400, $returnedResponse->getStatusCode(), "Default error response was not returned for CSRF-less $method request.");
		}
	}

	public function testReturnsDefaultErrorResponseOnWriteRequestWithOnlyCookieToken() {
		$mw = new DoubleSubmitCookieCsrfMiddleware();

		foreach (['PUT', 'POST', 'DELETE', 'PATCH'] as $method) {
			$request = (new ServerRequest($method, 'https://example.com'))->withCookieParams([
				$mw->attribute => 'Invalid unmatched CSRF token!'
			]);
			$returnedResponse = $mw->process($request, new ResponseRequestHandler(new Response(200)));
			$this->assertEquals(400, $returnedResponse->getStatusCode(), "Default error response was not returned for $method request with CSRF token only in the $mw->attribute cookie.");
		}
	}

	public function testReturnsDefaultErrorResponseOnWriteRequestWithOnlyBodyToken() {
		$mw = new DoubleSubmitCookieCsrfMiddleware();

		foreach (['PUT', 'POST', 'DELETE', 'PATCH'] as $method) {
			$request = (new ServerRequest($method, 'https://example.com'))->withParsedBody([
				$mw->attribute => 'Invalid unmatched CSRF token!'
			]);
			$returnedResponse = $mw->process($request, new ResponseRequestHandler(new Response(200)));
			$this->assertEquals(400, $returnedResponse->getStatusCode(), "Default error response was not returned for $method request with CSRF token only in the $mw->attribute body parameter.");
		}
	}

	public function testReturnsDefaultErrorResponseOnWriteRequestWithMismatchedTokens() {
		$mw = new DoubleSubmitCookieCsrfMiddleware();

		foreach (['PUT', 'POST', 'DELETE', 'PATCH'] as $method) {
			$request = (new ServerRequest($method, 'https://example.com'))->withParsedBody([
				$mw->attribute => 'Invalid unmatched CSRF token!'
			])->withCookieParams([
				$mw->attribute => 'INVALID UNMATCHED CSRF TOKEN!!!!!'
			]);
			$returnedResponse = $mw->process($request, new ResponseRequestHandler(new Response(200)));
			$this->assertEquals(400, $returnedResponse->getStatusCode(), "Default error response was not returned for $method request with CSRF token only in the $mw->attribute body parameter.");
		}
	}

	public function testPassesResponseThroughOnWriteRequestWithValidToken() {
		$mw = new DoubleSubmitCookieCsrfMiddleware();

		foreach (['PUT', 'POST', 'DELETE', 'PATCH'] as $method) {
			$request = (new ServerRequest($method, 'https://example.com'))->withParsedBody([
				$mw->attribute => 'Valid matching CSRF token :D'
			])->withCookieParams([
				$mw->attribute => 'Valid matching CSRF token :D'
			]);
			
			$returnedResponse = $mw->process($request, new ResponseRequestHandler(new Response(200)));
			$this->assertEquals(200, $returnedResponse->getStatusCode(), "The response was not passed through on a $method request with valid matching CSRF tokens.");
		}
	}

	public function acceptsCustomStringErrorResponse() {
		$errorResponseBody = 'ERROR!';
		$mw = new DoubleSubmitCookieCsrfMiddleware(null, null, $errorResponseBody);
		$response = $mw->process(new ServerRequest('POST', 'https://example.com'), new ResponseRequestHandler(new Response(200)));
		$this->assertEquals(400, $response->getStatusCode(), "An error response should have been returned.");
		$this->assertEquals($errorResponseBody, $response->getBody()->getContents(), "The error response should have the predefined body contents.");
	}

	public function acceptsCustomErrorResponse() {
		$errorResponseBody = 'ERROR!';
		$mw = new DoubleSubmitCookieCsrfMiddleware(null, null, new Response(400, [], $errorResponseBody));
		$response = $mw->process(new ServerRequest('POST', 'https://example.com'), new ResponseRequestHandler(new Response(200)));
		$this->assertEquals(400, $response->getStatusCode(), "An error response should have been returned.");
		$this->assertEquals($errorResponseBody, $response->getBody()->getContents(), "The error response should have the predefined body contents.");
	}

	public function acceptsCustomCallbackErrorResponse() {
		$errorResponseBody = 'ERROR!';
		$mw = new DoubleSubmitCookieCsrfMiddleware(null, null, function (ServerRequestInterface $request) use ($errorResponseBody) {
			$this->assertInstanceOf('\Psr\Http\Message\ServerRequestInterface', $request, "The request should be available within the error response callback.");
			return new Response(400, [], $errorResponseBody);
		});
		$response = $mw->process(new ServerRequest('POST', 'https://example.com'), new ResponseRequestHandler(new Response(200)));
		$this->assertEquals(400, $response->getStatusCode(), "An error response should have been returned.");
		$this->assertEquals($errorResponseBody, $response->getBody()->getContents(), "The error response should have the predefined body contents.");
	}
}
