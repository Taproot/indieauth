<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * No-Op Middleware
 * 
 * A PSR-15 Middleware which does nothing, simply passing `$request` onto `$handler` and returning
 * the response.
 */
class NoOpMiddleware implements MiddlewareInterface {
	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
		return $handler->handle($request);
	}
}
