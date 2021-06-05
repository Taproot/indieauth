<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class NoOpMiddleware implements MiddlewareInterface {
	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
		return $handler->handle($request);
	}
}