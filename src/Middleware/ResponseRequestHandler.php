<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ResponseRequestHandler implements RequestHandlerInterface {
	/** @var ResponseInterface $response */
	public $response;

	public function __construct(ResponseInterface $response) {
		$this->response = $response;
	}

	public function handle(ServerRequestInterface $request): ResponseInterface {
		return $this->response;
	}
}
