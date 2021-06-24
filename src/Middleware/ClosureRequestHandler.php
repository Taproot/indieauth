<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ClosureRequestHandler implements RequestHandlerInterface {
	protected $callable;

	/** @var array $args */
	protected $args;

	public function __construct(callable $callable) {
		$this->callable = $callable;
		$this->args = array_slice(func_get_args(), 1);
	}

	public function handle(ServerRequestInterface $request): ResponseInterface {
		return call_user_func_array($this->callable, array_merge([$request], $this->args));
	}
}
