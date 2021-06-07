<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Callback;

use BarnabyWalters\Mf2 as M;
use Psr\Http\Message\ServerRequestInterface;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Taproot\IndieAuth\renderTemplate;

class DefaultAuthorizationForm implements AuthorizationFormInterface, LoggerAwareInterface {
	public string $csrfKey;

	public string $formTemplatePath;

	public LoggerInterface $logger;

	public function __construct(?string $formTemplatePath=null, ?string $csrfKey=null, ?LoggerInterface $logger=null) {
		$this->formTemplatePath = $formTemplatePath ?? __DIR__ . '/../templates/default_authorization_page.html.php';
		$this->csrfKey = $csrfKey ?? \Taproot\IndieAuth\Server::DEFAULT_CSRF_KEY;
		$this->logger = $logger ?? new NullLogger;
	}

	public function showForm(ServerRequestInterface $request, array $authenticationResult, string $formAction, ?array $clientHApp): ResponseInterface {
		// Show an authorization page. List all requested scopes, as this default
		// function has now way of knowing which scopes are supported by the consumer.
		$scopes = [];
		foreach(explode(' ', $request->getQueryParams()['scope'] ?? '') as $s) {
			$scopes[$s] = null; // Ideally there would be a description of the scope here, we don’t have one though.
		}

		$hApp = [
			'name' => M\getProp($clientHApp, 'name'),
			'url' => M\getProp($clientHApp, 'url'),
			'photo' => M\getProp($clientHApp, 'photo')
		];

		return new Response(200, ['content-type' => 'text/html'], renderTemplate($this->formTemplatePath, [
			'scopes' => $scopes,
			'user' => $authenticationResult,
			'formAction' => $formAction,
			'request' => $request,
			'clientHApp' => $hApp,
			'clientId' => $request->getQueryParams()['client_id'],
			'clientRedirectUri' => $request->getQueryParams()['redirect_uri'],
			'csrfFormElement' => '<input type="hidden" name="' . htmlentities($this->csrfKey) . '" value="' . htmlentities($request->getAttribute($this->csrfKey)) . '" />'
		]));
	}

	public function transformAuthorizationCode(ServerRequestInterface $request, array $code): array {
		// Add any granted scopes from the form to the code.
		$grantedScopes = $request->getParsedBody()['taproot_indieauth_server_scope[]'] ?? [];

		// This default implementation naievely accepts any scopes it receives from the form.
		// You may wish to perform some sort of validation.
		$code['scope'] = join(' ', $grantedScopes);

		// You may wish to additionally make any other necessary changes to the the code based on
		// the form submission, e.g. if the user set a custom token lifetime, or wanted extra data
		// stored on the token to affect how it behaves.

		return $code;
	}

	public function setLogger(LoggerInterface $logger) {
		$this->logger = $logger;
	}
}
