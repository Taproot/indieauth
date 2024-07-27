<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Callback;

use BadMethodCallException;
use BarnabyWalters\Mf2 as M;
use Exception;
use Psr\Http\Message\ServerRequestInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Taproot\IndieAuth\renderTemplate;

/**
 * Default Authorization Form
 * 
 * This implementation of {@see AuthorizationFormInterface} is used by {@see \Taproot\IndieAuth\Server} if the user doesn’t 
 * provide one of their own. It presents the user with a simple consent screen, showing any
 * available details about the client app, and allowing the user to grant any requested scopes.
 * 
 * When the form is submitted, any granted scopes are then added to the authorization code data.
 * 
 * You can customise the authorization template used by passing either path to your own template or 
 * a custom callable to the constructor. Refer to the default template `/templates/default_authorization_page.html.php`
 * as a starting point.
 * 
 * If you want to add additional form controls (e.g. configurable token lifetimes), as well as
 * making a new template, you’ll need to make a subclass which overrides {@see DefaultAuthorizationForm::transformAuthorizationCode()}
 * to additionally handle your new form data.
 * 
 * For any more involved customisation, it may make sense to create your own implementation of {@see AuthorizationFormInterface}.
 */
class DefaultAuthorizationForm implements AuthorizationFormInterface, LoggerAwareInterface {
	/** @var string $csrfKey */
	public $csrfKey;

	/** @var callable $formTemplateCallable */
	private $formTemplateCallable;

	/** @var LoggerInterface $logger */
	private $logger;

	/**
	 * Constructor
	 * 
	 * @param string|callable|null $formTemplate The path to a custom template, or a template callable with the signature `function (array $context): string`. Uses the default if null.
	 * @param string|null $csrfKey The key used to retrieve a CSRF token from the request attributes, and as its form data name. Uses the default defined in Server if null. Only change this if you’re using a custom CSRF middleware.
	 * @param LoggerInterface|null $logger A logger.
	 */
	public function __construct($formTemplate=null, ?string $csrfKey=null, ?LoggerInterface $logger=null) {
		$this->csrfKey = $csrfKey ?? \Taproot\IndieAuth\Server::DEFAULT_CSRF_KEY;
		$this->logger = $logger ?? new NullLogger;

		$formTemplate = $formTemplate ?? __DIR__ . '/../../templates/default_authorization_page.html.php';
		if (is_string($formTemplate)) {
			if (!file_exists($formTemplate)) {
				$this->logger->warning("\$formTemplate string passed to DefaultAuthorizationForm was not a valid path.", ['formTemplate' => $formTemplate]);
			}
			$formTemplate = function (array $context) use ($formTemplate): string {
				return renderTemplate($formTemplate, $context);
			};
		}

		if (!is_callable($formTemplate)) {
			throw new BadMethodCallException("\$formTemplate must be a string (path), callable, or null.");
		}

		$this->formTemplateCallable = $formTemplate;
	}

	public function showForm(ServerRequestInterface $request, array $authenticationResult, string $formAction, $clientHAppOrException): ResponseInterface {
		// Show an authorization page. List all requested scopes, as this default
		// function has no way of knowing which scopes are supported by the consumer.
		$scopes = [];
		foreach(explode(' ', $request->getQueryParams()['scope'] ?? '') as $s) {
			$scopes[$s] = null; // Ideally there would be a description of the scope here, we don’t have one though.
		}

		$exception = null;
		$appData = null;
		if ($clientHAppOrException instanceof Exception) {
			$exception = $clientHAppOrException;
		} elseif (is_array($clientHAppOrException)) {
			// https://indieauth.spec.indieweb.org/#client-metadata
			$appData = [
				'name' => $clientHAppOrException['client_name'],
				'url' => $clientHAppOrException['client_uri'],
				'photo' => $clientHAppOrException['logo_uri'],
				'author' => null
			];
		} elseif (M\isMicroformat($clientHAppOrException)) {
			$appData = [
				'name' => M\getPlaintext($clientHAppOrException, 'name'),
				'url' => M\getPlaintext($clientHAppOrException, 'url'),
				'photo' => M\getPlaintext($clientHAppOrException, 'photo'),
				'author' => null
			];

			if (M\hasProp($clientHAppOrException, 'author')) {
				$rawAuthor = $clientHAppOrException['properties']['author'][0];
				if (is_string($rawAuthor)) {
					$appData['author'] = $rawAuthor;
				} elseif (M\isMicroformat($rawAuthor)) {
					$appData['author'] = [
						'name' => M\getPlaintext($rawAuthor, 'name'),
						'url' => M\getPlaintext($rawAuthor, 'url'),
						'photo' => M\getPlaintext($rawAuthor, 'photo')
					];
				}
			}
		}

		return new Response(200, ['content-type' => 'text/html'], call_user_func($this->formTemplateCallable, [
			'scopes' => $scopes,
			'user' => $authenticationResult,
			'formAction' => $formAction,
			'request' => $request,
			'clientHApp' => $appData,
			'exception' => $exception,
			'clientId' => $request->getQueryParams()['client_id'],
			'clientRedirectUri' => $request->getQueryParams()['redirect_uri'],
			'csrfFormElement' => '<input type="hidden" name="' . htmlentities($this->csrfKey) . '" value="' . htmlentities($request->getAttribute($this->csrfKey)) . '" />'
		]));
	}

	public function transformAuthorizationCode(ServerRequestInterface $request, array $code): array {
		// Add any granted scopes from the form to the code.
		$grantedScopes = $request->getParsedBody()['taproot_indieauth_server_scope'] ?? [];

		// This default implementation naievely accepts any scopes it receives from the form.
		// You may wish to perform some sort of validation.
		$code['scope'] = join(' ', $grantedScopes);

		// You may wish to additionally make any other necessary changes to the the code based on
		// the form submission, e.g. if the user set a custom token lifetime, or wanted extra data
		// stored on the token to affect how it behaves.
		return $code;
	}

	public function setLogger(LoggerInterface $logger): void {
		$this->logger = $logger;
	}
}
