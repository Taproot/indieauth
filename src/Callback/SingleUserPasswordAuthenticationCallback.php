<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Callback;

use Exception;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface;

use function Taproot\IndieAuth\renderTemplate;

class SingleUserPasswordAuthenticationCallback {
	const PASSWORD_FORM_PARAMETER = 'taproot_indieauth_server_password';

	public string $csrfKey;
	public string $formTemplate;
	protected array $user;
	protected string $hashedPassword;

	public function __construct(array $user, string $hashedPassword, ?string $csrfKey=null, ?string $formTemplate=null) {
		if (!array_key_exists('me', $user) || !is_string($user['me'])) {
			throw new Exception('The $user array MUST contain a “me” key, the value which must be the user’s canonical URL as a string.');
		}
		$this->user = $user;
		$this->hashedPassword = $hashedPassword;
		$this->formTemplate = $formTemplate ?? __DIR__ . '/../../templates/single_user_password_authentication_form.html.php';
		$this->csrfKey = $csrfKey ?? \Taproot\IndieAuth\Server::DEFAULT_CSRF_KEY;
	}

	public function __invoke(ServerRequestInterface $request, string $formAction) {
		// If the request is a form submission with a matching password, return the corresponding
		// user data.
		if ($request->getMethod() == 'POST' && password_verify($request->getParsedBody()[self::PASSWORD_FORM_PARAMETER] ?? '', $this->hashedPassword)) {
			return $this->user;
		}

		// Otherwise, return a response containing the password form.
		return new Response(200, ['content-type' => 'text/html'], renderTemplate($this->formTemplate, [
			'formAction' => $formAction,
			'request' => $request,
			'csrfFormElement' => '<input type="hidden" name="' . htmlentities($this->csrfKey) . '" value="' . htmlentities($request->getAttribute($this->csrfKey)) . '" />'
		]));
	}
}