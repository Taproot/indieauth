<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Callback;

use BadMethodCallException;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface;

use function Taproot\IndieAuth\renderTemplate;

/**
 * Single User Password Authentication Callback
 * 
 * A simple example authentication callback which performs authentication itself rather
 * than redirecting to an existing authentication flow.
 * 
 * In some cases, it may make sense for your IndieAuth server to be able to authenticate
 * users itself, rather than redirecting them to an existing authentication flow. This
 * implementation provides a simple single-user password authentication method intended
 * for bootstrapping and testing purposes.
 * 
 * The sign-in form can be customised by making your own template and passing the path to
 * the constructor.
 * 
 * Minimal usage:
 * 
 * ```php
 * // One-off during app configuration:
 * YOUR_HASHED_PASSWORD = password_hash('my super strong password', PASSWORD_DEFAULT);
 * 
 * // In your app:
 * use Taproot\IndieAuth;
 * $server = new IndieAuth\Server([
 *   …
 *   'authenticationHandler' => new IndieAuth\Callback\SingleUserPasswordAuthenticationCallback(
 *     ['me' => 'https://me.example.com/'],
 *     YOUR_HASHED_PASSWORD
 *   )
 *   …
 * ]);
 * ```
 * 
 * See documentation for `__construct()` for information about customising behaviour.
 */
class SingleUserPasswordAuthenticationCallback {
	const PASSWORD_FORM_PARAMETER = 'taproot_indieauth_server_password';

	public string $csrfKey;
	public string $formTemplate;
	protected array $user;
	protected string $hashedPassword;
	
	/**
	 * Constructor
	 * 
	 * @param array $user An array representing the user, which will be returned on a successful authentication. MUST include a 'me' key, may also contain a 'profile' key, or other keys at your discretion.
	 * @param string $hashedPassword The password used to authenticate as $user, hashed by `password_hash($pass, PASSWORD_DEFAULT)`
	 * @param string|null $formTemplate The path to a template used to render the sign-in form. Uses default if null.
	 * @param string|null $csrfKey The key under which to fetch a CSRF token from `$request` attributes, and as the CSRF token name in submitted form data. Defaults to the Server default, only change if you’re using a custom CSRF middleware.
	 */
	public function __construct(array $user, string $hashedPassword, ?string $formTemplate=null, ?string $csrfKey=null) {
		if (!isset($user['me'])) {
			throw new BadMethodCallException('The $user array MUST contain a “me” key, the value which must be the user’s canonical URL as a string.');
		}
		
		if (is_null(password_get_info($hashedPassword)['algo'])) {
			throw new BadMethodCallException('The provided $hashedPassword was not a valid hash created by the password_hash() function.');
		}
		$this->user = $user;
		$this->hashedPassword = $hashedPassword;
		$this->formTemplate = $formTemplate ?? __DIR__ . '/../../templates/single_user_password_authentication_form.html.php';
		$this->csrfKey = $csrfKey ?? \Taproot\IndieAuth\Server::DEFAULT_CSRF_KEY;
	}

	public function __invoke(ServerRequestInterface $request, string $formAction, ?string $normalizedMeUrl=null) {
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