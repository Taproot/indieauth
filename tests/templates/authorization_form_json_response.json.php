<?php

/** @var string $formAction The URL to POST to to authorize the app, or to set as the redirect URL for a logout action if the user wants to continue as a different user. */
/** @var Psr\Http\Message\ServerRequestInterface $request */
/** @var array|null $clientHApp a flattened version of the h-app containing name, url and photo keys, or null if none was found */
/** @var Exception|null $exception The exception thrown if fetching the client_id failed */
/** @var array $user */
/** @var array $scopes */
/** @var string $clientId */
/** @var string $clientRedirectUri */
/** @var string $csrfFormElement A pre-rendered CSRF form element which must be output inside the authorization form. */

echo json_encode([
	'formAction' => $formAction,
	'clientHApp' => $clientHApp,
	'exception' => is_null($exception) ? null : get_class($exception),
	'user' => $user,
	'scopes' => $scopes,
	'clientId' => $clientId,
	'clientRedirectUri' => $clientRedirectUri,
	'csrfFormElement' => $csrfFormElement
]);
?>