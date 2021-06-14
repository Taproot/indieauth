# taproot/indieauth

![Build Status](https://github.com/taproot/indieauth/actions/workflows/php.yml/badge.svg?branch=main)

A PSR-7-compatible implementation of the request-handling logic for IndieAuth authorization endpoints
and token endpoints.

* [API Documentation](https://taproot.github.io/indieauth/)
* [Code Coverage](https://taproot.github.io/indieauth/coverage/)

Typical minimal usage looks something like this:
    
```php
// Somewhere in your app set-up code:
$server = new Taproot\IndieAuth\Server([
	// A secret key, >= 64 characters long.
	'secret' => YOUR_APP_INDIEAUTH_SECRET,

	// A path to store token data, or an object implementing TokenStorageInterface.
	'tokenStorage' => '/../data/auth_tokens/',

	// An authentication callback function, which either returns data about the current user,
	// or redirects to/implements an authentication flow.
	'authenticationHandler' => function (ServerRequestInterface $request, string $authenticationRedirect, ?string $normalizedMeUrl) {
		// If the request is authenticated, return an array with a `me` key containing the
		// canonical URL of the currently logged-in user.
		if ($userUrl = getLoggedInUserUrl($request)) {
			return ['me' => $userUrl];
		}
		
		// Otherwise, redirect the user to a login page, ensuring that they will be redirected
		// back to the IndieAuth flow with query parameters intact once logged in.
		return new Response('302', ['Location' => 'https://example.com/login?next=' . urlencode($authenticationRedirect)]);
	}
]);

// In your authorization endpoint route:
return $server->handleAuthorizationEndpointRequest($request);

// In your token endpoint route:
return $server->handleTokenEndpointRequest($request);

// In another route (e.g. a micropub route), to authenticate the request:
// (assuming $bearerToken is a token parsed from an “Authorization: Bearer XXXXXX” header
// or access_token property from a request body)
if ($accessToken = $server->getTokenStorage()->getAccessToken($bearerToken)) {
	// Request is authenticated as $accessToken['me'], and is allowed to
	// act according to the scopes listed in $accessToken['scope'].
	$scopes = explode(' ', $accessToken['scope']);
}
```

Refer to the `__construct` documentation for further configuration options, and to [the
documentation](https://taproot.github.io/indieauth/namespaces/taproot-indieauth.html) for both handling methods for further documentation about them, specifically:

* [Taproot\IndieAuth\Server::__construct()](https://taproot.github.io/indieauth/classes/Taproot-IndieAuth-Server.html#method___construct) for detailed information about how to configure your `Server` instance.
* [Taproot\IndieAuth\Server::handleAuthorizationEndpointRequest()](https://taproot.github.io/indieauth/classes/Taproot-IndieAuth-Server.html#method_handleAuthorizationEndpointRequest) for an overview of exactly what happens during an authorization request (which is the bulk of what this library is for)
* [Taproot\IndieAuth\Callback\DefaultAuthorizationForm](https://taproot.github.io/indieauth/classes/Taproot-IndieAuth-Callback-DefaultAuthorizationForm.html) (and its [associated template](https://github.com/Taproot/indieauth/blob/main/templates/default_authorization_page.html.php)) for details about customising the default consent screen form.
* [Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback](https://taproot.github.io/indieauth/classes/Taproot-IndieAuth-Callback-SingleUserPasswordAuthenticationCallback.html) for an example of how to implement an authentication callback, and it’s [corresponding template](https://github.com/Taproot/indieauth/blob/main/templates/single_user_password_authentication_form.html.php) for information on customising the template.
* [Taproot\IndieAuth\Storage\TokenStorageInterface](https://taproot.github.io/indieauth/classes/Taproot-IndieAuth-Storage-TokenStorageInterface.html) for details about implementing your own token storage
* [Taproot\IndieAuth\Callback\AuthorizationFormInterface](https://taproot.github.io/indieauth/classes/Taproot-IndieAuth-Callback-AuthorizationFormInterface.html) for infomation about implementing your own authorization form.
