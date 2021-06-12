# taproot/indieauth

A PSR-7-compatible implementation of the request-handling logic for IndieAuth authorization endpoints
and token endpoints.

Typical minimal usage looks something like this:
    
```php
// Somewhere in your app set-up code:
$server = new Taproot\IndieAuth\Server([
	// A secret key, >= 64 characters long.
	'secret' => APP_INDIEAUTH_SECRET,

	// A path to store token data, or an object implementing TokenStorageInterface.
	'tokenStorage' => '/../data/auth_tokens/',

	// An authentication callback function, which either returns data about the current user,
	// or redirects to/implements an authentication flow.
	'handleAuthenticationRequestCallback' => function (ServerRequestInterface $request, string $authenticationRedirect, ?string $normalizedMeUrl) {
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

Refer to the `__construct` documentation for further configuration options, and to the
documentation for both handling methods for further documentation about them.
