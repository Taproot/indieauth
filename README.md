# taproot/indieauth

[![Latest Stable Version](http://poser.pugx.org/taproot/indieauth/v)](https://packagist.org/packages/taproot/indieauth) <a href="https://github.com/Taproot/indieauth/actions/workflows/php.yml"><img src="https://github.com/taproot/indieauth/actions/workflows/php.yml/badge.svg?branch=main" alt="" /></a> [![License](http://poser.pugx.org/taproot/indieauth/license)](https://packagist.org/packages/taproot/indieauth) [![Total Downloads](http://poser.pugx.org/taproot/indieauth/downloads)](https://packagist.org/packages/taproot/indieauth) 

A PSR-7-compatible implementation of the request-handling logic for IndieAuth authorization endpoints
and token endpoints.

* [API Documentation](https://taproot.github.io/indieauth/namespaces/taproot-indieauth.html)
* [Code Coverage](https://taproot.github.io/indieauth/coverage/)

## Installation

taproot/indieauth is currently tested against and compatible with PHP 7.3, 7.4, and 8.0.

Install taproot/indieauth using [composer](https://getcomposer.org/):

    composer.phar require taproot/indieauth
    composer.phar install (or composer.phar update)

Versioned releases are GPG signed so you can verify that the code hasn’t been tampered with.

    gpg --recv-keys 1C00430B19C6B426922FE534BEF8CE58118AD524
    cd vendor/taproot/indieauth
    git tag -v v0.1.0 # Replace with the version you have installed

## Usage

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

### Example Application

See the [taproot/micropub example app](https://github.com/Taproot/micropub-adapter/tree/main/example) for a working example of how to use taproot/indieauth.

## Contributing

If you have any questions about using this library, join the [indieweb chatroom](https://indieweb.org/discuss) and ping `barnaby`.

If you find a bug or problem with the library, or want to suggest a feature, please [create an issue](https://github.com/Taproot/indieauth/issues/new).

If discussions lead to you wanting to submit a pull request, following this process, while not required, will increase the chances of it quickly being accepted:

* Fork this repo to your own github account, and clone it to your development computer.
* Run `./run_coverage.sh` and ensure that all tests pass — you’ll need XDebug for code coverage data.
* If applicable, write failing regression tests e.g. for a bug you’re fixing.
* Make your changes.
* Run `./run_coverage.sh` and `open docs/coverage/index.html`. Make sure that the changes you made are covered by tests. taproot/indieauth had nearly 100% test coverage from version 0.1.0, and that number should never go down!
* Run `./vendor/bin/psalm` and and fix any warnings it brings up.
* Install and run `./phpDocumentor.phar` to regenerate the documentation if applicable.
* Push your changes and submit the PR.

## Changelog

* v0.1.0 coming soon!
