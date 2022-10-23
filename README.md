# taproot/indieauth

[![Latest Stable Version](http://poser.pugx.org/taproot/indieauth/v)](https://packagist.org/packages/taproot/indieauth) <a href="https://github.com/Taproot/indieauth/actions/workflows/php.yml"><img src="https://github.com/taproot/indieauth/actions/workflows/php.yml/badge.svg?branch=main" alt="" /></a> [![License](http://poser.pugx.org/taproot/indieauth/license)](https://packagist.org/packages/taproot/indieauth) [![Total Downloads](http://poser.pugx.org/taproot/indieauth/downloads)](https://packagist.org/packages/taproot/indieauth) 

taproot/indieauth is a PSR-7-compatible IndieAuth server library. It allows you to quickly and easily turn your existing website into an IndieAuth Identity Provider, enabling you to log into websites using your domain, and to grant granular access to your website to external apps (e.g. to allow external apps to post to your site via micropub). It comes with sane defaults, but can be extensively customised.

## Quick Links

* [IndieAuth Living Standard](https://indieauth.spec.indieweb.org/)
* [API Documentation](https://taproot.github.io/indieauth/namespaces/taproot-indieauth.html)
* [Code Coverage](https://taproot.github.io/indieauth/coverage/)
* [Support Chatroom](https://chat.indieweb.org/dev/) (ping `barnaby` or ask one of the other friendly people there)

## Installation

taproot/indieauth is currently tested against and compatible with PHP 7.3, 7.4, 8.0 and 8.1.

Install taproot/indieauth using [composer](https://getcomposer.org/):

    composer.phar require taproot/indieauth
    composer.phar install (or composer.phar update)

Versioned releases are GPG signed so you can verify that the code hasn’t been tampered with.

    gpg --recv-keys 1C00430B19C6B426922FE534BEF8CE58118AD524
    cd vendor/taproot/indieauth
    git tag -v v0.3.1 # Replace with the version you have installed

## Usage

Typical minimal usage looks something like this:
    
```php
// Somewhere in your app set-up code:
$server = new Taproot\IndieAuth\Server([
	// Your server’s issuer ID URL (see __construct() docs for more details)
 	'issuer' => 'https://example.com/',

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

// In your authorization endpoint route, which must not be CSRF-protected:
return $server->handleAuthorizationEndpointRequest($request);

// In your token endpoint route, which must not be CSRF-protected:
return $server->handleTokenEndpointRequest($request);

// In another route (e.g. a micropub route), to authenticate the request:
// (assuming $bearerToken is a token parsed from an “Authorization: Bearer XXXXXX” header
// or access_token property from a request body)
if ($accessToken = $server->getAccessToken($bearerToken)) {
	// Request is authenticated as $accessToken['me'], and is allowed to
	// act according to the scopes listed in $accessToken['scope'].
	$scopes = explode(' ', $accessToken['scope']);
}
```

IndieAuth clients require some discovery metadata to be able to discover relevant URLs and configuration details. Providing this discovery is currently out of the scope of taproot/indieauth (we might consider semi-automating the generation of the indieauth-metadata endpoint in the future), so please refer to the [Discovery section of the specification](https://indieauth.spec.indieweb.org/#discovery) for more information.

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

If you have any questions about using this library, join the [indieweb dev chatroom](https://chat.indieweb.org/dev/), and ping `barnaby` or ask one of the other friendly people there.

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

### v0.3.1
2022-10-23

* Corrected Cache-Control headers, added CSP and X-Frame-Options headers to user-facing responses (#21)
* Removed hard dependencies on nyholm/psr7 and webmozart/path-util (#20)
* Allowed installation alongside mf2/mf2 ^0.5, added code for handling img+alt parsing of photos

### v0.3.0
2022-10-21

Breaking changes:
* various public members of classes are now protected and can only be configured on instantiation
* `issuer` key is now semi-required in the Server config array (omitting it will result in a warning)

Other changes:
* Everywhere which previously accepted a custom template path now additionally supports a callable with the following signature (#18)
  ```php
	function (array $context): string
	```
* Client ID web pages are now searched for matching h-x-app microformats in addition to h-app (#17)
* If a valid author property is present on the client ID h-(x-)app, DefaultAuthorizationForm and its corresponding template make it available and present it (#16)
* Improved documentation with internal links, better formatting
* Allowed DoubleSubmitCookieCsrfMiddleware’s cookie path to be set to arbitrary values (not useful for internal IndieAuth use, but handy for reusing that code elsewhere)
* DoubleSubmitCookieCsrfMiddleware adds a pre-rendered CSRF form element attribute to $request for convenience

### v0.2.2
2022-10-03

* Allowed installation with psr/log v2 and v3 in addition to v1.1

### v0.2.1
2022-09-24

Added a migration script for updating FilesystemJsonStorage tokens from v0.1 to v0.2 format. Run it with:

```bash
php vendor/taproot/indieauth/bin/migrate.php ../path/to/your/json/token/storage/
```

Normalized client_id and redirect_uri before validation and fetching, but stored and used the raw strings for comparison purposes (Fixes #12)

### v0.2.0
2022-09-06
* Allow supporting older clients with response_type=id (#3)
* Changed FilesystemJsonStorage internal structure to better match terms used in OAuth (#5)
* Allowed guzzle v2 (#7)
* Improved authentication callback handling logic (#8)
* Allowed . and ~ in plain text code challenge (#13)
* No more hard fail if client_id cannot be fetched (#14)
* Improved styling of all default templates
* Minor fixes, regenerated documentation

### v0.1.0
2021-06-24
* Initial release