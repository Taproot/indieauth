<?php

namespace Taproot\IndieAuth;

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

// From https://github.com/indieweb/indieauth-client-php/blob/main/src/IndieAuth/Client.php, thanks aaronpk.
function generateRandomString(int $numBytes): string {
	if (function_exists('random_bytes')) {
		$bytes = random_bytes($numBytes);
		// We can’t easily test the following code.
		// @codeCoverageIgnoreStart
	} elseif (function_exists('openssl_random_pseudo_bytes')){
		$bytes = openssl_random_pseudo_bytes($numBytes);
	} else {
		$bytes = '';
		for($i=0, $bytes=''; $i < $numBytes; $i++) {
			$bytes .= chr(mt_rand(0, 255));
		}
		// @codeCoverageIgnoreEnd
	}
	return bin2hex($bytes);
}

function generateRandomPrintableAsciiString(int $length): string {
	$chars = [];
	while (count($chars) < $length) {
		// 0x21 to 0x7E is the entire printable ASCII range, not including space (0x20).
		$chars[] = chr(random_int(0x21, 0x7E));
	}
	return join('', $chars);
}

function generatePKCECodeChallenge(string $plaintext): string {
	return base64_urlencode(hash('sha256', $plaintext, true));
}

function base64_urlencode(string $string): string {
	return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
}

function hashAuthorizationRequestParameters(ServerRequestInterface $request, string $secret, ?string $algo=null, ?array $hashedParameters=null, bool $requirePkce=true): ?string {
	$queryParams = $request->getQueryParams();

	if (is_null($hashedParameters)) {
		$hashedParameters = ($requirePkce or isset($queryParams['code_challenge'])) ? ['client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method'] : ['client_id', 'redirect_uri'];
	}
	
	$algo = $algo ?? 'sha256';

	$data = '';
	foreach ($hashedParameters as $key) {
		if (!isset($queryParams[$key])) {
			return null;
		}
		$data .= $queryParams[$key];
	}
	return hash_hmac($algo, $data, $secret);
}

function isIndieAuthAuthorizationCodeRedeemingRequest(ServerRequestInterface $request): bool {
	return strtolower($request->getMethod()) == 'post'
			&& array_key_exists('grant_type', $request->getParsedBody() ?? [])
			&& $request->getParsedBody()['grant_type'] == 'authorization_code';
}

function isIndieAuthAuthorizationRequest(ServerRequestInterface $request, array $permittedMethods=['get']): bool {
	return in_array(strtolower($request->getMethod()), array_map('strtolower', $permittedMethods))
			&& array_key_exists('response_type', $request->getQueryParams())
			&& in_array($request->getQueryParams()['response_type'], ['code', 'id']);
}

function isAuthorizationApprovalRequest(ServerRequestInterface $request): bool {
	return strtolower($request->getMethod()) == 'post'
			&& array_key_exists('taproot_indieauth_action', $request->getParsedBody() ?? [])
			&& $request->getParsedBody()[Server::APPROVE_ACTION_KEY] == Server::APPROVE_ACTION_VALUE;
}

function buildQueryString(array $parameters): string {
	$qs = [];
	foreach ($parameters as $k => $v) {
		$qs[] = urlencode($k) . '=' . urlencode($v);
	}
	return join('&', $qs);
}

function urlComponentsMatch(string $url1, string $url2, ?array $components=null): bool {
	$validComponents = [PHP_URL_HOST, PHP_URL_PASS, PHP_URL_PATH, PHP_URL_PORT, PHP_URL_USER, PHP_URL_QUERY, PHP_URL_SCHEME, PHP_URL_FRAGMENT];
	$components = $components ?? $validComponents;

	foreach ($components as $cmp) {
		if (!in_array($cmp, $validComponents)) {
			throw new Exception("Invalid parse_url() component passed: $cmp");
		}

		if (parse_url($url1, $cmp) !== parse_url($url2, $cmp)) {
			return false;
		}
	}

	return true;
}

/**
 * Append Query Parameters
 * 
 * Converts `$queryParams` into a query string, then checks `$uri` for an
 * existing query string. Then appends the newly generated query string
 * with either ? or & as appropriate.
 */
function appendQueryParams(string $uri, array $queryParams): string {
	if (empty($queryParams)) {
		return $uri;
	}
	
	$queryString = buildQueryString($queryParams);
	$separator = parse_url($uri, \PHP_URL_QUERY) ? '&' : '?';
	$uri = rtrim($uri, '?&');
	return "{$uri}{$separator}{$queryString}";
}

/**
 * Try setLogger
 * 
 * If `$target` implements `LoggerAwareInterface`, set it’s logger
 * to `$logger`. Returns `$target`.
 * 
 * @psalm-suppress MissingReturnType
 * @psalm-suppress MissingParamType
 */
function trySetLogger($target, LoggerInterface $logger) {
	if ($target instanceof LoggerAwareInterface) {
		$target->setLogger($logger);
	}
	return $target;
}

function renderTemplate(string $template, array $context=[]) {
	$render = function ($__template, $__templateData) {
		$render = function ($template, $data){
			return renderTemplate($template, $data);
		};
		ob_start();
		extract($__templateData);
		unset($__templateData);
		include $__template;
		return ob_get_clean();
	};
	return $render($template, $context);
}

// IndieAuth/OAuth2-related Validation Functions
// Mostly taken or adapted by https://github.com/Zegnat/php-mindee/ — thanks Zegnat!
// Code was not licensed at time of writing, permission granted here https://chat.indieweb.org/dev/2021-06-10/1623327498355700

/**
 * Check if a provided string matches the IndieAuth criteria for a Client Identifier.
 * @see https://indieauth.spec.indieweb.org/#client-identifier
 * 
 * @param string $client_id The client ID provided by the OAuth Client
 * @return bool true if the value is allowed by IndieAuth
 */
function isClientIdentifier(string $client_id): bool {
	return ($url_components = parse_url($client_id)) &&                     // Clients are identified by a URL.
			in_array($url_components['scheme'] ?? '', ['http', 'https']) &&     // Client identifier URLs MUST have either an https or http scheme,
			0 < strlen($url_components['path'] ?? '') &&                        // MUST contain a path component,
			false === strpos($url_components['path'], '/./') &&                 // MUST NOT contain single-dot
			false === strpos($url_components['path'], '/../') &&                // or double-dot path segments,
			false === isset($url_components['fragment']) &&                     // MUST NOT contain a fragment component,
			false === isset($url_components['user']) &&                         // MUST NOT contain a username
			false === isset($url_components['pass']) &&                         // or password component,
			(
				false === filter_var($url_components['host'], FILTER_VALIDATE_IP) ||  // MUST NOT be an IP address
				($url_components['host'] ?? null) == '127.0.0.1' ||                   // except for 127.0.0.1
				($url_components['host'] ?? null) == '[::1]'                          // or [::1]
			)
	;
}

/**
 * Check if a provided string matches the IndieAuth criteria for a User Profile URL.
 * @see https://indieauth.spec.indieweb.org/#user-profile-url
 * 
 * @param string $profile_url The profile URL provided by the IndieAuth Client as me
 * @return bool true if the value is allowed by IndieAuth
 */
function isProfileUrl(string $profile_url): bool {
	return ($url_components = parse_url($profile_url)) &&                   // Users are identified by a URL.
			in_array($url_components['scheme'] ?? '', ['http', 'https']) &&     // Profile URLs MUST have either an https or http scheme,
			0 < strlen($url_components['path'] ?? '') &&                        // MUST contain a path component,
			false === strpos($url_components['path'], '/./') &&                 // MUST NOT contain single-dot
			false === strpos($url_components['path'], '/../') &&                // or double-dot path segments,
			false === isset($url_components['fragment']) &&                     // MUST NOT contain a fragment component,
			false === isset($url_components['user']) &&                         // MUST NOT contain a username
			false === isset($url_components['pass']) &&                         // or password component,
			false === isset($url_components['port']) &&                         // MUST NOT contain a port,
			false === filter_var($url_components['host'], FILTER_VALIDATE_IP)   // MUST NOT be an IP address.
	;
}

/**
 * OAuth 2.0 limits what values are valid for state.
 * We check this first, because if valid, we want to send it along with other errors.
 * @see https://tools.ietf.org/html/rfc6749#appendix-A.5
 */
function isValidState(string $state): bool {
	return false !== filter_var($state, FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '/^[\x20-\x7E]*$/']]);
}

/**
 * IndieAuth requires PKCE. This implementation supports only S256 for hashing.
 * 
 * @see https://indieauth.spec.indieweb.org/#authorization-request
 */
function isValidCodeChallenge(string $challenge): bool {
	return false !== filter_var($challenge, FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '/^[A-Za-z0-9_\-.~]+$/']]);
}

/**
 * OAuth 2.0 limits what values are valid for scope.
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 */
function isValidScope(string $scope): bool {
	return false !== filter_var($scope, FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '/^([\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*)?$/']]);
}
