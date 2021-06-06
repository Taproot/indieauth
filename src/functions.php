<?php

namespace Taproot\IndieAuth;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

// From https://github.com/indieweb/indieauth-client-php/blob/main/src/IndieAuth/Client.php, thanks aaronpk.
function generateRandomString($numBytes) {
	if (function_exists('random_bytes')) {
		$bytes = random_bytes($numBytes);
	} elseif (function_exists('openssl_random_pseudo_bytes')){
		$bytes = openssl_random_pseudo_bytes($numBytes);
	} else {
		$bytes = '';
		for($i=0, $bytes=''; $i < $numBytes; $i++) {
			$bytes .= chr(mt_rand(0, 255));
		}
	}
	return bin2hex($bytes);
}

function isIndieAuthAuthorizationCodeRedeemingRequest(ServerRequestInterface $request) {
	return strtolower($request->getMethod()) == 'post'
			&& array_key_exists('grant_type', $request->getParsedBody())
			&& $request->getParsedBody()['grant_type'] == 'authorization_code';
}

function isIndieAuthAuthorizationRequest(ServerRequestInterface $request, $permittedMethods=['get']) {
	return in_array(strtolower($request->getMethod()), array_map('strtolower', $permittedMethods))
			&& array_key_exists('response_type', $request->getQueryParams())
			&& $request->getQueryParams()['response_type'] == 'code';
}

function isAuthorizationApprovalRequest(ServerRequestInterface $request) {
	return strtolower($request->getMethod()) == 'post'
			&& array_key_exists('taproot_indieauth_action', $request->getParsedBody())
			&& $request->getParsedBody()['taproot_indieauth_action'] == 'approve';
}

function buildQueryString(array $parameters) {
	$qs = [];
	foreach ($parameters as $k => $v) {
		$qs[] = urlencode($k) . '=' . urlencode($v);
	}
	return join('&', $qs);
}

/**
 * Append Query Parameters
 * 
 * Converts `$queryParams` into a query string, then checks `$uri` for an
 * existing query string. Then appends the newly generated query string
 * with either ? or & as appropriate.
 */
function appendQueryParams(string $uri, array $queryParams) {
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
