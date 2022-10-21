<?php

require(__DIR__ . '/../vendor/autoload.php');

// Quick-and-dirty script for previewing templates under various conditions, for working on styling.
// Run with:
// cd templates
// php -S localhost:8000 index.php

// Most templates expect a $request variable. Create an empty one, customise later if required.
$request = (new \Nyholm\Psr7\Factory\Psr17Factory())->createServerRequest('GET', '/');

if (empty($_GET['t'])) {
	?>
<p>Templates:</p>
<ul>
	<li><a href="?t=default_authorization_page.html&happ=photo&profile=photo&scopes=descriptions">Authorization Page with h-app w/photo, user details w/photo and scopes with descriptions</a></li>
	<li><a href="?t=default_authorization_page.html&happ=photo,string-author&profile=photo&scopes=descriptions">Authorization Page with h-app w/photo+string author, user details w/photo and scopes with descriptions</a></li>
	<li><a href="?t=default_authorization_page.html&happ=photo,full-author&profile=photo&scopes=descriptions">Authorization Page with h-app w/photo+full author, user details w/photo and scopes with descriptions</a></li>
	<li><a href="?t=default_authorization_page.html&happ=name&profile=name&scopes=keys">Authorization Page with h-app, user details and scope list</a></li>
	<li><a href="?t=default_authorization_page.html&exception=1">Authorization Page with no h-app, no profile and an exception</a></li>
	<li><a href="?t=single_user_password_authentication_form.html">Single User Password Auth Form</a></li>
	<li><a href="?t=default_exception_response.html?trust=1">Default Exception Response</a></li>
</ul>
	<?php
} else {
	if ($_GET['t'] == 'default_authorization_page.html') {
		$_happ = empty($_GET['happ']) ? null : $_GET['happ'];
		switch ($_happ) {
			case 'photo,string-author':
				$clientHApp = [
					'name' => 'Demo App',
					'url' => 'https://client.example.com/',
					'photo' => 'http://waterpigs.co.uk/taproot/logo.png',
					'author' => 'https://waterpigs.co.uk'
				];
				break;
			case 'photo,full-author':
				$clientHApp = [
					'name' => 'Demo App',
					'url' => 'https://client.example.com/',
					'photo' => 'http://waterpigs.co.uk/taproot/logo.png',
					'author' => [
						'name' => 'Barnaby Walters',
						'photo' => 'https://waterpigs.co.uk/photo-2021-04-22-719w.jpg',
						'url' => 'https://waterpigs.co.uk'
					]
				];
				break;
			case 'photo':
				$clientHApp = [
					'name' => 'Demo App',
					'url' => 'https://client.example.com/',
					'photo' => 'http://waterpigs.co.uk/taproot/logo.png',
				];
				break;
			case 'name':
				$clientHApp = [
					'name' => 'Demo App',
					'url' => 'https://client.example.com/'
				];
				break;
			default:
				$clientHApp = null;
				break;
		}

		$_profile = empty($_GET['profile']) ? null : $_GET['profile'];
		switch ($_profile) {
			case 'photo':
				$user = [
					'me' => 'https://me.example.com/',
					'profile' => [
						'name' => 'Demo User',
						'photo' => 'https://waterpigs.co.uk/photo-2021-04-22-719w.jpg'
					]
				];
				break;
			case 'name':
				$user = [
					'me' => 'https://me.example.com/',
					'profile' => [
						'name' => 'Demo User'
					]
				];
				break;
			default:
				$user = ['me' => 'https://me.example.com/'];
				break;
		}

		$_scopes = empty($_GET['scopes']) ? null : $_GET['scopes'];
		switch ($_scopes) {
			case 'descriptions':
				$scopes = [
					'profile' => 'Allow the app to access to your profile data',
					'create' => 'Allow the app to create new content on your site',
					'update' => 'Allow the app to update content on your site'
				];
				break;
			case 'keys':
				$scopes = [
					'profile' => null,
					'create' => null,
					'update' => null
				];
				break;
			default:
				$scopes = [];
				break;
		}

		if (array_key_exists('exception', $_GET)) {
			$exception = new Exception('An example exception which might have occurred.');
		} else {
			$exception = null;
		}

		$clientId = 'https://client.example.com/';
		$formAction = '';
		$csrfFormElement = '';
		$clientRedirectUri = 'https://client.example.com/redirect';

		include('default_authorization_page.html.php');
	} elseif ($_GET['t'] == 'single_user_password_authentication_form.html') {
		$csrfFormElement = '';
		$formAction = '';
		include('single_user_password_authentication_form.html.php');
	} elseif ($_GET['t'] == 'default_exception_response.html') {
		$exception = \Taproot\IndieAuth\IndieAuthException::create(\Taproot\IndieAuth\IndieAuthException::INTERNAL_ERROR, $request);
		include('default_exception_response.html.php');
	} else {
		// Unknown template, redirect to template choosing page
		header('Location: /');
	}
}
