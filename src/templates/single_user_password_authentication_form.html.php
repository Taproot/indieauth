<?php
/** @var string $formAction The URL to POST to to authorize the app, or to set as the redirect URL for a logout action if the user wants to continue as a different user. */
/** @var Psr\Http\Message\ServerRequestInterface $request */
/** @var string $csrfFormElement A pre-rendered CSRF form element which must be output inside the authorization form. */
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>IndieAuth • Log In</title>

		<style>

		</style>
	</head>
	<body>
		<form method="post" action="<?= $formAction ?>">
			<?= $csrfFormElement ?>
			
			<h1>Log In</h1>

			<p><input type="password" name="<?= \Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback::PASSWORD_FORM_PARAMETER ?>" /></p>

			<p><button type="submit">Log In</button></p>

		</form>

		<footer>
			<small>Powered by <a href="https://taprootproject.com">taproot/indieauth</a></small>
		</footer>
	</body>
</html>
