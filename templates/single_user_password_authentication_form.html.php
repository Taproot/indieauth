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
			* {
				box-sizing: border-box;
				max-width: 100%;
				margin: 0;
				padding: 0;
			}

			h1, h2, h3, h4, h5, h6, p { margin-bottom: 1em; }

			body {
				font-size: 1em;
				font-family: Helvetica, sans-serif;
				padding: 0;
				margin: 0;
			}

			form {
				margin: 1em auto;
				padding: 1em;
				max-width: 40em;
			}

			button[type=submit] {
				padding: 0.5em;
				cursor: pointer;
			}

			footer {
				text-align: center;
				margin: 5em 0 2em 0;
				opacity: 0.6;
				position: fixed;
				bottom: 0;
				width: 100%;
			}
		</style>
	</head>
	<body>
		<form method="post" action="<?= $formAction ?>">
			<?= $csrfFormElement ?>
			
			<h1>Log In</h1>

			<p><label>Password: <input type="password" name="<?= \Taproot\IndieAuth\Callback\SingleUserPasswordAuthenticationCallback::PASSWORD_FORM_PARAMETER ?>" /></label></p>

			<p><button type="submit">Log In</button></p>

		</form>

		<footer>
			<small>Powered by <a href="https://taprootproject.com">taproot/indieauth</a></small>
		</footer>
	</body>
</html>
