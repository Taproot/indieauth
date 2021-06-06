<?php
/** @var string $authenticationRedirect The URL to POST to to authorize the app, or to set as the redirect URL for a logout action if the user wants to continue as a different user. */
/** @var Psr\Http\Message\ServerRequestInterface $request */
/** @var array|null $clientHApp */
/** @var array $me */
/** @var string $csrfFormElement A pre-rendered CSRF form element which must be output inside the authorization form. */
?>

<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>IndieAuth • Authorize</title>
	</head>
	<body>
		<form method="post" action="<?= $authenticationRedirect ?>">
			<?= $csrfFormElement ?>

			<h1>Authorize</h1>

			<!-- TODO -->
		</form>
	</body>
</html>
