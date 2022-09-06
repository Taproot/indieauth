<?php
/** @var Taproot\IndieAuth\IndieAuthExcepton $exception */
/** @var Psr\Http\Message\ServerRequestInterface $request */
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>IndieAuth • Error!</title>

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

			main {
				margin: 1em auto;
				padding: 1em;
				max-width: 40em;
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
		<main>
			<h1>Error: <?= htmlentities($exception->getMessage()) ?></h1>

			<p><?= htmlentities($exception->getExplanation()) ?></p>

			<!-- If $exception->trustQueryParams() returns false, then the query parameters have been tampered with
					and we shouldn’t offer the user a redirect back to the client_id! -->
			<?php if ($exception->trustQueryParams() and !empty($request->getQueryParams()['client_id'])): ?>
				<p><a href="<?= htmlentities($request->getQueryParams()['client_id']) ?>">Return to app (<?= htmlentities($request->getQueryParams()['client_id']) ?> ?>)</a>
			<?php endif ?>

			<!-- You’ll probably want to offer the user a suitable link to leave the flow. -->
		</main>

		<footer>
			<small>Powered by <a href="https://taprootproject.com">taproot/indieauth</a></small>
		</footer>
	</body>
</html>
