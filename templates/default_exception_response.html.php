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

		</style>
	</head>
	<body>
		<h1>Error: <?= htmlentities($exception->getMessage()) ?></h1>

		<p><?= htmlentities($exception->getExplanation()) ?></p>

		<!-- If $exception->trustQueryParams() returns false, then the query parameters have been tampered with
		     and we shouldn’t offer the user a redirect back to the client_id! -->
		<?php if ($exception->trustQueryParams()): ?>
			<p><a href="<?= htmlentities($request->getQueryParams()['client_id']) ?>">Return to app (<?= htmlentities($request->getQueryParams()['client_id']) ?> ?>)</a>
		<?php endif ?>

		<!-- You’ll probably want to offer the user a suitable link to leave the flow. -->

		<footer>
			<small>Powered by <a href="https://taprootproject.com">taproot/indieauth</a></small>
		</footer>
	</body>
</html>
