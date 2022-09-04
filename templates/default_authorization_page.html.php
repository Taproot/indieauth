<?php

use Taproot\IndieAuth\Server;

/** @var string $formAction The URL to POST to to authorize the app, or to set as the redirect URL for a logout action if the user wants to continue as a different user. */
/** @var Psr\Http\Message\ServerRequestInterface $request */
/** @var array|null $clientHApp a flattened version of the h-app containing name, url and photo keys, or null if none was found */
/** @var Exception|null $exception The exception thrown if fetching the client_id failed */
/** @var array $user */
/** @var array $scopes */
/** @var string $clientId */
/** @var string $clientRedirectUri */
/** @var string $csrfFormElement A pre-rendered CSRF form element which must be output inside the authorization form. */
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>IndieAuth • Authorize</title>

		<style>

		</style>
	</head>
	<body>
		<?php if (!is_null($clientHApp)): ?>
			<h1>Authorize <?= htmlentities($clientHApp['name']) ?> (<span class="inline-url"><?= $clientId ?></span>)</h1>

			<div class="client-app-details">
				<?php if (!is_null($clientHApp['photo'])): ?>
					<img class="client-app-photo" src="<?= htmlentities($clientHApp['photo']) ?>" alt="" />
				<?php else: ?>
					<div class="client-app-photo client-app-photo-placeholder"></div>
				<?php endif ?>

				<p class="client-app-name"><?= htmlentities($clientHApp['name']) ?></p>
				<p class="client-app-url"><?= htmlentities($clientHApp['url']) ?></p>
			</div>
		<?php else: ?>
			<h1>Authorize <span class="inline-url"><?= $clientId ?></span></h1>
		<?php endif ?>

		<?php if (!is_null($exception)): ?>
		<div class="warning">
			<p>The client URL <code><?= $clientId ?></code> couldn’t be fetched. This doesn’t necessarily mean that it’s insecure or broken,
			but it’s recommended that you only proceed if you know that this isn’t an issue. If in doubt, contact the client app for more
			information.</p>

			<p>Technical details: <?= get_class($exception) ?>: <?= $exception->getMessage() ?></p>
		</div>
		<?php endif ?>
		
		<div class="user-details">
			<?php if (!is_null($user['profile'])): ?>
				<?php if (!is_null($user['profile']['photo'])): ?>
					<img class="user-photo" src="<?= htmlentities($user['profile']['photo']) ?>" alt="" />
				<?php else: ?>
					<div class="user-photo user-photo-placeholder"></div>
				<?php endif ?>

				<?php if (!is_null($user['profile']['name'])): ?>
					<p class="user-name"><?= htmlentities($user['profile']['name']) ?></p>
				<?php endif ?>

				<p class="user-me-url"><?= htmlentities($user['me']) ?></p>
			<?php else: ?>
				<p>User: <span class="inline-url"><?= htmlentities($user['me']) ?></span></p>
			<?php endif ?>

			<!-- Example! If your server supports multiple users, add a form like this to allow the currently
			     logged-in user to log out and re-authenticate. In order for the IndieAuth request to proceed
					 seamlessly, you MUST redirect to $formAction after re-authenticating. For security, all
					 of the requests involved in the re-authentication SHOULD be CSRF-protected (but you’re already
					 CSRF-protecting your authentication flow… right?)

			<form class="logout-form" action="/logout" method="post">
				<input type="hidden" name="your_csrf_name" value="your_csrf_token" />

				<input type="hidden" name="your_logout_redirect_parameter" value="<?= htmlentities($formAction) ?>" />

				<p>Want to log into <span class="inline-url"><?= $clientId ?></span> as another user? <button type="submit">Log out and continue</button></p>
			</form>
			 -->
		</div>

		<form method="post" action="<?= $formAction ?>">
		<?= $csrfFormElement ?>
			<div class="scope-section">
				<h2>Scope</h2>
				<?php if(!empty($scopes)): ?>
					<p>The app has requested the following scopes. You may choose which to grant it.</p>

					<ul class="scope-list">
						<!-- Loop through $scopes, which maps string $scope to ?string $description by default. -->
						<?php foreach ($scopes as $scope => $description): ?>
							<li class="scope-list-item">
								<label>
									<input type="checkbox" name="taproot_indieauth_server_scope[]" value="<?= htmlentities($scope) ?>" />
									<p class="scope-name"><?= htmlentities($scope) ?></p>
									<?php if (!empty($description)): ?>
										<p class="scope-description"><?= htmlentities($description) ?></p>
									<?php endif ?>
								</label>
							</li>
						<?php endforeach ?>
					</ul>
				<?php else: ?>
					<p>The app has requested no scopes, and will only be able to confirm that you’re logged in as <span class="inline-url"><?= htmlentities($user['me']) ?></span>.</p>
				<?php endif ?>
			</div>

			<!-- You’re welcome to add addition UI for the user to customise the properties of the granted
			     access token (e.g. lifetime), just make sure you adapt the transformAuthorizationCode
					 function to handle them. -->

			<div class="submit-section">
				<p>After approving, you will be redirected to <span class="inline-url"><?= htmlentities($clientRedirectUri) ?></span>.</p>

				<p>
					<!-- Forms should give the user a chance to cancel the authorization. This usually involves linking them back to the app they came from. -->
					<a class="cancel-link" href="<?= htmlentities($clientId) ?>">Cancel (back to <?= $clientHApp['name'] ?? 'app' ?>)</a>

					<!-- Your form MUST be submitted with taproot_indieauth_action=approve for the approval submission to work. -->
					<button type="submit" name="<?= Server::APPROVE_ACTION_KEY ?>" value="<?= Server::APPROVE_ACTION_VALUE ?>">Authorize</button>
				</p>
			</div>
		</form>

		<footer>
			<small>Powered by <a href="https://taprootproject.com">taproot/indieauth</a></small>
		</footer>
	</body>
</html>
