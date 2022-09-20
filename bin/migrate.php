<?php declare(strict_types=1);

namespace Taproot\IndieAuth;

use DirectoryIterator;

// When multiple migration options become necessary, probably move to following structure:
// JSON path and SQLite path become options, args becomes a list of migrations to apply, in order,
// enabling multiple migrations between different storage backends to be applied at once.

$migrations = [
	'json_v0.1.0_v0.2.0' => function(string $path): array {
		$logs = [];
		
		foreach (new DirectoryIterator($path) as $fileInfo) {
			if ($fileInfo->isFile() && $fileInfo->getExtension() == 'json') {
				$tokenPath = $fileInfo->getPathname();
				$token = json_decode(file_get_contents($tokenPath), true);
				
				if (array_key_exists('exp', $token)) {
					// This token is new or has already been migrated.
					continue;
				}

				// The exact migration depends on whether the code was exchanged for a token already.
				if ($token['exchanged_at'] ?? false) {
					$token['exp'] = $token['valid_until'];
					$token['iat'] = $token['exchanged_at'];
				} else {
					$token['code_exp'] = $token['valid_until'];
				}

				file_put_contents($tokenPath, json_encode($token));
			}
		}

		return $logs;
	}
];

function showHelp() {
	global $migrations; // ew, global variables :(

	echo <<<EOD
taproot/indieauth Token Storage Migration Utility"

Usage: php migrate.php ../path/to/your/json/token/folder

For the moment there is only one migration (JSON v0.1.0 -> v0.2.0). The utility
will be expanded when more migrations become necessary, and the command line interface
will change, so it’s not recommended to automate running this tool.
EOD;
}

if (!empty($argv) and str_contains($argv[0], 'migrate.php')) {
	// Script currently only accepts a single JSON path argument. Expand when required.
	if ($argc != 2) {
		showHelp();
		die;
	}

	$jsonPath = rtrim($argv[1], '/');

	$logs = $migrations['json_v0.1.0_v0.2.0']($jsonPath);

	foreach ($logs as $logline) {
		echo "$logline\n";
	}
}

// For automating migrations in the unlikely event anyone wants to do that.
return $migrations;
