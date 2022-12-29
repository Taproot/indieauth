<?php //declare(strict_types=1); // No strict_types so that we don’t need PHP8-only Stringable for MockLogger.

namespace Taproot\IndieAuth\Test;

use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Taproot\IndieAuth\Callback\DefaultAuthorizationForm;

class DefaultAuthorizationFormTest extends TestCase {
	public function testConstructorEmitsWarningIfStringFormTemplateIsntAFile() {
		$logCount = 0;
		$logLevel = null;
		$mockLogger = new MockLogger(function ($level, $message, $context=[]) use (&$logCount, &$logLevel) {
			$logCount += 1;
			$logLevel = $level;
		});

		new DefaultAuthorizationForm(__DIR__ . '/nonexistent-file', null, $mockLogger);

		$this->assertEquals(1, $logCount);
		$this->assertEquals(LogLevel::WARNING, $logLevel);
	}
}

class MockLogger extends AbstractLogger {
	private $callback;

	public function __construct($callback) {
		$this->callback = $callback;
	}

	// Ignoring the signature mismatch error on this line for the moment to retain compat with PHP7.
	public function log($level, $message, array $context=[]): void {
		call_user_func($this->callback, $level, $message, $context);
	}
}
