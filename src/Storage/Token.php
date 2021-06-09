<?php declare(strict_types=1);

namespace Taproot\IndieAuth\Storage;

use JsonSerializable;

class Token implements JsonSerializable {
	protected string $key;
	protected array $data;

	public function __construct(string $key, array $data) {
		$this->key = $key;
		$this->data = $data;
	}

	public function getData(): array {
		return $this->data;
	}

	public function getKey(): string {
		return $this->key;
	}

	public function __toString() {
		return $this->key;
	}

	public function jsonSerialize() {
		return $this->data;
	}
}
