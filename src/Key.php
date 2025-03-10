<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
use SensitiveParameter;

final class Key {
	const KEY_CURRENT_VERSION = "\xDE\xF0\x00\x00";
	const KEY_BYTE_SIZE = 32;

	/**
	 * @var string
	 */
	private $key_bytes;

	/**
	 * Constructs a new Key object from a string of raw bytes.
	 *
	 * @param string $bytes
	 *
	 * @throws Ex\EnvironmentIsBrokenException
	 */
	private function __construct(
		#[SensitiveParameter]
		$bytes
	) {
		Core::ensureTrue(
			Core::ourStrlen($bytes) === self::KEY_BYTE_SIZE,
			'Bad key length.'
		);
		$this->key_bytes = $bytes;
	}

	/**
	 * Creates new random key.
	 *
	 * @return Key
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 */
	public static function createNewRandomKey()
	{
		return new Key(Core::secureRandom(self::KEY_BYTE_SIZE));
	}

	/**
	 * Loads a Key from its encoded form.
	 *
	 * By default, this function will call Encoding::trimTrailingWhitespace()
	 * to remove trailing CR, LF, NUL, TAB, and SPACE characters, which are
	 * commonly appended to files when working with text editors.
	 *
	 * @param string $saved_key_string
	 * @param bool   $do_not_trim (default: false)
	 *
	 * @return Key
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 * @throws Ex\BadFormatException
	 */
	public static function loadFromAsciiSafeString(
		#[SensitiveParameter]
		$saved_key_string,
		$do_not_trim = false
	) {
		if ( ! $do_not_trim)
		{
			$saved_key_string
				= Encoding::trimTrailingWhitespace($saved_key_string);
		}
		$key_bytes
			= Encoding::loadBytesFromChecksummedAsciiSafeString(self::KEY_CURRENT_VERSION,
			$saved_key_string);

		return new Key($key_bytes);
	}

	/**
	 * Encodes the Key into a string of printable ASCII characters.
	 *
	 * @return string
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 */
	public function saveToAsciiSafeString()
	{
		return Encoding::saveBytesToChecksummedAsciiSafeString(
			self::KEY_CURRENT_VERSION,
			$this->key_bytes
		);
	}

	/**
	 * Gets the raw bytes of the key.
	 *
	 * @return string
	 */
	public function getRawBytes()
	{
		return $this->key_bytes;
	}

}
