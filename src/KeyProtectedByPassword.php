<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;

final class KeyProtectedByPassword {
	const PASSWORD_KEY_CURRENT_VERSION = "\xDE\xF1\x00\x00";

	/**
	 * @var string
	 */
	private $encrypted_key = '';

	/**
	 * Constructor for KeyProtectedByPassword.
	 *
	 * @param string $encrypted_key
	 */
	private function __construct($encrypted_key)
	{
		$this->encrypted_key = $encrypted_key;
	}

	/**
	 * Creates a random key protected by the provided password.
	 *
	 * @param string $password
	 *
	 * @return KeyProtectedByPassword
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 */
	public static function createRandomPasswordProtectedKey(
		#[\SensitiveParameter]
		$password
	) {
		$inner_key = Key::createNewRandomKey();
		/* The password is hashed as a form of poor-man's domain separation
		 * between this use of encryptWithPassword() and other uses of
		 * encryptWithPassword() that the user may also be using as part of the
		 * same protocol. */
		$encrypted_key = Crypto::encryptWithPassword(
			$inner_key->saveToAsciiSafeString(),
			\hash(Core::HASH_FUNCTION_NAME, $password, true),
			true
		);

		return new KeyProtectedByPassword($encrypted_key);
	}

	/**
	 * Encodes the KeyProtectedByPassword into a string of printable ASCII
	 * characters.
	 *
	 * @return string
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 */
	public function saveToAsciiSafeString()
	{
		return Encoding::saveBytesToChecksummedAsciiSafeString(
			self::PASSWORD_KEY_CURRENT_VERSION,
			$this->encrypted_key
		);
	}

	/**
	 * Changes the password.
	 *
	 * @param string $current_password
	 * @param string $new_password
	 *
	 * @return KeyProtectedByPassword
	 * @throws Ex\WrongKeyOrModifiedCiphertextException
	 *
	 * @throws Ex\EnvironmentIsBrokenException
	 */
	public function changePassword(
		#[\SensitiveParameter]
		$current_password,
		#[\SensitiveParameter]
		$new_password
	) {
		$inner_key = $this->unlockKey($current_password);
		/* The password is hashed as a form of poor-man's domain separation
		 * between this use of encryptWithPassword() and other uses of
		 * encryptWithPassword() that the user may also be using as part of the
		 * same protocol. */
		$encrypted_key = Crypto::encryptWithPassword(
			$inner_key->saveToAsciiSafeString(),
			\hash(Core::HASH_FUNCTION_NAME, $new_password, true),
			true
		);

		$this->encrypted_key = $encrypted_key;

		return $this;
	}

	/**
	 * Decrypts the protected key, returning an unprotected Key object that can
	 * be used for encryption and decryption.
	 *
	 * @param string $password
	 *
	 * @return Key
	 * @throws Ex\EnvironmentIsBrokenException
	 * @throws Ex\WrongKeyOrModifiedCiphertextException
	 *
	 */
	public function unlockKey(
		#[\SensitiveParameter]
		$password
	) {
		try
		{
			$inner_key_encoded = Crypto::decryptWithPassword(
				$this->encrypted_key,
				\hash(Core::HASH_FUNCTION_NAME, $password, true),
				true
			);

			return Key::loadFromAsciiSafeString($inner_key_encoded);
		}
		catch (Ex\BadFormatException $ex)
		{
			/* This should never happen unless an attacker replaced the
			 * encrypted key ciphertext with some other ciphertext that was
			 * encrypted with the same password. We transform the exception type
			 * here in order to make the API simpler, avoiding the need to
			 * document that this method might throw an Ex\BadFormatException. */
			throw new Ex\WrongKeyOrModifiedCiphertextException(
				"The decrypted key was found to be in an invalid format. ".
				"This very likely indicates it was modified by an attacker."
			);
		}
	}

	/**
	 * Loads a KeyProtectedByPassword from its encoded form.
	 *
	 * @param string $saved_key_string
	 *
	 * @return KeyProtectedByPassword
	 * @throws Ex\BadFormatException
	 *
	 */
	public static function loadFromAsciiSafeString(
		#[\SensitiveParameter]
		$saved_key_string
	) {
		$encrypted_key = Encoding::loadBytesFromChecksummedAsciiSafeString(
			self::PASSWORD_KEY_CURRENT_VERSION,
			$saved_key_string
		);

		return new KeyProtectedByPassword($encrypted_key);
	}
}
