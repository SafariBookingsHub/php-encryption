<?php

namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
use SensitiveParameter;

use function hash;
use function ord;

final class Encoding {
	const CHECKSUM_BYTE_SIZE = 32;
	const CHECKSUM_HASH_ALGO = 'sha256';
	const SERIALIZE_HEADER_BYTES = 4;

	/**
	 * Remove trialing whitespace without table look-ups or branches.
	 *
	 * Calling this function may leak the length of the string as well as the
	 * number of trailing whitespace characters through side-channels.
	 *
	 * @param string $string
	 *
	 * @return string
	 */
public static function trimTrailingWhitespace($string = '')
{
    $length = Core::ourStrlen($string);
    if ($length < 1)
    {
        return '';
    }

    do
    {
        $prevLength = $length;
        $lastChar = ord($string[$length - 1]);
        
        // Using a while loop makes it cleaner to handle multiple types of characters
        while ($length > 0 && ($lastChar === 0x00 ||  // Null Byte
                               $lastChar === 0x09 ||  // Horizontal Tab
                               $lastChar === 0x0a ||  // New Line
                               $lastChar === 0x0d ||  // Carriage Return
                               $lastChar === 0x20))   // Space
        {
            $length--;
            if ($length > 0)
            {
                $lastChar = ord($string[$length - 1]);
            }
        }
    }
    while ($prevLength !== $length && $length > 0);

    return (string)Core::ourSubstr($string, 0, $length);
}


	/**
	 * INTERNAL USE ONLY: Applies a version header, applies a checksum, and
	 * then encodes a byte string into a range of printable ASCII characters.
	 *
	 * @param string $header
	 * @param string $bytes
	 *
	 * @return string
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 */
	public static function saveBytesToChecksummedAsciiSafeString(
		$header,
		#[SensitiveParameter]
		$bytes
	) {
		// Headers must be a constant length to prevent one type's header from
		// being a prefix of another type's header, leading to ambiguity.
		Core::ensureTrue(
			Core::ourStrlen($header) === self::SERIALIZE_HEADER_BYTES,
			'Header must be '.self::SERIALIZE_HEADER_BYTES.' bytes.'
		);

		return Encoding::binToHex(
			$header.
			$bytes.
			hash(
				self::CHECKSUM_HASH_ALGO,
				$header.$bytes,
				true
			)
		);
	}

	/**
	 * Converts a byte string to a hexadecimal string without leaking
	 * information through side channels.
	 *
	 * @param string $byte_string
	 *
	 * @return string
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 */
	public static function binToHex($byte_string)
	{
		$hex = '';
		$len = Core::ourStrlen($byte_string);

		for ($i = 0; $i < $len; ++$i)
		{
			$byte = ord($byte_string[$i]);

			// Extract the lower 4 bits (rightmost hex digit)
			$lowNibble = $byte & 0xf;

			// Extract the higher 4 bits (leftmost hex digit) and shift right to get the value
			$highNibble = $byte >> 4;

			// Convert high and low nibbles to hex representation
			$hexHigh = self::decimalToHexChar($highNibble);
			$hexLow = self::decimalToHexChar($lowNibble);

			$hex .= $hexHigh.$hexLow;
		}

		return $hex;
	}

	/**
	 * Convert a decimal value (0-15) to its corresponding hexadecimal character.
	 *
	 * @param int $decimalValue Value between 0 and 15 inclusive.
	 *
	 * @return string The corresponding hexadecimal character.
	 */
	private static function decimalToHexChar($decimalValue)
	{
		// If value is between 0 and 9, return the character representation of that value
		if ($decimalValue >= 0 && $decimalValue <= 9)
		{
			return chr(48 + $decimalValue); // 48 is the ASCII value for '0'
		}

		// If value is between 10 and 15, return the character representation (A-F)
		return chr(87
			+ $decimalValue); // 87 is the ASCII value for 'a' minus 10
	}

	/*
	 * SECURITY NOTE ON APPLYING CHECKSUMS TO SECRETS:
	 *
	 *      The checksum introduces a potential security weakness. For example,
	 *      suppose we apply a checksum to a key, and that an adversary has an
	 *      exploit against the process containing the key, such that they can
	 *      overwrite an arbitrary byte of memory and then cause the checksum to
	 *      be verified and learn the result.
	 *
	 *      In this scenario, the adversary can extract the key one byte at
	 *      a time by overwriting it with their guess of its value and then
	 *      asking if the checksum matches. If it does, their guess was right.
	 *      This kind of attack may be more easy to implement and more reliable
	 *      than a remote code execution attack.
	 *
	 *      This attack also applies to authenticated encryption as a whole, in
	 *      the situation where the adversary can overwrite a byte of the key
	 *      and then cause a valid ciphertext to be decrypted, and then
	 *      determine whether the MAC check passed or failed.
	 *
	 *      By using the full SHA256 hash instead of truncating it, I'm ensuring
	 *      that both ways of going about the attack are equivalently difficult.
	 *      A shorter checksum of say 32 bits might be more useful to the
	 *      adversary as an oracle in case their writes are coarser grained.
	 *
	 *      Because the scenario assumes a serious vulnerability, we don't try
	 *      to prevent attacks of this style.
	 */

	/**
	 * INTERNAL USE ONLY: Decodes, verifies the header and checksum, and returns
	 * the encoded byte string.
	 *
	 * @param string $expected_header
	 * @param string $string
	 *
	 * @return string
	 * @throws Ex\BadFormatException
	 *
	 * @throws Ex\EnvironmentIsBrokenException
	 */
	public static function loadBytesFromChecksummedAsciiSafeString(
		$expected_header,
		#[SensitiveParameter]
		$string
	) {
		// Headers must be a constant length to prevent one type's header from
		// being a prefix of another type's header, leading to ambiguity.
		Core::ensureTrue(
			Core::ourStrlen($expected_header) === self::SERIALIZE_HEADER_BYTES,
			'Header must be 4 bytes.'
		);

		/* If you get an exception here when attempting to load from a file, first pass your
		   key to Encoding::trimTrailingWhitespace() to remove newline characters, etc.      */
		$bytes = Encoding::hexToBin($string);

		/* Make sure we have enough bytes to get the version header and checksum. */
		if (Core::ourStrlen($bytes) < self::SERIALIZE_HEADER_BYTES
			+ self::CHECKSUM_BYTE_SIZE
		)
		{
			throw new Ex\BadFormatException(
				'Encoded data is shorter than expected.'
			);
		}

		/* Grab the version header. */
		$actual_header = (string)Core::ourSubstr($bytes, 0,
			self::SERIALIZE_HEADER_BYTES);

		if ($actual_header !== $expected_header)
		{
			throw new Ex\BadFormatException(
				'Invalid header.'
			);
		}

		/* Grab the bytes that are part of the checksum. */
		$checked_bytes = (string)Core::ourSubstr(
			$bytes,
			0,
			Core::ourStrlen($bytes) - self::CHECKSUM_BYTE_SIZE
		);

		/* Grab the included checksum. */
		$checksum_a = (string)Core::ourSubstr(
			$bytes,
			Core::ourStrlen($bytes) - self::CHECKSUM_BYTE_SIZE,
			self::CHECKSUM_BYTE_SIZE
		);

		/* Re-compute the checksum. */
		$checksum_b = hash(self::CHECKSUM_HASH_ALGO, $checked_bytes, true);

		/* Check if the checksum matches. */
		if ( ! Core::hashEquals($checksum_a, $checksum_b))
		{
			throw new Ex\BadFormatException(
				"Data is corrupted, the checksum doesn't match"
			);
		}

		return (string)Core::ourSubstr(
			$bytes,
			self::SERIALIZE_HEADER_BYTES,
			Core::ourStrlen($bytes) - self::SERIALIZE_HEADER_BYTES
			- self::CHECKSUM_BYTE_SIZE
		);
	}

	/**
	 * Converts a hexadecimal string into a byte string without leaking
	 * information through side channels.
	 *
	 * @param string $hex_string
	 *
	 * @return string
	 * @psalm-suppress TypeDoesNotContainType
	 * @throws Ex\EnvironmentIsBrokenException
	 *
	 * @throws Ex\BadFormatException
	 */
	public static function hexToBin($hex_string)
	{
		$hex_pos = 0;
		$bin = '';
		$hex_len = Core::ourStrlen($hex_string);
		$state = 0;
		$c_acc = 0;

		while ($hex_pos < $hex_len)
		{
			$c = ord($hex_string[$hex_pos]);
			$c_num = $c ^ 48;
			$c_num0 = ($c_num - 10) >> 8;
			$c_alpha = ($c & ~32) - 55;
			$c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
			if (($c_num0 | $c_alpha0) === 0)
			{
				throw new Ex\BadFormatException(
					'Encoding::hexToBin() input is not a hex string.'
				);
			}
			$c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
			if ($state === 0)
			{
				$c_acc = $c_val * 16;
			}
			else
			{
				$bin .= pack('C', $c_acc | $c_val);
			}
			$state ^= 1;
			++$hex_pos;
		}

		return $bin;
	}
}
