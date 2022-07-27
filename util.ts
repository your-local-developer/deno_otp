import { OtpAlgorithm } from "./otp.ts";

/**
 * Converts a 64 bit number to a Uint8Array representing its bytes.
 * Standard length is 8 bytes.
 *
 * @param value Number to convert
 * @param byteArrayLen Length of the Uint8Array or false if the Uint8Array should only be of minimal length.
 * @throws Errors if the value exceeds 64 bit
 */
export function numberToBytes(
  value: number,
  byteArrayLen: number | false = 8,
): Uint8Array {
  // Fill the Array with bytes
  const preparedArray = new Array<number>();
  do {
    const currentBytes = value & 0xff;
    preparedArray.unshift(currentBytes);
    value = (value - currentBytes) / 256;
  } while (value !== 0);
  // If byteArrayLen is false, use the needed length
  byteArrayLen = byteArrayLen === false ? preparedArray.length : byteArrayLen;
  // Prepare a Uint8Array for being filled. The "WebCrypto API seems to need an array with 8 bytes.
  const byteArr = new Uint8Array(byteArrayLen);
  const fillOffset = byteArrayLen - preparedArray.length;
  if (fillOffset < 0) {
    throw Error(
      `The amount of bytes (${preparedArray.length}) of the provided value exceeds the limit of the arraylength (${byteArrayLen}) you provided!`,
    );
  }
  byteArr.set(preparedArray, fillOffset);

  return byteArr;
}

/**
 * Converts bytes to a unsigned 32 bit integer.
 *
 * @param bytes Bytes to convert
 */
export function bytesToUInt32BE(bytes: Uint8Array): number {
  // TODO: Maybe add useLastBytes?
  return new DataView(bytes.buffer).getUint32(0);
}

/**
 * Converts a code as string to a number while trimming it's whitespace.
 *
 * @param code Code to convert
 */
export function codeToNumber(code: string | number): number {
  if (typeof code === "number") return code;
  const unifiedCode = cleanUserInputFormat(code);
  return parseInt(unifiedCode);
}

// TODO: Make it comply with the deno style guide
/**
 * Calculates the HMAC digest based on the moving factor.
 *
 * @param movingFactor Moving factor to sign
 * @param secret Secret which is used as key
 * @param algorithm Algorithm used for signing
 * @throws Errors if the movingFactor exceeds 64 bit
 */
export async function calculateHmacDigest(
  movingFactor: number,
  secret: Uint8Array,
  algorithm: OtpAlgorithm | AlgorithmIdentifier,
): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );
  const bytesToSign = numberToBytes(movingFactor);
  const signedDigest = new Uint8Array(
    await crypto.subtle.sign("HMAC", hmacKey, bytesToSign),
  );
  return signedDigest;
}

/**
 * Extracts an n-digit integer from the given HMAC-SHA digest using it's last byte as offset and the provided digits to limit it length.
 *
 * @param digest The digest to extract from
 * @param digits The maximum amount of digits the result can have
 * @throws Errors if the last digit of the Uint8Array is undefined
 */
export function extractCodeFromHmacShaDigest(
  digest: Uint8Array,
  digits: number,
): number {
  let dynamicOffset = digest.at(digest.length - 1);
  if (dynamicOffset === undefined) throw new Error("Digest not valid!");
  // Limit the offset from 0 to 15 because SHA-1 produces a 20 byte digest
  dynamicOffset &= 0xf;
  // Get 32 bit from the digest
  const codeBytes = digest.slice(dynamicOffset, dynamicOffset + 4);
  const digestAsInt = bytesToUInt32BE(codeBytes);
  // Shorten the code to 32 bit
  const fullCode = digestAsInt & 0x7fffffff;
  const shortCode = fullCode % Math.pow(10, digits);
  return shortCode;
}

// TODO: Rename to cleanUserInputFormatAndAddBase32Padding
/**
 * Adds padding and removes whitespace from the given Base32 secret and turns its characters to uppercase to prepare it for decoding.
 * @param secret
 */
export function trimWhitespaceAndAddBase32Padding(secret: string): string {
  secret = cleanUserInputFormat(secret);
  // Base32 has to be a multiple of 8
  let amountOfMissingPadding = 8 - (secret.length % 8);
  // Returns 8 if no missing padding is required, because it's 8 to the next multiple of 8
  amountOfMissingPadding = amountOfMissingPadding === 8
    ? 0
    : amountOfMissingPadding;
  // `=` is used for Base32 padding
  secret = secret.padEnd(secret.length + amountOfMissingPadding, "=");
  return secret;
}

/**
 * Removes whitespace and turns characters to uppercase
 * @param input
 */
export function cleanUserInputFormat(input: string): string {
  return input.replaceAll(" ", "").toUpperCase();
}

/**
 * Check the string to only be Base32 alphabet not the "Extended Hex" Base 32 Alphabet (https://www.rfc-editor.org/rfc/rfc4648#section-7)
 * @param b32
 */
export function isBase32(b32: string): boolean {
  let includesBadChar = false;
  for (const char of b32) {
    const charCode = char.charCodeAt(0);
    // Check if char is not in the Base32 alphabet
    if (
      // Invert the truth check
      !(
        // Check if charCode is not NaN
        !isNaN(charCode) && (
          // Is in range 2 to 7
          charCode >= 50 && charCode <= 55 ||
          // Is =
          charCode === 61 ||
          // Is in range A to Z
          charCode >= 65 && charCode <= 90
        )
      )
    ) {
      includesBadChar = true;
      break;
    }
  }
  return !includesBadChar;
}
