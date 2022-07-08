import { Buffer } from "./deps.ts";

/**
 * Converts a 64 Bit number to a Uint8Array representing its bytes.
 *
 * @param value the number to convert
 * @param byteArrayLen length of the array
 * @returns the byte representation
 * @throws an error if the value exceeds 64 bit
 */
export function numberToBytes(value: number, byteArrayLen = 8): Uint8Array {
  const preparedArray = new Array<number>();
  while (value !== 0) {
    const bytesAtIndex = value & 0xff;
    preparedArray.unshift(bytesAtIndex);
    value = (value - bytesAtIndex) / 256;
  }
  const byteArr = new Uint8Array(byteArrayLen);
  const fillOffset = byteArrayLen - preparedArray.length;
  if (fillOffset < 0) throw Error("The provided value is bigger than 64 Bit");
  byteArr.set(preparedArray, fillOffset);

  return byteArr;
}

/**
 * Converts bytes to a unsigned 32 bit integer.
 *
 * @param bytes the bytes to convert
 * @returns a 32 Uint representation of the given bytes
 */
export function bytesToUInt32BE(bytes: Uint8Array): number {
  const buffer = Buffer.from(bytes);
  return buffer.readUInt32BE(0);
}
