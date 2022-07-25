import { byteLength, decode } from "./deps.ts";
import {
  calculateHmacDigest,
  codeToNumber,
  extractCodeFromHmacShaDigest,
  trimWhitespaceAndAddBase32Padding,
} from "./util.ts";

export enum OtpAlgorithm {
  SHA1 = "SHA-1",
  SHA256 = "SHA-256",
  SHA512 = "SHA-512",
}

export interface OtpOptions {
  digits?: number;
  validationWindow?: number;
  algorithm?: OtpAlgorithm;
}

export abstract class Otp {
  #secret: Uint8Array;

  #digits = 6;
  public get digits(): number {
    return this.#digits;
  }

  #validationWindow = 0;
  public get validationWindow(): number {
    return this.#validationWindow;
  }

  #algorithm = OtpAlgorithm.SHA1;
  public get algorithm(): OtpAlgorithm {
    return this.#algorithm;
  }

  /**
   * @param secret Secret in unencoded Uint8Array or Base32 encoded string representation.
   * @param options Options to configure the number of digits, the size of the validation window and the algorithm.
   */
  constructor(
    secret: Uint8Array | string,
    options?: OtpOptions,
  ) {
    if (typeof secret === "string") {
      secret = decode(trimWhitespaceAndAddBase32Padding(secret));
    }
    this.#secret = secret;
    if (options?.digits) this.#digits = options.digits;
    if (options?.validationWindow) {
      this.#validationWindow = options.validationWindow;
    }
    if (options?.algorithm) this.#algorithm = options?.algorithm;
  }

  /**
   * Validates the Base32 encoded secret for it's characters set and possibly checks it length for the length requirement.
   * Regarding to the RFC HOTP and therefore TOTP require a secret with at least 16 bytes of length.
   * Google Authenticator ignored this requirement in the past and therefore a number of services generate secrets which are shorter than 16 bytes.
   * Therefore, the default behavior is to ignore the length.
   *
   * @param secret
   * @param ignoreLength
   */
  static validateSecret(secret: string, ignoreLength = true): boolean {
    let validated = false;
    try {
      const paddedSecret = trimWhitespaceAndAddBase32Padding(secret);
      if (decode(paddedSecret).length !== 0) {
        // Check for Base32 alphabet to exclude the "Extended Hex" Base 32 Alphabet (https://www.rfc-editor.org/rfc/rfc4648#section-7)
        let includesBadChar = false;
        for (const char of paddedSecret) {
          // TODO: Think of a cleaner way to do this
          switch (char) {
            case "A":
            case "B":
            case "C":
            case "D":
            case "E":
            case "F":
            case "G":
            case "H":
            case "I":
            case "J":
            case "K":
            case "L":
            case "M":
            case "N":
            case "O":
            case "P":
            case "Q":
            case "R":
            case "S":
            case "T":
            case "U":
            case "V":
            case "W":
            case "X":
            case "Y":
            case "Z":
            case "2":
            case "3":
            case "4":
            case "5":
            case "6":
            case "7":
            case "=":
              break;
            default:
              includesBadChar = true;
              break;
          }
        }
        validated = !includesBadChar;
        // Deal with secrets which are too short if secret is okay.
        if (validated && !ignoreLength) {
          const len = byteLength(paddedSecret);
          validated = (len >= 16) ? true : false;
        }
      }
      // deno-lint-ignore no-empty
    } catch (_) {}
    return validated;
  }

  abstract generate(movingFactor?: number): Promise<number>;

  async generateCodeNoSideEffects(movingFactor: number): Promise<number> {
    const digest = await calculateHmacDigest(
      movingFactor,
      this.#secret,
      this.#algorithm,
    );
    return extractCodeFromHmacShaDigest(
      digest,
      this.#digits,
    );
  }

  abstract validate(
    code: number | string,
    movingFactor?: number,
  ): Promise<boolean>;

  async validateCodeNoSideEffects(
    code: number | string,
    movingFactor: number,
  ): Promise<boolean> {
    return codeToNumber(code) === await this.generateCodeNoSideEffects(
      movingFactor,
    );
  }

  static formatCode(code: number): string {
    // TODO: Implement method
    throw new Error("Method not implemented.");
  }
}
