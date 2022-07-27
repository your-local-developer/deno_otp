import { byteLength, decode } from "./deps.ts";
import {
  calculateHmacDigest,
  cleanUserInputFormat,
  extractCodeFromHmacShaDigest,
  isBase32,
  trimWhitespaceAndAddBase32Padding,
} from "./util.ts";

/** The values have to follow the naming convention of the WebCrypto API. */
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
    if (options?.digits !== undefined) this.#digits = options.digits;
    if (options?.validationWindow !== undefined) {
      this.#validationWindow = options.validationWindow;
    }
    if (options?.algorithm !== undefined) this.#algorithm = options?.algorithm;
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
        validated = isBase32(paddedSecret);
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

  /**
   * Generates the formatted otp code and causes side effects like incrementing a internal counter if no moving factor is provided.
   * Attention it only causes side effects if no moving factor is provided.
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * this.validate or this.validateCodeNoSideEffects should be used validate otp codes.
   * @param movingFactor
   */
  abstract generate(movingFactor?: number): Promise<string>;

  /**
   * Generates the formatted otp code.
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * this.validate or this.validateCodeNoSideEffects should be used validate otp codes.
   * @param movingFactor
   */
  async generateCodeNoSideEffects(movingFactor: number): Promise<string> {
    const digest = await calculateHmacDigest(
      movingFactor,
      this.#secret,
      this.#algorithm,
    );
    return Otp.formatCode(
      extractCodeFromHmacShaDigest(
        digest,
        this.#digits,
      ),
      this.#digits,
    );
  }

  /**
   * Validates the formatted otp code, ignoring spaces and causes side effects like incrementing a internal counter if no moving factor is provided.
   * Attention it only causes side effects if no moving factor is provided.
   * @param movingFactor
   */
  abstract validate(
    code: string,
    movingFactor?: number,
  ): Promise<boolean>;

  /**
   * Validates the formatted otp code, ignoring spaces.
   * @param movingFactor
   */
  async validateCodeNoSideEffects(
    code: string,
    movingFactor: number,
  ): Promise<boolean> {
    return cleanUserInputFormat(code) ===
      cleanUserInputFormat(await this.generateCodeNoSideEffects(movingFactor));
  }

  /**
   * Groups the digits of the code in groups of three if the amount of digits is dividable by three and groups of four if not.
   * Prepends zeros if the amount of digits is less than the digits parameter.
   * @param code
   * @param minimumDigits
   */
  static formatCode(code: number, minimumDigits: number): string {
    const formattedCharArray = [...code.toString()];
    const deltaDigits = minimumDigits - formattedCharArray.length;
    const zeroFilledArray = [
      ..."0".repeat(deltaDigits > 0 ? deltaDigits : 0),
      ...formattedCharArray,
    ];
    const grouping = zeroFilledArray.length % 3 === 0 ? 3 : 4;
    // skip index 0 and last char
    return zeroFilledArray.map((v, i, a) =>
      v = (i !== (a.length - 1) && (i + 1) % grouping === 0) ? `${v} ` : v
    ).join("");
  }
}
