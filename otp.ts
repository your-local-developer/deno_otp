import { byteLength, decode, encode } from "./deps.ts";
import {
  calculateHmacDigest,
  cleanUserInputFormat,
  cleanUserInputFormatAndAddBase32Padding,
  extractCodeFromHmacShaDigest,
  isBase32,
} from "./util.ts";

/** The values have to follow the naming convention of the WebCrypto API. */
export enum OtpAlgorithm {
  SHA1 = "SHA-1",
  SHA256 = "SHA-256",
  SHA512 = "SHA-512",
}

export interface GenerateSecretOptions {
  byteLength?: number;
  allowShortSecret?: boolean;
}

export interface FormatCodeOptions {
  grouping?: number;
}

export interface GenerateOptions {
  movingFactor?: number;
  formatCode?: boolean;
  grouping?: number;
  sideEffects: boolean;
}

export interface GenerateCodeNoSideEffects {
  grouping?: number;
}

export interface ValidateOptions {
  movingFactor?: number;
  sideEffects: boolean;
  validateAgainstWindow: boolean;
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
      secret = decode(cleanUserInputFormatAndAddBase32Padding(secret));
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
      const paddedSecret = cleanUserInputFormatAndAddBase32Padding(secret);
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
   * Generates the formatted otp code and causes side effects like incrementing a internal counter if options.sideEffects is set to true (default).
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * Setting a custom grouping or disabling the formatting is possible.
   * this.validate should be used to validate otp codes.
   * @param options
   */
  abstract generate(options?: GenerateOptions): Promise<string>;

  /**
   * Generates the formatted otp code.
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * this.validate or this.validateCodeNoSideEffects should be used validate otp codes.
   * @param movingFactor
   */
  protected async generateCodeNoSideEffects(
    movingFactor: number,
    formatCode: boolean,
    options?: GenerateCodeNoSideEffects,
  ): Promise<string> {
    const extractedCode = extractCodeFromHmacShaDigest(
      await calculateHmacDigest(
        movingFactor,
        this.#secret,
        this.#algorithm,
      ),
      this.#digits,
    );
    let grouping = options?.grouping;
    if (!formatCode) grouping = 0;
    return Otp.formatCode(
      extractedCode,
      this.#digits,
      {
        grouping,
      },
    );
  }

  /**
   * Validates the formatted otp code, ignoring spaces and causes side effects like incrementing a internal counter if options.sideEffects is set to true (default).
   * @param options
   */
  abstract validate(
    code: string,
    options?: ValidateOptions,
  ): Promise<boolean>;

  /**
   * Validates the formatted otp code, ignoring spaces.
   * @param movingFactor
   */
  protected async validateCodeNoSideEffects(
    code: string,
    movingFactor: number,
  ): Promise<boolean> {
    return cleanUserInputFormat(code) ===
      cleanUserInputFormat(
        await this.generateCodeNoSideEffects(movingFactor, false),
      );
  }

  /**
   * Groups the digits of the code in groups of three if the amount of digits is dividable by three and groups of four if not.
   * Prepends zeros if the amount of digits is less than the digits parameter.
   * @param code
   * @param minimumDigits
   */
  static formatCode(
    code: number | string,
    minimumDigits: number,
    options?: FormatCodeOptions,
  ): string {
    const formattedCharArray = [
      ...cleanUserInputFormat(code.toString()),
    ];
    const deltaDigits = minimumDigits - formattedCharArray.length;
    const zeroFilledArray = [
      ..."0".repeat(deltaDigits > 0 ? deltaDigits : 0),
      ...formattedCharArray,
    ];
    const grouping = options?.grouping !== undefined
      ? options.grouping
      : zeroFilledArray.length % 3 === 0
      ? 3
      : 4;
    // skip index 0 and last char
    return zeroFilledArray.map((v, i, a) =>
      v = (i !== (a.length - 1) && (i + 1) % grouping === 0) ? `${v} ` : v
    ).join("");
  }

  /**
   * Generates a 20 byte random secret with the given length using the secure WebCryptoApi.
   * The secret should be at least 16 bytes long but per [HOTP RFC](https://www.rfc-editor.org/rfc/rfc4226#section-4) the recommended length is at least 20 bytes.
   * @param options
   * @throws RangeError if the optional length is less than 16 bytes and allowedShortSecret is not set to true.
   */
  static generateSecret(options?: GenerateSecretOptions): Uint8Array {
    const notOptionalOptions = {
      ...options,
    };
    if (notOptionalOptions.byteLength === undefined) {
      notOptionalOptions.byteLength = 20;
    }
    if (notOptionalOptions.allowShortSecret === undefined) {
      notOptionalOptions.allowShortSecret = false;
    }
    if (notOptionalOptions.byteLength < 16 && !options?.allowShortSecret) {
      throw new RangeError("Secret must be at least 16 bytes long.");
    } else {
      return crypto.getRandomValues(
        new Uint8Array(notOptionalOptions.byteLength),
      );
    }
  }

  /**
   * Generates a 20 byte random Base32 encoded secret with the given length using the secure WebCryptoApi.
   * The secret should be at least 16 bytes long but per [HOTP RFC](https://www.rfc-editor.org/rfc/rfc4226#section-4) the recommended length is at least 20 bytes.
   * @param options
   * @throws RangeError if options.length is less than 16 bytes and options.allowedShortSecret is not set to true.
   */
  static generateBase32Secret(options?: GenerateSecretOptions): string {
    return encode(Otp.generateSecret(options));
  }
}
