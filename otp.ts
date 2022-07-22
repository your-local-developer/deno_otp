import { decode } from "./deps.ts";
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

  // TODO: Add comment
  /**
   * @param secret Secret in unencoded Uint8Array or Base32 encoded string representation.
   * @param options
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

  static validateSecret(secret: string, ignoreLength: boolean): boolean {
    // TODO: Implement method, use byteLength
    throw new Error("Method not implemented.");
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
