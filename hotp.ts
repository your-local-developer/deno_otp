import { GenerateOptions, Otp, OtpAlgorithm, ValidateOptions } from "./otp.ts";
import type { OtpOptions } from "./otp.ts";

export interface HotpOptions {
  counter?: number;
}

export class Hotp extends Otp {
  #counter = 0;
  public get counter(): number {
    return this.#counter;
  }

  public resetCounter(counter = 0) {
    this.#counter = counter;
  }

  constructor(secret: Uint8Array | string, options?: HotpOptions & OtpOptions) {
    const defaultOptions: OtpOptions = {
      algorithm: OtpAlgorithm.SHA1,
      digits: 6,
      // TODO: Find a good validation window or introduce a resync mechanism
      // Plausible look ahead window https://www.protectimus.com/blog/hotp-algorithm/
      validationWindow: 100,
    };
    const normalizedOptions: OtpOptions = {
      ...defaultOptions,
      ...options,
    };
    super(secret, normalizedOptions);
    if (options?.counter !== undefined) this.#counter = options.counter;
  }

  /**
   * Generates the formatted Otp code and increments the internal counter if if options.sideEffects is set to true (default).
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * Setting a custom grouping or disabling the formatting is possible.
   * this.validate should be used to validate otp codes.
   * @param options
   */
  async generate(options?: GenerateOptions): Promise<string> {
    const generatedCode = await this.generateCodeNoSideEffects(
      options?.movingFactor ?? this.#counter,
      options?.formatCode ?? true,
      {
        grouping: options?.grouping,
      },
    );
    if (options?.sideEffects ?? true) this.#counter++;
    return generatedCode;
  }

  /**
   * Validates the formatted otp code against a look ahead window, ignoring spaces and increments the internal counter if options.sideEffects is set to true (default).
   * @param code
   * @param options
   */
  async validate(code: string, options?: ValidateOptions): Promise<boolean> {
    let codeIsValid = false;
    const usedMovingFactor = options?.movingFactor ?? this.#counter;
    // Set upper bound to zero to make the for loop run one time only
    const upperBound = options?.validateAgainstWindow ?? true
      ? this.validationWindow
      : 0;
    for (let index = 0; index <= upperBound; index++) {
      // Only reassign if code is not already valid
      codeIsValid = !codeIsValid
        ? await this.validateCodeNoSideEffects(code, usedMovingFactor + index)
        : codeIsValid;
    }
    if ((options?.sideEffects ?? true) && codeIsValid) this.#counter++;
    return codeIsValid;
  }
}
