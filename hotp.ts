import { Otp, OtpAlgorithm } from "./otp.ts";
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

  // TODO: make formatting configurable and optional and side effects too
  /**
   * Generates the formatted Otp code and increments the internal counter.
   * Attention it only causes side effects if no moving factor is provided.
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * this.validate or this.validateCodeNoSideEffects should be used validate otp codes.
   * @param movingFactor
   */
  async generate(movingFactor?: number | undefined): Promise<string> {
    const generatedCode = await this.generateCodeNoSideEffects(
      movingFactor ?? this.#counter,
    );
    if (movingFactor === undefined) this.#counter++;
    return generatedCode;
  }

  // TODO: make side effects optional.
  /**
   * Validates the formatted otp code, ignoring spaces and increments the internal counter.
   * Attention it only causes side effects if no moving factor is provided.
   * @param code
   * @param movingFactor
   */
  async validate(
    code: string,
    movingFactor?: number | undefined,
  ): Promise<boolean> {
    let codeIsValid = false;
    const usedMovingFactor = movingFactor ?? this.#counter;
    for (let index = 0; index <= this.validationWindow; index++) {
      // Only reassign if code is not already valid
      codeIsValid = !codeIsValid
        ? await this.validateCodeNoSideEffects(
          code,
          usedMovingFactor + index,
        )
        : codeIsValid;
    }
    if (movingFactor === undefined && codeIsValid) this.#counter++;
    return codeIsValid;
  }
}
