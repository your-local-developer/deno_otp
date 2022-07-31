import { Otp, OtpAlgorithm } from "./otp.ts";
import type { OtpOptions } from "./otp.ts";

export interface TotpOptions {
  stepSize?: number;
  lastValidatedCode?: string;
}

export class Totp extends Otp {
  #stepSize = 30;
  public get stepSize(): number {
    return this.#stepSize;
  }

  #lastValidatedCode?: string;

  constructor(secret: Uint8Array | string, options?: TotpOptions & OtpOptions) {
    const defaultOptions: OtpOptions = {
      algorithm: OtpAlgorithm.SHA1,
      digits: 6,
      // TODO: Check RFC 6238 for the correct value and use it
      validationWindow: 1,
    };
    const normalizedOptions: OtpOptions = {
      ...defaultOptions,
      ...options,
    };
    super(secret, normalizedOptions);
    if (options?.stepSize !== undefined) this.#stepSize = options.stepSize;
    if (options?.lastValidatedCode !== undefined) {
      this.#lastValidatedCode = options.lastValidatedCode;
    }
  }

  /**
   * Generates the formatted Otp code and sets the last validated code.
   * Attention it only causes side effects if no moving factor is provided.
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * this.validate or this.validateCodeNoSideEffects should be used validate otp codes.
   * @param movingFactor
   */
  async generate(movingFactor?: number | undefined): Promise<string> {
    const calculatedMovingFactor = calculateMovingFactor(
      this.#stepSize,
      movingFactor,
    );

    const generatedCode = await this.generateCodeNoSideEffects(
      calculatedMovingFactor,
    );
    return generatedCode;
  }

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
    // TODO: Use validation window
    const calculatedMovingFactor = calculateMovingFactor(
      this.#stepSize,
      movingFactor,
    );
    const codeIsValid = await this.validateCodeNoSideEffects(
      code,
      calculatedMovingFactor,
    );
    // Ensure one time use
    if (codeIsValid) {
      // Check if the code is reused
      if (this.#lastValidatedCode === code) {
        return false;
      }

      // Set the last validated code to the generated code, so it is not reusable
      if (movingFactor === undefined) {
        this.#lastValidatedCode = await this.generateCodeNoSideEffects(
          calculatedMovingFactor,
        );
      }
    }
    return codeIsValid;
  }
}

function calculateMovingFactor(stepSize: number, seconds?: number): number {
  // Calculate moving factor and convert ms to seconds
  seconds = seconds !== undefined ? seconds : Math.floor(Date.now() / 1000);
  return Math.floor(seconds / stepSize);
}
