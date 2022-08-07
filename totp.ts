import type { OtpOptions } from "./otp.ts";
import { GenerateOptions, Otp, OtpAlgorithm, ValidateOptions } from "./otp.ts";
import { cleanUserInputFormat } from "./util.ts";

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
  public get lastValidatedCode(): string | undefined {
    return this.#lastValidatedCode;
  }

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
   * Generates the formatted Otp code.
   * The code is formatted in a grouping of three digits followed by a space if the amount of digits is dividable by three and a grouping of four otherwise.
   * Setting a custom grouping or disabling the formatting is possible.
   * this.validate should be used to validate otp codes.
   * @param options
   */
  async generate(options?: GenerateOptions): Promise<string> {
    // INFO: Side effects is not used
    const calculatedMovingFactor = calculateMovingFactor(
      this.#stepSize,
      options?.movingFactor,
    );

    const generatedCode = await this.generateCodeNoSideEffects(
      calculatedMovingFactor,
      options?.formatCode ?? true,
      {
        grouping: options?.grouping,
      },
    );
    return generatedCode;
  }

  /**
   * Validates the formatted otp code, ignoring spaces and increments the internal counter.
   * Attention it only causes side effects if no moving factor is provided.
   * @param code
   * @param options
   */
  async validate(
    code: string,
    options?: ValidateOptions,
  ): Promise<boolean> {
    const calculatedMovingFactor = calculateMovingFactor(
      this.#stepSize,
      options?.movingFactor,
    );
    let codeIsValid = false;
    const validationWindow = options?.validateAgainstWindow
      ? this.validationWindow
      : 0;
    for (
      let attempt = -validationWindow;
      attempt <= validationWindow;
      attempt++
    ) {
      const movingFactorAndAttempt = calculatedMovingFactor + attempt;

      if (movingFactorAndAttempt < 0) {
        continue;
      }

      codeIsValid = !codeIsValid
        ? await this.validateCodeNoSideEffects(
          code,
          movingFactorAndAttempt,
        )
        : codeIsValid;

      if (codeIsValid) {
        // Get out of the loop
        break;
      }
    }
    // Ensure one time use
    if (codeIsValid) {
      // Check if the code is reused
      if (
        this.#lastValidatedCode &&
        this.#lastValidatedCode === cleanUserInputFormat(code)
      ) {
        return false;
      }

      // Set the last validated code to the generated code, so it is not reusable
      if (options?.sideEffects ?? true) {
        this.#lastValidatedCode = await this.generateCodeNoSideEffects(
          calculatedMovingFactor,
          false,
        );
      }
    }
    return codeIsValid;
  }

  secondsUntilNextWindow(seconds?: number): number {
    return Totp.secondsUntilNextWindow(this.#stepSize, seconds);
  }

  static secondsUntilNextWindow(stepSize: number, seconds?: number): number {
    return stepSize -
      Math.floor(
          seconds ?? (Date.now() / 1000),
        ) % stepSize;
  }
}

function calculateMovingFactor(stepSize: number, seconds?: number): number {
  // Calculate moving factor and convert ms to seconds
  seconds = seconds !== undefined
    ? Math.floor(seconds)
    : Math.floor(Date.now() / 1000);
  return Math.floor(seconds / stepSize);
}
