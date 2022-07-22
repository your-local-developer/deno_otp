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

  constructor(secret: Uint8Array | string, options?: HotpOptions & OtpOptions) {
    const defaultOptions: OtpOptions = {
      algorithm: OtpAlgorithm.SHA1,
      digits: 6,
      validationWindow: 30,
    };
    const normalizedOptions: OtpOptions = {
      ...defaultOptions,
      ...options,
    };
    super(secret, normalizedOptions);
    if (options?.counter) this.#counter = options.counter;
  }

  async generate(movingFactor?: number | undefined): Promise<number> {
    const generatedCode = await this.generateCodeNoSideEffects(
      movingFactor ?? this.#counter,
    );
    if (movingFactor === undefined) this.#counter++;
    return generatedCode;
  }

  async validate(
    code: string | number,
    movingFactor?: number | undefined,
  ): Promise<boolean> {
    const codeIsValid = await this.validateCodeNoSideEffects(
      code,
      movingFactor ?? this.#counter,
    );
    if (movingFactor === undefined && codeIsValid) this.#counter++;
    return codeIsValid;
  }
}
