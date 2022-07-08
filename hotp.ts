import { decode } from "./deps.ts";
import { Otp } from "./otp.ts";
import type { OtpOptions } from "./otp.ts";

type HotpOptions = OtpOptions & {
  counter?: number;
};

class Hotp extends Otp {
  #counter: number;

  public get counter(): number {
    return this.#counter;
  }

  constructor(secret: Uint8Array | string, options?: HotpOptions) {
    const defaultCounter = 0;
    const defaultOptions: HotpOptions = {
      counter: defaultCounter,
      algorithm: "SHA-1",
      digits: 6,
      validationWindow: 30,
    };
    const normalizedOptions = {
      ...defaultOptions,
      ...options,
    };
    super(secret, normalizedOptions as OtpOptions);
    this.#counter = normalizedOptions.counter ?? defaultCounter;
  }

  static fromBase32Secret(base32Secret: string, options?: HotpOptions): Hotp {
    return new Hotp(decode(base32Secret), options);
  }

  validateSecret(secret: string, ignoreLenth: boolean): boolean {
    throw new Error("Method not implemented.");
  }

  async generate(movingFactor?: number | undefined): Promise<number> {
    const generatedCode = await this._generateCode(
      movingFactor ?? this.#counter,
    );
    if (movingFactor === undefined) this.#counter++;
    return generatedCode;
  }

  async validate(
    code: string | number,
    movingFactor?: number | undefined,
  ): Promise<boolean> {
    const codeIsValid = await this._validateCode(
      code,
      movingFactor ?? this.#counter,
    );
    if (movingFactor === undefined && codeIsValid) this.#counter++;
    return codeIsValid;
  }

  formatCode(code: number): string {
    throw new Error("Method not implemented.");
  }
}

export { Hotp };
