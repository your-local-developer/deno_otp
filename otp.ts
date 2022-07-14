import { crypto } from "./deps.ts";
import { bytesToUInt32BE, numberToBytes } from "./util.ts";

type OtpAlgorithms = "SHA-1" | "SHA-256" | "SHA-512";

type OtpOptions = {
  digits?: number;
  validationWindow?: number;
  algorithm?: OtpAlgorithms;
};

abstract class Otp {
  #secret: Uint8Array;

  #digits: number;
  public get digits(): number {
    return this.#digits;
  }

  #validationWindow: number;
  public get validationWindow(): number {
    return this.#validationWindow;
  }

  #algorithm: OtpAlgorithms;
  public get algorithm(): OtpAlgorithms {
    return this.#algorithm;
  }

  constructor(
    secret: Uint8Array | string,
    options?: OtpOptions,
  ) {
    if (typeof secret === "string") {
      secret = new TextEncoder().encode(secret);
    }
    this.#secret = secret;
    this.#digits = options?.digits ?? 6;
    this.#validationWindow = options?.validationWindow ?? 0;
    this.#algorithm = options?.algorithm ?? "SHA-1";
  }

  abstract validateSecret(secret: string, ignoreLenth: boolean): boolean;
  abstract generate(movingFactor?: number): Promise<number>;
  abstract validate(
    code: number | string,
    movingFactor?: number,
  ): Promise<boolean>;
  abstract formatCode(code: number): string;

  async #calculateHmacDigest(
    movingFactor: number,
  ): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
      "raw",
      this.#secret,
      { name: "HMAC", hash: this.#algorithm },
      false,
      ["sign"],
    );
    const bytesToSign = numberToBytes(movingFactor);
    const signed = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, bytesToSign),
    );
    return signed;
  }

  #shortenCode(digest: Uint8Array): number {
    let dynamicOffset = digest.at(digest.length - 1);
    if (!dynamicOffset) throw new Error("Digest not valid!");
    dynamicOffset &= 0xf;
    const codeBytes = digest.slice(dynamicOffset, dynamicOffset + 4);
    const code = bytesToUInt32BE(codeBytes);
    const fullCode = code & 0x7fffffff;
    const shortCode = fullCode % Math.pow(10, this.#digits);
    return shortCode;
  }

  protected async _generateCode(movingFactor: number): Promise<number> {
    return this.#shortenCode(
      await this.#calculateHmacDigest(movingFactor),
    );
  }

  protected async _validateCode(
    code: string | number,
    movingFactor: number,
  ): Promise<boolean> {
    return this.#codeToNumber(code) === await this._generateCode(movingFactor);
  }

  #codeToNumber(code: string | number): number {
    if (typeof code === "number") return code;
    const unifiedCode = code.replaceAll(" ", "");
    return parseInt(unifiedCode);
  }
}

export { Otp };
export type { OtpAlgorithms, OtpOptions };
