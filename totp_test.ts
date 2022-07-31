import { assertEquals } from "./test_deps.ts";
import { Totp, TotpOptions } from "./totp.ts";
import { encode } from "./deps.ts";
import { OtpAlgorithm, OtpOptions } from "./otp.ts";

// RFC6238 test vectors and tests
{
  const rfcSecret = new TextEncoder().encode("12345678901234567890");
  const rfcBase32Secret = encode(rfcSecret);

  const rfcSha256Secret = new TextEncoder().encode(
    "12345678901234567890123456789012",
  );
  const rfcSha512Secret = new TextEncoder().encode(
    "1234567890123456789012345678901234567890123456789012345678901234",
  );

  const rfcSeconds = [
    59,
    1111111109,
    1111111111,
    1234567890,
    2000000000,
    20000000000,
  ];

  const rfcSha1Codes = [
    "9428 7082",
    "0708 1804",
    "1405 0471",
    "8900 5924",
    "6927 9037",
    "6535 3130",
  ];

  const rfcSha256Codes = [
    "4611 9246",
    "6808 4774",
    "6706 2674",
    "9181 9424",
    "9069 8825",
    "7773 7706",
  ];

  const rfcSha512Codes = [
    "9069 3936",
    "2509 1201",
    "9994 3326",
    "9344 1116",
    "3861 8901",
    "4786 3826",
  ];

  Deno.test({
    name: "Can be constructed with Uint8Array and string",
    async fn(): Promise<void> {
      const totp = new Totp(
        rfcSecret,
        {
          digits: 8,
        },
      );
      assertEquals((await totp.generate(59)).replaceAll(" ", ""), "94287082");
      assertEquals(
        (await (new Totp(rfcBase32Secret, {
          digits: 8,
          algorithm: OtpAlgorithm.SHA1,
        })).generate(59)).replaceAll(" ", ""),
        "94287082",
      );
    },
  });

  Deno.test({
    name: "generate() is RFC compliant",
    async fn(): Promise<void> {
      const rfcOptions: TotpOptions & OtpOptions = {
        digits: 8,
      };
      for (let index = 0; index < rfcSeconds.length; index++) {
        const seconds = rfcSeconds[index];
        assertEquals(
          await (new Totp(rfcSecret, {
            ...rfcOptions,
            algorithm: OtpAlgorithm.SHA1,
          })).generate(
            seconds,
          ),
          rfcSha1Codes[index],
        );
        assertEquals(
          await (new Totp(rfcSha256Secret, {
            digits: 8,
            algorithm: OtpAlgorithm.SHA256,
          })).generate(
            seconds,
          ),
          rfcSha256Codes[index],
        );
        assertEquals(
          await (new Totp(rfcSha512Secret, {
            digits: 8,
            algorithm: OtpAlgorithm.SHA512,
          })).generate(
            seconds,
          ),
          rfcSha512Codes[index],
        );
      }
    },
  });

  // TODO: Make this test more robust. It's time sensitive and can fail
  Deno.test({
    name: "validate() insures one time use",
    async fn(): Promise<void> {
      const totp: Totp = new Totp(
        rfcSecret,
        {
          digits: 8,
        },
      );
      const code = await totp.generate();
      assertEquals(await totp.validate(code), true);
      assertEquals(await totp.validate(code), false);
    },
  });
}
