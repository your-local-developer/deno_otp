import { assert, assertEquals, assertFalse } from "./test_deps.ts";
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
      assert(await totp.validate(code));
      assertFalse(await totp.validate(code));
    },
  });

  // Write deno test for validate() against a time window
  Deno.test({
    name: "validate() validates against a time window",
    async fn(): Promise<void> {
      // Test with validationWindow set to 1 step
      {
        const totp: Totp = new Totp(
          rfcSecret,
          {
            digits: 8,
          },
        );
        const time = 1111111109;
        const codeAt1111111109 = await totp.generate(time);
        assert(await totp.validate(codeAt1111111109, time));
        assert(await totp.validate(codeAt1111111109, time + 30));
        assertFalse(await totp.validate(codeAt1111111109, time + 31));
        // 1111111109 is at the end of a 60 second window
        assert(await totp.validate(codeAt1111111109, time - 59));
        assertFalse(await totp.validate(codeAt1111111109, time - 60));

        // Test code at zero against a 30 second window with step size of one.
        const codeAt0 = await totp.generate(0);

        // Window 0
        assert(await totp.validate(codeAt0, 29));
        assert(await totp.validate(codeAt0, 0));

        // Window 1
        assert(await totp.validate(codeAt0, 59));
        assertFalse(await totp.validate(codeAt0, 60));

        // Window -1
        assert(await totp.validate(codeAt0, -30));
        assertFalse(await totp.validate(codeAt0, -31));
      }

      // Test with validationWindow set to 0 steps
      {
        const totp: Totp = new Totp(
          rfcSecret,
          {
            digits: 8,
            validationWindow: 0,
          },
        );
        const time = 59;
        const codeAt59 = await totp.generate(time);
        // Step is 30 seconds therefore the code is valid from 30 until 59 which is 30 time units
        assert(await totp.validate(codeAt59, time));
        assertFalse(await totp.validate(codeAt59, time + 1));
        assert(await totp.validate(codeAt59, time - 29));
        assertFalse(await totp.validate(codeAt59, time - 30));

        const timeAt0 = 0;
        const codeAt0 = await totp.generate(timeAt0);
        // Step is 30 seconds therefore the code is valid from 0 until 29 which is 30 time units
        assert(await totp.validate(codeAt0, 0));
        assert(await totp.validate(codeAt0, 29));
        assertFalse(await totp.validate(codeAt0, 30));
        assertFalse(await totp.validate(codeAt0, -1));
      }
      // Test with validationWindow set to 0 steps and a step size of 10 seconds
      {
        const totp: Totp = new Totp(
          rfcSecret,
          {
            digits: 8,
            validationWindow: 0,
            stepSize: 10,
          },
        );
        const time = 0;
        const codeAt0 = await totp.generate(time);
        // Step is 30 seconds therefore the code is valid from 0 until 10 which is 30 time units
        assert(await totp.validate(codeAt0, time));
        assert(await totp.validate(codeAt0, time + 9));
        assertFalse(await totp.validate(codeAt0, time + 10));
        assertFalse(await totp.validate(codeAt0, time - 1));
      }
    },
  });

  Deno.test({
    name: "secondsUntilNextWindow() calculates the time until the next window.",
    fn(): void {
      const totp = new Totp(rfcSecret);
      assertEquals(Totp.secondsUntilNextWindow(30, 0), 30);
      assertEquals(Totp.secondsUntilNextWindow(30, 45), 15);

      assertEquals(totp.secondsUntilNextWindow(0), 30);
      assertEquals(totp.secondsUntilNextWindow(29), 1);
      assertEquals(totp.secondsUntilNextWindow(30), 30);

      assertEquals(
        totp.secondsUntilNextWindow(),
        30 - Math.round(Math.floor(Date.now() / 1000) % 30),
      );
    },
  });
}
