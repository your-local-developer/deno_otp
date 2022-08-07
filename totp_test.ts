import { encode } from "./deps.ts";
import { OtpAlgorithm, OtpOptions } from "./otp.ts";
import { assert, assertEquals, assertFalse } from "./test_deps.ts";
import { Totp, TotpOptions } from "./totp.ts";

// RFC6238 test vectors and tests
{
  const rfcSha1Secret = new TextEncoder().encode("12345678901234567890");
  const rfcSha1Base32Secret = encode(rfcSha1Secret);

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
        rfcSha1Secret,
        {
          digits: 8,
        },
      );
      assertEquals(
        (await totp.generate({ sideEffects: false, movingFactor: 59 }))
          .replaceAll(" ", ""),
        "94287082",
      );
      assertEquals(
        await (new Totp(rfcSha1Base32Secret, {
          digits: 8,
          algorithm: OtpAlgorithm.SHA1,
        })).generate({
          sideEffects: false,
          movingFactor: 59,
          formatCode: false,
        }),
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
          await (new Totp(rfcSha1Secret, {
            ...rfcOptions,
            algorithm: OtpAlgorithm.SHA1,
          })).generate(
            { movingFactor: seconds, sideEffects: false },
          ),
          rfcSha1Codes[index],
        );
        assertEquals(
          await (new Totp(rfcSha256Secret, {
            digits: 8,
            algorithm: OtpAlgorithm.SHA256,
          })).generate(
            { movingFactor: seconds, sideEffects: false },
          ),
          rfcSha256Codes[index],
        );
        assertEquals(
          await (new Totp(rfcSha512Secret, {
            digits: 8,
            algorithm: OtpAlgorithm.SHA512,
          })).generate(
            { movingFactor: seconds, sideEffects: false },
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
        rfcSha1Secret,
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
          rfcSha1Secret,
          {
            digits: 8,
          },
        );
        const time = 1111111109;
        const codeAt1111111109 = await totp.generate({
          movingFactor: time,
          sideEffects: false,
        });
        assert(
          await totp.validate(codeAt1111111109, {
            movingFactor: time,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assert(
          await totp.validate(codeAt1111111109, {
            movingFactor: time + 30,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt1111111109, {
            movingFactor: time + 31,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        // 1111111109 is at the end of a 60 second window
        assert(
          await totp.validate(codeAt1111111109, {
            movingFactor: time - 59,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt1111111109, {
            movingFactor: time - 60,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );

        // Test code at zero against a 30 second window with step size of one.
        const codeAt0 = await totp.generate({
          movingFactor: 0,
          sideEffects: false,
        });

        // Window 0
        assert(
          await totp.validate(codeAt0, {
            movingFactor: 29,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assert(
          await totp.validate(codeAt0, {
            movingFactor: 0,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );

        // Window 1
        assert(
          await totp.validate(codeAt0, {
            movingFactor: 59,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt0, {
            movingFactor: 60,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );

        // Window -1
        assert(
          await totp.validate(codeAt0, {
            movingFactor: -30,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt0, {
            movingFactor: -31,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
      }

      // Test with validationWindow set to 0 steps
      {
        const totp: Totp = new Totp(
          rfcSha1Secret,
          {
            digits: 8,
            validationWindow: 0,
          },
        );
        const time = 59;
        const codeAt59 = await totp.generate({
          movingFactor: time,
          sideEffects: false,
        });
        // Step is 30 seconds therefore the code is valid from 30 until 59 which is 30 time units
        assert(
          await totp.validate(codeAt59, {
            movingFactor: time,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt59, {
            movingFactor: time + 1,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assert(
          await totp.validate(codeAt59, {
            movingFactor: time - 29,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt59, {
            movingFactor: time - 30,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );

        const timeAt0 = 0;
        const codeAt0 = await totp.generate({
          movingFactor: timeAt0,
          sideEffects: false,
        });
        // Step is 30 seconds therefore the code is valid from 0 until 29 which is 30 time units
        assert(
          await totp.validate(codeAt0, {
            movingFactor: 0,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assert(
          await totp.validate(codeAt0, {
            movingFactor: 29,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt0, {
            movingFactor: 30,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt0, {
            movingFactor: -1,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
      }
      // Test with validationWindow set to 0 steps and a step size of 10 seconds
      // Basically the same as validateAgainsWindow = false
      {
        const totp: Totp = new Totp(
          rfcSha1Secret,
          {
            digits: 8,
            validationWindow: 0,
            stepSize: 10,
          },
        );
        const time = 0;
        const codeAt0 = await totp.generate({
          movingFactor: time,
          sideEffects: false,
        });
        // Step is 30 seconds therefore the code is valid from 0 until 10 which is 30 time units
        assert(
          await totp.validate(codeAt0, {
            movingFactor: time,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assert(
          await totp.validate(codeAt0, {
            movingFactor: time,
            sideEffects: false,
            validateAgainstWindow: false,
          }),
        );
        assert(
          await totp.validate(codeAt0, {
            movingFactor: time + 9,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assert(
          await totp.validate(codeAt0, {
            movingFactor: time + 9,
            sideEffects: false,
            validateAgainstWindow: false,
          }),
        );
        assertFalse(
          await totp.validate(codeAt0, {
            movingFactor: time + 10,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
        assertFalse(
          await totp.validate(codeAt0, {
            movingFactor: time - 1,
            sideEffects: false,
            validateAgainstWindow: true,
          }),
        );
      }
    },
  });

  Deno.test({
    name: "secondsUntilNextWindow() calculates the time until the next window.",
    fn(): void {
      const totp = new Totp(rfcSha1Secret);
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

Deno.test({
  name: "Simulate TOTP auth flow",
  async fn(): Promise<void> {
    const sharedSecret = Totp.generateBase32Secret();
    assert(Totp.validateSecret(sharedSecret));

    const serverTotp = new Totp(sharedSecret);

    const clientTotp = new Totp(sharedSecret);
    const clientCode = await clientTotp.generate();

    // One time use
    assert(await serverTotp.validate(clientCode));
    assertEquals(serverTotp.lastValidatedCode, clientCode.replaceAll(" ", ""));
    assertFalse(await serverTotp.validate(clientCode));
  },
});
