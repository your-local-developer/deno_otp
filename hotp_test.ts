import { assert, assertEquals, assertFalse } from "./test_deps.ts";
import { Hotp } from "./hotp.ts";
import { encode } from "./deps.ts";

Deno.test({
  name: "Can be constructed with Uint8Array and base32 string",
  async fn(): Promise<void> {
    const secretAsArray = (new TextEncoder()).encode("12345678901234567890");
    const secretAsBase32 = encode(secretAsArray);
    const hotp: Hotp = new Hotp(
      secretAsArray,
    );
    assertEquals(
      await hotp.generate({
        movingFactor: 0,
        sideEffects: false,
      }),
      "755 224",
    );
    assertEquals(
      await (new Hotp(secretAsBase32))
        .generate({
          movingFactor: 0,
          sideEffects: false,
        }),
      "755 224",
    );
  },
});

Deno.test({
  name: "generate() is RFC compliant",
  async fn(): Promise<void> {
    const rfcCodes = [
      "755 224",
      "287 082",
      "359 152",
      "969 429",
      "338 314",
      "254 676",
      "287 922",
      "162 583",
      "399 871",
      "520 489",
    ];
    const rfcSecretString = "12345678901234567890";
    const rfcSecretBase32 = encode(new TextEncoder().encode(rfcSecretString));

    for (let index = 0; index < rfcCodes.length; index++) {
      const code = rfcCodes[index];
      assertEquals(
        await (new Hotp((new TextEncoder()).encode(rfcSecretString))).generate(
          {
            movingFactor: index,
            sideEffects: false,
            grouping: 3,
          },
        ),
        code,
      );
      assertEquals(
        await (new Hotp(rfcSecretBase32)).generate({
          movingFactor: index,
          sideEffects: false,
          grouping: 3,
        }),
        code,
      );
    }
  },
});

Deno.test({
  name: "generate() increments the counter",
  async fn(): Promise<void> {
    const rfcSecretString = "12345678901234567890";
    const hotp = new Hotp((new TextEncoder()).encode(rfcSecretString));

    // Increments counter if the internal counter is used
    assertEquals(hotp.counter, 0);
    await hotp.generate();
    assertEquals(hotp.counter, 1);

    // Does not increment the counter when side effects is set to false
    // TODO: Document that the code will not change!
    await hotp.generate({
      sideEffects: false,
    });
    assertEquals(hotp.counter, 1);
  },
});

Deno.test({
  name: "validate() increments the counter",
  async fn(): Promise<void> {
    const rfcCodeAt0 = "755 224";
    const rfcSecretString = "12345678901234567890";
    const hotp = new Hotp((new TextEncoder()).encode(rfcSecretString));

    // Increments counter if the internal counter is used
    assertEquals(hotp.counter, 0);
    await hotp.validate(rfcCodeAt0);
    assertEquals(hotp.counter, 1);

    // Does not increment the counter when side effects is set to false
    await hotp.validate(rfcCodeAt0, {
      sideEffects: false,
      validateAgainstWindow: false,
    });
    assertEquals(hotp.counter, 1);
  },
});

Deno.test({
  name: "validate() validates against a look ahead window",
  async fn(): Promise<void> {
    const rfcSecretString = "12345678901234567890";
    // Test with validationWindow set to 100 steps
    {
      const hotp = new Hotp((new TextEncoder()).encode(rfcSecretString));

      // Timer is not incremented when side effects are disabled
      // The counter is incremented after the code is validated
      const codeAt0 = await hotp.generate({
        movingFactor: 0,
        sideEffects: false,
      });
      assert(
        await hotp.validate(codeAt0, {
          sideEffects: false,
          validateAgainstWindow: true,
        }),
      );

      const codeAtDelta100 = await hotp.generate({
        movingFactor: 100,
        sideEffects: false,
      });
      assert(
        await hotp.validate(codeAtDelta100, {
          sideEffects: false,
          validateAgainstWindow: true,
        }),
      );

      const codeAtDelta101 = await hotp.generate({
        movingFactor: 101,
        sideEffects: false,
      });
      assertFalse(
        await hotp.validate(codeAtDelta101, {
          sideEffects: false,
          validateAgainstWindow: true,
        }),
      );
    }

    // Test with validationWindow set to 0 steps
    {
      const hotp = new Hotp((new TextEncoder()).encode(rfcSecretString), {
        validationWindow: 0,
      });

      // Timer is not incremented when side effects are disabled
      // The counter is incremented after the code is validated
      const codeAt0 = await hotp.generate({
        movingFactor: 0,
        sideEffects: false,
      });
      assert(
        await hotp.validate(codeAt0, {
          sideEffects: false,
          validateAgainstWindow: true,
        }),
      );

      const codeAtDelta1 = await hotp.generate({
        movingFactor: 1,
        sideEffects: false,
      });
      assertFalse(
        await hotp.validate(codeAtDelta1, {
          sideEffects: false,
          validateAgainstWindow: true,
        }),
      );
    }

    {
      // Validate against a window of turned off validates only a single code
      const hotp = new Hotp((new TextEncoder()).encode(rfcSecretString));
      const codeAt0 = await hotp.generate({
        movingFactor: 0,
        sideEffects: false,
      });
      assertEquals(hotp.counter, 0);
      assert(
        await hotp.validate(codeAt0, {
          sideEffects: false,
          validateAgainstWindow: false,
        }),
      );
      const codeAt1 = await hotp.generate({
        movingFactor: 1,
        sideEffects: false,
      });
      // Hotp with the counter set to zero is not allowed to validate against a code generated for a counter of 1
      assert(codeAt0 !== codeAt1);
      // Internal counter is zero or a moving factor of 0 is set
      assertEquals(hotp.counter, 0);
      assertFalse(
        await hotp.validate(codeAt1, {
          sideEffects: false,
          validateAgainstWindow: false,
        }),
      );
      assertFalse(
        await hotp.validate(codeAt1, {
          sideEffects: false,
          movingFactor: 0,
          validateAgainstWindow: false,
        }),
      );
      // Should be able to validate against a code generated for a counter of 1
      assert(
        await hotp.validate(codeAt1, {
          sideEffects: false,
          movingFactor: 1,
          validateAgainstWindow: false,
        }),
      );
      // To high
      assertFalse(
        await hotp.validate(codeAt1, {
          sideEffects: false,
          movingFactor: 2,
          validateAgainstWindow: false,
        }),
      );
    }
  },
});

Deno.test({
  name: "Simulate HOTP auth flow",
  async fn(): Promise<void> {
    const sharedSecret = Hotp.generateBase32Secret();
    assert(Hotp.validateSecret(sharedSecret));

    const serverHotp = new Hotp(sharedSecret);

    const clientHotp = new Hotp(sharedSecret);
    const clientCode = await clientHotp.generate();

    // Test one time use
    assert(await serverHotp.validate(clientCode));
    assertFalse(await serverHotp.validate(clientCode));

    clientHotp.resetCounter(clientHotp.counter + 10);

    assert(await serverHotp.validate(await clientHotp.generate()));
  },
});
