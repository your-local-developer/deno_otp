import { assertEquals } from "./test_deps.ts";
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
    assertEquals(await hotp.generate(0), "755 224");
    assertEquals(
      await (new Hotp(secretAsBase32))
        .generate(0),
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
          index,
        ),
        code,
      );
      assertEquals(
        await (new Hotp(rfcSecretBase32)).generate(index),
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

    // Does not increment when a moving factor is provided
    await hotp.generate(0);
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

    // Does not increment the counter when a moving factor is provided
    await hotp.validate(rfcCodeAt0, 0);
    assertEquals(hotp.counter, 1);
  },
});
