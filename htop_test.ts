import { assertEquals, encode } from "./test_deps.ts";
import { Hotp } from "./hotp.ts";

Deno.test({
  name: "Can be constructed with Uint8Array and string",
  async fn(): Promise<void> {
    const hotp: Hotp = new Hotp(
      Uint8Array.from([
        49,
        50,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        48,
        49,
        50,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        48,
      ]),
    );
    assertEquals(await hotp.generate(0), 755224);
    assertEquals(await (new Hotp("12345678901234567890")).generate(0), 755224);
  },
});

Deno.test({
  name: "generate() is RFC compliant",
  async fn(): Promise<void> {
    const rfcCodes = [
      755224,
      287082,
      359152,
      969429,
      338314,
      254676,
      287922,
      162583,
      399871,
      520489,
    ];
    const rfcSecretString = "12345678901234567890";
    const rfcSecretBase32 = encode(new TextEncoder().encode(rfcSecretString));

    for (let index = 0; index < rfcCodes.length; index++) {
      const code = rfcCodes[index];
      assertEquals(await (new Hotp(rfcSecretString)).generate(index), code);
      assertEquals(
        await (Hotp.fromBase32Secret(rfcSecretBase32)).generate(index),
        code,
      );
    }
  },
});

Deno.test({
  name: "generate() increments the counter",
  async fn(): Promise<void> {
    const rfcSecretString = "12345678901234567890";
    const hotp = new Hotp(rfcSecretString);

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
    const rfcCodeAt0 = 755224;
    const rfcSecretString = "12345678901234567890";
    const hotp = new Hotp(rfcSecretString);

    // Increments counter if the internal counter is used
    assertEquals(hotp.counter, 0);
    await hotp.validate(rfcCodeAt0);
    assertEquals(hotp.counter, 1);

    // Does not increment the counter when a moving factor is provided
    await hotp.validate(rfcCodeAt0, 0);
    assertEquals(hotp.counter, 1);
  },
});
