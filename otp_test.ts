import { Otp } from "./otp.ts";
import { assert, assertEquals, assertFalse } from "./test_deps.ts";

const goodButShortBase32Secret = "JBQWY3DPEBLWK3DU"; // 80 bit
const goodAndLongBase32SecretNoPadding = "GEZDGNBVGY3TQMJSGM2DKNRXHA"; // 128 bit
const goodAndLongBase32Secret = `${goodAndLongBase32SecretNoPadding}======`; // 128 bit
const badAndShortBase32Secret = "0123456Z0123456Z"; // 80 bit

Deno.test({
  name: "Otp.validateSecret accepts good but too short secrets",
  fn() {
    assert(Otp.validateSecret(goodButShortBase32Secret));
  },
});

Deno.test({
  name: "Otp.validateSecret accepts good and long enough secret",
  fn() {
    assert(Otp.validateSecret(goodAndLongBase32SecretNoPadding));
    assert(Otp.validateSecret(goodAndLongBase32Secret));
  },
});

Deno.test({
  name:
    "Otp.validateSecret with ignoreLength set to false does not accept good but too short secrets",
  fn() {
    assertFalse(Otp.validateSecret(goodButShortBase32Secret, false));
  },
});

Deno.test({
  name:
    "Otp.validateSecret with ignoreLength set to false does accept good and long enough secrets",
  fn() {
    assert(Otp.validateSecret(goodAndLongBase32SecretNoPadding, false));
    assert(Otp.validateSecret(goodAndLongBase32Secret, false));
  },
});

Deno.test({
  name:
    "Otp.validateSecret does not accept bad or 'Extended Hex' Base32 secrets",
  fn() {
    assertFalse(Otp.validateSecret(badAndShortBase32Secret));
    assertFalse(Otp.validateSecret(badAndShortBase32Secret, false));
    assertFalse(
      Otp.validateSecret(badAndShortBase32Secret + badAndShortBase32Secret),
    );
    assertFalse(
      Otp.validateSecret(
        badAndShortBase32Secret + badAndShortBase32Secret,
        false,
      ),
    );
  },
});

Deno.test({
  name:
    "Otp.formatCode adds spaces and does not append whitespace to the end and start",
  fn() {
    assertEquals(Otp.formatCode(123456, 6), "123 456");
    assertEquals(Otp.formatCode(12345, 6), "012 345");
    assertEquals(Otp.formatCode(1234567, 7), "1234 567");
  },
});
