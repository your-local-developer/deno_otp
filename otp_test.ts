import { byteLength } from "./deps.ts";
import { Otp } from "./otp.ts";
import {
  assert,
  assertEquals,
  assertFalse,
  assertThrows,
} from "./test_deps.ts";
import { isBase32 } from "./util.ts";

// Otp.validateSecret tests
{
  const goodButShortBase32Secret = "JBQWY3DPEBLWK3DU"; // 80 bit
  const goodAndLongBase32SecretNoPadding = "GEZDGNBVGY3TQMJSGM2DKNRXHA"; // 128 bit
  const goodAndLongBase32Secret = `${goodAndLongBase32SecretNoPadding}======`; // 128 bit
  const badAndShortBase32Secret = "0123456Z0123456Z"; // 80 bit
  const goodBase32AlphabetWithWhiteSpace =
    "ABC DEF GHI JKL MNO PQR STU VWX YZ2 345 67";
  const badBase32Alphabet =
    "ABC DEF GHI JKL MNO PQR STU VWX YZ/ <>@ 0[8 912 345 67";

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
    name: "Otp.validateSecret only accepts the base32 alphabet",
    fn() {
      assert(Otp.validateSecret(goodBase32AlphabetWithWhiteSpace));
      assert(
        Otp.validateSecret(
          goodBase32AlphabetWithWhiteSpace.toLowerCase(),
        ),
      );
      assertFalse(Otp.validateSecret(badBase32Alphabet));
      assertFalse(Otp.validateSecret(badBase32Alphabet.toLowerCase()));
    },
  });
}

Deno.test({
  name:
    "Otp.formatCode adds spaces for the grouping and does not append whitespace to the end and start",
  fn() {
    assertEquals(Otp.formatCode(123456, 6), "123 456");
    assertEquals(Otp.formatCode(12345, 6), "012 345");
    assertEquals(Otp.formatCode("012345", 6), "012 345");
    assertEquals(Otp.formatCode(1234567, 7), "1234 567");
    // Ignores minimum digit requirement if the code is longer
    assertEquals(Otp.formatCode(1234567, 6), "1234 567");
    assertEquals(Otp.formatCode("1234567", 6), "1234 567");
    assertEquals(
      Otp.formatCode(1234567, 6, {
        grouping: 0,
      }),
      "1234567",
    );
    // Reformats the code
    assertEquals(Otp.formatCode("0012 345", 6, { grouping: 3 }), "001 234 5");
  },
});

Deno.test({
  name:
    "Otp.generateSecret and Otp.generateBase32Secret generate a secret of the correct length",
  fn() {
    assertEquals(Otp.generateSecret().length, 20);
    assertEquals(Otp.generateSecret({ byteLength: 16 }).length, 16);
    assertEquals(
      byteLength(Otp.generateBase32Secret({ byteLength: 16 })),
      16,
    );
    assert(isBase32(Otp.generateBase32Secret()));
    assertThrows(() => Otp.generateSecret({ byteLength: 3 }));
    assertEquals(
      byteLength(
        Otp.generateBase32Secret({ byteLength: 3, allowShortSecret: true }),
      ),
      3,
    );
  },
});
