import {
  bytesToUInt32BE,
  numberToBytes,
  trimWhitespaceAndAddBase32Padding,
} from "./util.ts";
import { assertEquals } from "./test_deps.ts";

Deno.test({
  name: "Converts a number to a Uint8Array representing its bytes",
  fn(): void {
    const uint32MaxValue = 4294967295;
    assertEquals(
      numberToBytes(uint32MaxValue),
      new Uint8Array([0, 0, 0, 0, 255, 255, 255, 255]),
    );
    assertEquals(
      numberToBytes(uint32MaxValue, false),
      new Uint8Array([255, 255, 255, 255]),
    );
    assertEquals(numberToBytes(600), new Uint8Array([0, 0, 0, 0, 0, 0, 2, 88]));
    assertEquals(numberToBytes(0), new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]));
    assertEquals(numberToBytes(0, false), new Uint8Array([0]));
  },
});

Deno.test({
  name: "Converts a Uint8Array to a uint32",
  fn(): void {
    const uint32MaxValue = 4294967295;
    // Ignores last bytes of array which contain more than 32 bit
    assertEquals(
      bytesToUInt32BE(new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255])),
      uint32MaxValue,
    );
    assertEquals(
      bytesToUInt32BE(new Uint8Array([127, 127, 127, 127, 255, 255, 255, 255])),
      2139062143,
    );
    assertEquals(
      bytesToUInt32BE(new Uint8Array([255, 255, 255, 255, 127, 127, 127, 127])),
      uint32MaxValue,
    );
    assertEquals(
      bytesToUInt32BE(new Uint8Array([255, 255, 255, 255])),
      uint32MaxValue,
    );

    assertEquals(
      bytesToUInt32BE(
        new Uint8Array([0, 0, 16, 12] /**That's the code to my heart */),
      ),
      4108,
    );

    assertEquals(bytesToUInt32BE(new Uint8Array([0, 0, 0, 0])), 0);
  },
});

Deno.test({
  name: "Secret is modified to fir Base32 requirements",
  fn(): void {
    const falselyEncodedSecret =
      "GEZ DGN BVG Y3T QOJ QGE ZDG NBV GY3 TQO JQG EZDG";
    const treatedSecret = trimWhitespaceAndAddBase32Padding(
      falselyEncodedSecret,
    );
    assertEquals(
      treatedSecret,
      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDG===",
    );

    const correctlyEncodedSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBV";
    assertEquals(
      trimWhitespaceAndAddBase32Padding(correctlyEncodedSecret),
      correctlyEncodedSecret,
    );
  },
});
