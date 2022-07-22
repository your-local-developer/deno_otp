import { bytesToUInt32BE, numberToBytes } from "./util.ts";
import { assertEquals } from "./test_deps.ts";

Deno.test({
  name: "Number to Uint8Array and back Test",
  fn(): void {
    const uint32MaxValue = 4294967295;
    // Ignores arrays which contain more than 32 bit
    assertEquals(
      bytesToUInt32BE(new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255])),
      uint32MaxValue,
    );
    assertEquals(
      bytesToUInt32BE(new Uint8Array([255, 255, 255, 255])),
      uint32MaxValue,
    );
    assertEquals(
      numberToBytes(uint32MaxValue),
      new Uint8Array([0, 0, 0, 0, 255, 255, 255, 255]),
    );
    assertEquals(
      numberToBytes(uint32MaxValue, false),
      new Uint8Array([255, 255, 255, 255]),
    );
    assertEquals(numberToBytes(600), new Uint8Array([0, 0, 0, 0, 0, 0, 2, 88]));
  },
});
