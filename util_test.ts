import { bytesToUInt32BE, numberToBytes } from "./util.ts";
import { assertEquals } from "./test_deps.ts";

Deno.test({
  name: "Number to Uint8Array Test",
  fn(): void {
    assertEquals(
      bytesToUInt32BE(new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255])),
      4294967295,
    );
    assertEquals(
      numberToBytes(4294967295),
      new Uint8Array([0, 0, 0, 0, 255, 255, 255, 255]),
    );
    assertEquals(numberToBytes(600), new Uint8Array([0, 0, 0, 0, 0, 0, 2, 88]));
  },
});
