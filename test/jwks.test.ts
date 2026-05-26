import { test } from "node:test";
import assert from "node:assert/strict";
import { rsaBits } from "../src/checks/blackbox/jwks.js";

/** base64url of a buffer of `bytes` length (0x01 then zeros) -> ~bytes*8 bits. */
function modOfBytes(bytes: number): string {
  const b = Buffer.alloc(bytes, 0);
  b[0] = 0x01; // no leading zero byte
  return b.toString("base64url");
}

test("rsaBits: 256-byte modulus is 2048 bits", () => {
  assert.equal(rsaBits(modOfBytes(256)), 2048);
});

test("rsaBits: 128-byte modulus is 1024 bits (weak)", () => {
  assert.equal(rsaBits(modOfBytes(128)), 1024);
});

test("rsaBits: strips a leading zero byte", () => {
  const b = Buffer.alloc(257, 0); // leading 0x00 + 256 meaningful bytes
  b[1] = 0x01;
  assert.equal(rsaBits(b.toString("base64url")), 2048);
});
