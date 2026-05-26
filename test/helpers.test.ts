import { test } from "node:test";
import assert from "node:assert/strict";
import {
  dangerousRedirectUris,
  parsePasswordPolicy,
} from "../src/checks/helpers.js";

test("dangerousRedirectUris flags wildcards and non-local http", () => {
  assert.deepEqual(dangerousRedirectUris(["*"]), ["*"]);
  assert.deepEqual(dangerousRedirectUris(["https://*.example.com"]), [
    "https://*.example.com",
  ]);
  assert.deepEqual(dangerousRedirectUris(["http://evil.com/cb"]), [
    "http://evil.com/cb",
  ]);
  assert.deepEqual(dangerousRedirectUris(["https://app.example.com/cb"]), []);
  assert.deepEqual(dangerousRedirectUris(["http://localhost:3000/cb"]), []);
  assert.deepEqual(dangerousRedirectUris(["http://127.0.0.1/cb"]), []);
  assert.deepEqual(dangerousRedirectUris(undefined), []);
});

test("parsePasswordPolicy extracts length and flags", () => {
  const m = parsePasswordPolicy("length(12) and digits(1) and notUsername");
  assert.equal(m.get("length"), "12");
  assert.equal(m.get("digits"), "1");
  assert.equal(m.get("notUsername"), "");
  assert.equal(parsePasswordPolicy(undefined).size, 0);
});
