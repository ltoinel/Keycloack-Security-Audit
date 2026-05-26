import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSetCookie } from "../src/checks/blackbox/cookies.js";

test("parseSetCookie: reads name and all flags", () => {
  const c = parseSetCookie(
    "AUTH_SESSION_ID=abc; Version=1; Path=/realms/x/; HttpOnly; SameSite=None; Secure",
  );
  assert.equal(c.name, "AUTH_SESSION_ID");
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, "None");
});

test("parseSetCookie: detects missing flags", () => {
  const c = parseSetCookie("KC_RESTART=xyz; Path=/");
  assert.equal(c.name, "KC_RESTART");
  assert.equal(c.secure, false);
  assert.equal(c.httpOnly, false);
  assert.equal(c.sameSite, undefined);
});

test("parseSetCookie: flag matching is case-insensitive", () => {
  const c = parseSetCookie("X=1; secure; httponly; samesite=Lax");
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, "Lax");
});
