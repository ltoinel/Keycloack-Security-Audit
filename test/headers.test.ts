import { test } from "node:test";
import assert from "node:assert/strict";
import { meetsExpectation } from "../src/checks/external/headers.js";

test("meetsExpectation: no expectation means presence is enough", () => {
  assert.equal(meetsExpectation("anything"), true);
  assert.equal(meetsExpectation("", {}), true);
});

test("meetsExpectation: equals is case-insensitive", () => {
  assert.equal(meetsExpectation("nosniff", { equals: "nosniff" }), true);
  assert.equal(meetsExpectation("NOSNIFF", { equals: "nosniff" }), true);
  assert.equal(meetsExpectation("sniff", { equals: "nosniff" }), false);
});

test("meetsExpectation: regex is case-insensitive", () => {
  assert.equal(meetsExpectation("SAMEORIGIN", { regex: "sameorigin|deny" }), true);
  assert.equal(meetsExpectation("DENY", { regex: "sameorigin|deny" }), true);
  assert.equal(meetsExpectation("ALLOW-FROM x", { regex: "sameorigin|deny" }), false);
});

test("meetsExpectation: HSTS minMaxAge threshold", () => {
  assert.equal(meetsExpectation("max-age=31536000", { minMaxAge: 31536000 }), true);
  assert.equal(meetsExpectation("max-age=31536001; includeSubDomains", { minMaxAge: 31536000 }), true);
  assert.equal(meetsExpectation("max-age=600", { minMaxAge: 31536000 }), false);
  assert.equal(meetsExpectation("includeSubDomains", { minMaxAge: 31536000 }), false);
});

test("meetsExpectation: invalid regex is treated as not satisfied", () => {
  assert.equal(meetsExpectation("x", { regex: "(" }), false);
});
