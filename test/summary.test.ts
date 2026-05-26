import { test } from "node:test";
import assert from "node:assert/strict";
import { summarize } from "../src/report/summary.js";
import type { Finding, FindingStatus, Severity } from "../src/types.js";

function f(status: FindingStatus, severity: Severity): Finding {
  return { id: "x", title: "x", status, severity, category: "c", detail: "d" };
}

test("failuresBySeverity counts only fail, not warn", () => {
  const s = summarize([f("fail", "high"), f("warn", "high"), f("pass", "low")]);
  assert.equal(s.bySeverity.high, 2); // fail + warn
  assert.equal(s.failuresBySeverity.high, 1); // fail only
  assert.equal(s.byStatus.pass, 1);
});

test("score: a warn weighs half of a fail", () => {
  assert.equal(summarize([f("fail", "medium")]).score, 95); // 100 - 5
  assert.equal(summarize([f("warn", "medium")]).score, 98); // 100 - 2.5 -> rounded
});

test("full score when everything passes", () => {
  assert.equal(summarize([f("pass", "info"), f("skipped", "info")]).score, 100);
});
