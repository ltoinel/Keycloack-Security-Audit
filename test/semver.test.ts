import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compareVersions,
  satisfiesRange,
} from "../src/checks/external/semver.js";

test("compareVersions orders correctly", () => {
  assert.equal(compareVersions("26.0.5", "22.0.10"), 1);
  assert.equal(compareVersions("1.0.0", "1.0.0"), 0);
  assert.equal(compareVersions("21.1.0", "21.1.2"), -1);
  assert.equal(compareVersions("26.0", "26.0.0"), 0);
  assert.equal(compareVersions("26.0.5-SNAPSHOT", "26.0.5"), 0);
});

test("satisfiesRange combines constraints with AND", () => {
  assert.equal(satisfiesRange("21.1.0", ">= 21.0.0, < 21.1.2"), true);
  assert.equal(satisfiesRange("21.1.2", ">= 21.0.0, < 21.1.2"), false);
  assert.equal(satisfiesRange("22.0.5", "< 22.0.10"), true);
  assert.equal(satisfiesRange("22.0.10", "< 22.0.10"), false);
  assert.equal(satisfiesRange("18.0.0", "= 18.0.0"), true);
  assert.equal(satisfiesRange("26.0.5", ">= 0, < 22.0.10"), false);
  assert.equal(satisfiesRange("15.0.0", "<= 26.6.1"), true);
});

test("satisfiesRange: empty range is not satisfied", () => {
  assert.equal(satisfiesRange("1.0.0", ""), false);
});
