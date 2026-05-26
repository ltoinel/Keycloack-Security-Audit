import { test } from "node:test";
import assert from "node:assert/strict";
import { looksLikeAdminConsole } from "../src/checks/blackbox/endpoints.js";

test("looksLikeAdminConsole: genuine console index page", () => {
  const body =
    '<!doctype html><html><head><title>Keycloak Administration Console</title>' +
    '<script src="/resources/26.0.5/admin/keycloak.v2/main.js"></script></head>' +
    '<body><div id="app"></div></body></html>';
  assert.equal(looksLikeAdminConsole(body, "text/html;charset=utf-8"), true);
});

test("looksLikeAdminConsole: resources/admin marker alone is enough", () => {
  const body =
    '<html><link rel="stylesheet" href="/resources/abc12/admin/keycloak.v2/style.css"></html>';
  assert.equal(looksLikeAdminConsole(body, "text/html"), true);
});

test("looksLikeAdminConsole: generic HTML without markers is rejected", () => {
  assert.equal(looksLikeAdminConsole("<html><body>Welcome</body></html>", "text/html"), false);
});

test("looksLikeAdminConsole: empty body (redirect) is rejected", () => {
  assert.equal(looksLikeAdminConsole("", "text/html"), false);
});

test("looksLikeAdminConsole: non-HTML response is rejected", () => {
  assert.equal(looksLikeAdminConsole('{"error":"not found"}', "application/json"), false);
});
