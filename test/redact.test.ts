import test from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.js";
test("redaction learns dynamic JSON and hidden HTML secrets without treating cookie origins or role names as secrets", () => {
  const r = new Redactor({
    userA: {
      username: "userA",
      password: "demo-secret",
      cookies: [
        {
          name: "session",
          value: "cookie-secret",
          url: "http://127.0.0.1:13000",
        },
      ],
    },
  });
  assert.equal(
    r.text("userA http://127.0.0.1:13000"),
    "userA http://127.0.0.1:13000",
  );
  assert.equal(r.text("demo-secret cookie-secret"), "[REDACTED] [REDACTED]");
  const json = r.text('{"access_token":"fresh-access-value","user":"userA"}');
  assert.ok(!json.includes("fresh-access-value"));
  assert.ok(json.includes("userA"));
  const html = r.text(
    '<input type="hidden" name="csrf_token" value="fresh-csrf-value">',
  );
  assert.ok(!html.includes("fresh-csrf-value"));
  assert.equal(r.text("fresh-csrf-value"), "[REDACTED]");
  assert.ok(
    !r.url("http://example.test/?token=query-secret").includes("query-secret"),
  );
  assert.equal(
    r.clean({ cookie: "session=cookie-secret" }).cookie,
    "[REDACTED]",
  );
});
