import test from "node:test";
import assert from "node:assert/strict";
import { startFixture } from "../src/fixture.js";

async function login(url: string, username: string) {
  const response = await fetch(`${url}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password: "Demo-pass-123!" }),
  });
  assert.equal(response.status, 200);
  const body = (await response.json()) as { token: string };
  assert.match(response.headers.get("set-cookie") ?? "", /HttpOnly/);
  return { authorization: `Bearer ${body.token}` };
}

for (const mode of ["vulnerable", "fixed"] as const) {
  test(`fixture ${mode}: tenant and admin authorization have contrasting behavior`, async () => {
    const fixture = await startFixture({ mode });
    try {
      const a = await login(fixture.url, "userA"),
        b = await login(fixture.url, "userB"),
        admin = await login(fixture.url, "admin");
      const probe = await fetch(`${fixture.url}/api/me`, { headers: a });
      assert.match(await probe.text(), /AUTHENTICATED_userA/);
      const records = (await (
        await fetch(`${fixture.url}/api/invoices`, { headers: a })
      ).json()) as Array<{ id: string; org: string }>;
      assert.ok(records.length > 0);
      assert.ok(records.every((record) => record.org === "org-a"));
      const cross = await fetch(`${fixture.url}/invoices/${records[0].id}`, {
        headers: b,
      });
      assert.equal(cross.status, mode === "fixed" ? 403 : 200);
      assert.equal(
        (await cross.text()).includes("ORG_A_PRIVATE_INVOICE"),
        mode === "vulnerable",
      );
      const privileged = await fetch(`${fixture.url}/admin`, { headers: a });
      assert.equal(privileged.status, mode === "fixed" ? 403 : 200);
      assert.equal(
        (await privileged.text()).includes("ADMIN_PRIVATE_DATA"),
        mode === "vulnerable",
      );
      assert.match(
        await (await fetch(`${fixture.url}/admin`, { headers: admin })).text(),
        /ADMIN_PRIVATE_DATA/,
      );
    } finally {
      await fixture.close();
    }
  });
  test(`fixture ${mode}: reflection and session invalidation are independently verifiable`, async () => {
    const fixture = await startFixture({ mode });
    try {
      const auth = await login(fixture.url, "userA");
      const payload = "<script>window.__fixture_xss=1</script>";
      const text = await (
        await fetch(`${fixture.url}/search?q=${encodeURIComponent(payload)}`, {
          headers: auth,
        })
      ).text();
      assert.equal(text.includes(payload), mode === "vulnerable");
      assert.ok(text.includes("&lt;script&gt;"));
      const logout = await fetch(`${fixture.url}/logout`, {
        headers: auth,
        redirect: "manual",
      });
      assert.equal(logout.status, 303);
      const replay = await fetch(`${fixture.url}/api/me`, { headers: auth });
      assert.equal(replay.status, mode === "fixed" ? 401 : 200);
    } finally {
      await fixture.close();
    }
  });
}

test("fixture browser login, editable records, action counters, and deterministic reset", async () => {
  const fixture = await startFixture({ mode: "fixed" });
  try {
    const page = await fetch(`${fixture.url}/login`);
    const body = await page.text();
    const csrf = body.match(/name="csrf" value="([^"]+)"/)?.[1];
    assert.ok(csrf);
    const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0];
    const invalid = await fetch(`${fixture.url}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie },
      body: new URLSearchParams({
        username: "userA",
        password: "Demo-pass-123!",
        csrf: "invalid",
      }),
      redirect: "manual",
    });
    assert.equal(invalid.status, 403);
    const accepted = await fetch(`${fixture.url}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie },
      body: new URLSearchParams({
        username: "userA",
        password: "Demo-pass-123!",
        csrf,
      }),
      redirect: "manual",
    });
    assert.equal(accepted.status, 303);
    const headers = {
      cookie: (accepted.headers.get("set-cookie") ?? "").split(";")[0],
    };
    const list = (await (
      await fetch(`${fixture.url}/api/invoices`, { headers })
    ).json()) as Array<{ id: string; note: string }>;
    const detail = await (
      await fetch(`${fixture.url}/invoices/${list[0].id}`, { headers })
    ).text();
    assert.match(detail, /id="edit-dialog"/);
    assert.match(detail, /data-tab="history"/);
    assert.match(detail, /data-authenticated="userA"/);
    await fetch(`${fixture.url}/api/invoices/${list[0].id}`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ note: "Changed in test" }),
    });
    const saved = (await (
      await fetch(`${fixture.url}/api/invoices/${list[0].id}`, { headers })
    ).json()) as { note: string };
    assert.equal(saved.note, "Changed in test");
    await fetch(`${fixture.url}/api/invoices/${list[0].id}/pay`, {
      method: "POST",
      headers,
    });
    await fetch(`${fixture.url}/api/invoices/${list[0].id}/delete`, {
      method: "POST",
      headers,
    });
    await fetch(`${fixture.url}/api/me`, {
      headers: { ...headers, "x-flowaudit-correlation": "example" },
    });
    const metrics = (await (
      await fetch(`${fixture.url}/api/metrics`)
    ).json()) as {
      payRequests: number;
      deleteRequests: number;
      leakedCorrelationHeaders: number;
    };
    assert.equal(metrics.payRequests, 1);
    assert.equal(metrics.deleteRequests, 1);
    assert.equal(metrics.leakedCorrelationHeaders, 1);
    const external = await fetch(`${fixture.url}/redirect-external`, {
      redirect: "manual",
    });
    assert.equal(
      external.headers.get("location"),
      "https://example.com/outside-fixture",
    );
    const reset = await fetch(`${fixture.url}/api/reset`, { method: "POST" });
    assert.equal(reset.status, 200);
    assert.equal(
      (await fetch(`${fixture.url}/api/me`, { headers })).status,
      401,
    );
    const restored = await (
      await fetch(`${fixture.url}/api/invoices`, {
        headers: await login(fixture.url, "userA"),
      })
    ).json();
    assert.deepEqual(restored, list);
  } finally {
    await fixture.close();
  }
});
