import { createHash, randomUUID } from "node:crypto";
import { mkdir, realpath } from "node:fs/promises";
import { join, relative, isAbsolute } from "node:path";
import type { Request, Response } from "playwright";
import type { BrowserRecorder } from "./browser.js";
import { assertScope, dangerous, inScope } from "./config.js";

/** The navigation goes to the server. No setContent, fulfill or response reconstruction. */
export async function liveFormResponse(
  r: BrowserRecorder,
  role: string,
  url: string,
  fields: URLSearchParams,
  mutationHeaders: Record<string, string>,
  capture: boolean,
) {
  r.check();
  assertScope(r.config, url);
  if (
    !r.config.tests?.publicSurface?.forms.some(
      (f) => new URL(f.submitPath, r.config.target).href === url,
    )
  )
    throw Error("Browser POST outside public form allowlist");
  if (
    dangerous.test(decodeURIComponent(new URL(url).pathname)) &&
    !r.config.allowedActions.includes(new URL(url).pathname)
  )
    throw Error("Browser POST blocked by action policy");
  const context = await r.browser!.newContext({
    viewport: { width: 1280, height: 900 },
    serviceWorkers: "block",
    acceptDownloads: false,
    ignoreHTTPSErrors: !!r.config.zap,
    proxy: r.config.zap
      ? { server: r.config.zap.proxyUrl, bypass: "<-loopback>" }
      : undefined,
  });
  try {
    await context.addCookies(await r.session(role).context.cookies());
    const page = await context.newPage();
    page.setDefaultTimeout(6000);
    context.on("page", (popup) => {
      if (popup !== page) void popup.close();
    });
    page.on("dialog", (dialog) => void dialog.dismiss());
    await context.routeWebSocket("**/*", (ws) => ws.close());
    let initial: Request | undefined;
    let response: Response | undefined;
    let sentHeaders: Record<string, string> = {};
    let resourceCount = 0;
    page.on("response", (value) => {
      if (value.request() === initial) response = value;
    });
    await context.route("**/*", async (route) => {
      const request = route.request();
      try {
        r.check();
        if (
          !initial &&
          request.isNavigationRequest() &&
          request.frame() === page.mainFrame() &&
          request.url() === url
        ) {
          initial = request;
          sentHeaders = {
            ...request.headers(),
            ...mutationHeaders,
            "content-type": "application/x-www-form-urlencoded",
          };
          delete sentHeaders["x-flowaudit-correlation"];
          delete sentHeaders["x-security-scan-correlation"];
          await route.continue({
            method: "POST",
            postData: fields.toString(),
            headers: sentHeaders,
          });
          return;
        }
        // Never repeat a POST on redirect or navigate to an application-selected destination.
        if (request.isNavigationRequest() || request.redirectedFrom())
          throw Error("Browser verification redirect/navigation not followed");
        if (!inScope(r.config, request.url()))
          throw Error("Browser verification resource outside scope");
        if (
          request.method() !== "GET" ||
          !["stylesheet", "image", "font", "script"].includes(
            request.resourceType(),
          ) ||
          dangerous.test(decodeURIComponent(new URL(request.url()).pathname))
        )
          throw Error("Browser verification resource blocked by action policy");
        if (
          ++resourceCount > 32 ||
          r.data.coverage.actions >= r.config.limits.actions
        )
          throw Error("Browser verification resource/action budget reached");
        const delay = Math.max(0, r.nextRequest - Date.now());
        r.nextRequest =
          Math.max(Date.now(), r.nextRequest) +
          1000 / r.config.limits.requestsPerSecond;
        await new Promise((resolve) => setTimeout(resolve, delay));
        r.check();
        r.data.coverage.actions++;
        const headers = { ...request.headers() };
        delete headers["x-flowaudit-correlation"];
        delete headers["x-security-scan-correlation"];
        await route.continue({ headers });
      } catch (error) {
        r.blocker((error as Error).message, role, request.url());
        await route.abort().catch(() => {});
      }
    });
    let navigationError = "";
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 12000 });
    } catch (error) {
      navigationError = (error as Error).message.split("\n")[0];
    }
    if (!response)
      throw Error(
        navigationError || "Browser received no main document response",
      );
    const main = response as Response;
    const status = main.status();
    const headers = await main.allHeaders();
    let bytes: Buffer = Buffer.alloc(0);
    try {
      bytes = await main.body();
    } catch {
      if (status < 300 || status >= 400)
        throw Error("Browser response body unavailable");
    }
    for (const cookie of await context.cookies()) r.redactor.add(cookie.value);
    const responseSha256 = createHash("sha256").update(bytes).digest("hex");
    let visibleText = "";
    let screenshot: string | undefined;
    let captureNote = "";
    if (!navigationError && page.url() === url && status >= 400) {
      await page.waitForLoadState("load", { timeout: 3000 }).catch(() => {});
      visibleText = await page
        .locator("body")
        .innerText()
        .catch(() => "");
      if (capture) {
        try {
          r.check();
          // Only masks are added to the live DOM. Layout/content are not replaced.
          await page.evaluate((values) => {
            for (const element of document.querySelectorAll("body *")) {
              if (element.children.length) continue;
              const text = element.textContent || "";
              if (
                values.some((value) => text.includes(value)) ||
                /(?:cookie|authorization|password|secret|token|csrf|api.?key)\s*[:=]/i.test(
                  text,
                )
              )
                element.setAttribute("data-scan-sensitive", "true");
              if (
                /^(?:cookie|authorization|password|secret|token|csrf|api.?key)s?\s*:?$/i.test(
                  text.trim(),
                )
              )
                element.nextElementSibling?.setAttribute(
                  "data-scan-sensitive",
                  "true",
                );
            }
          }, r.redactor.values);
          await mkdir(join(r.dir, "screens"), { recursive: true });
          const root = await realpath(r.dir),
            images = await realpath(join(r.dir, "screens"));
          const inside = relative(root, images);
          if (inside.startsWith("..") || isAbsolute(inside))
            throw Error("Screenshot directory outside scan");
          screenshot = `screens/${randomUUID()}.png`;
          const mask = [
            page.locator("input,textarea,[data-scan-sensitive]"),
            ...r.config.sensitiveSelectors.map((selector) =>
              page.locator(selector),
            ),
          ];
          await page.screenshot({
            path: join(r.dir, screenshot),
            fullPage: false,
            mask,
            timeout: 10000,
          });
          captureNote =
            "Live browser screenshot of the server POST response. Sensitive fields masked; viewport capture; redirects and non-allowlisted resources blocked. No HTML reconstruction.";
        } catch (error) {
          screenshot = undefined;
          captureNote = `Live screenshot unavailable: ${(error as Error).message.split("\n")[0]}`;
          r.blocker(captureNote, role, url);
        }
      }
    } else if (capture)
      captureNote =
        "No error document was rendered by the browser; no screenshot substituted.";
    return {
      status,
      headers,
      body: bytes.toString("utf8"),
      visibleText,
      screenshot,
      captureNote,
      responseSha256,
      sentHeaders,
      url: main.url(),
      capturedAt: new Date().toISOString(),
    };
  } finally {
    await context.close();
  }
}
