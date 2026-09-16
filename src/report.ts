import { randomBytes } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import {
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { fileURLToPath } from "node:url";
import type { ScanData } from "./types.js";

/** Escape JSON for a script raw-text element. HTML escaping alone is insufficient. */
export function scriptSafeJson(value: unknown): string {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    (character) =>
      ({
        "<": "\\u003c",
        ">": "\\u003e",
        "&": "\\u0026",
        "\u2028": "\\u2028",
        "\u2029": "\\u2029",
      })[character]!,
  );
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ]!,
  );
}

async function assets(): Promise<{ script: string; style: string }> {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [
    resolve(here, "../report"),
    resolve(here, "../dist/report"),
  ]) {
    try {
      const [script, style] = await Promise.all([
        readFile(join(candidate, "client.js"), "utf8"),
        readFile(join(candidate, "client.css"), "utf8"),
      ]);
      return { script, style };
    } catch {
      /* Source and compiled entrypoints have different relative roots. */
    }
  }
  throw new Error(
    "Report assets are missing. Run npm run build from the flowaudit project directory, then export the report again.",
  );
}

/** Produces an offline report without fetching remote assets or executing captured markup. */
export async function generateReport(
  data: ScanData,
  scanDir: string,
  outputDir = join(scanDir, "report"),
): Promise<{ html: string; json: string }> {
  const { script, style } = await assets();
  data = structuredClone(data);
  const screenshots: Record<string, string> = {};
  const reportWarnings: string[] = [];
  // Remove legacy synthesized previews from older exports. Only captured PNGs remain.
  const synthesized = new Set(
    data.screens.filter((s) => s.kind === "http-response").map((s) => s.id),
  );
  data.screens = data.screens.filter((s) => !synthesized.has(s.id));
  data.transitions = data.transitions.filter(
    (t) => !synthesized.has(t.to) && !synthesized.has(t.from || ""),
  );
  for (const finding of data.findings) {
    if (finding.resultScreenId && synthesized.has(finding.resultScreenId))
      delete finding.resultScreenId;
  }
  const root = await realpath(scanDir);
  for (const screen of data.screens) {
    if (!screen.screenshot) {
      reportWarnings.push(`Screenshot unavailable for screen ${screen.id}.`);
      continue;
    }
    try {
      const candidate = await realpath(resolve(root, screen.screenshot));
      const inside = relative(root, candidate);
      if (
        isAbsolute(screen.screenshot) ||
        inside.startsWith("..") ||
        isAbsolute(inside)
      )
        throw new Error("Screenshot is outside the scan directory");
      const mime = (
        {
          ".png": "image/png",
          ".jpg": "image/jpeg",
          ".jpeg": "image/jpeg",
          ".webp": "image/webp",
        } as Record<string, string>
      )[extname(candidate).toLowerCase()];
      if (!mime) throw new Error("Unsupported screenshot type");
      const bytes = await readFile(candidate);
      screenshots[screen.id] =
        `data:${mime};base64,${bytes.toString("base64")}`;
    } catch {
      reportWarnings.push(
        `Screenshot unavailable or unsafe for screen ${screen.id}.`,
      );
    }
  }
  const nonce = randomBytes(24).toString("base64");
  const payload = scriptSafeJson({
    ...data,
    screenshots,
    reportWarnings,
    exportedAt: new Date().toISOString(),
  });
  const csp = `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`;
  const htmlText = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${csp}"><title>${escapeHtml(data.name)} · FlowAudit</title><style>${style.replace(/<\/style/gi, "<\\/style")}</style></head>
<body><div id="root"></div><noscript>This report requires JavaScript. The accompanying scan.json contains the complete structured results.</noscript><script id="scan-data" type="application/json" nonce="${nonce}">${payload}</script><script nonce="${nonce}">${script.replace(/<\/script/gi, "<\\/script")}</script></body></html>`;
  await mkdir(outputDir, { recursive: true });
  const html = resolve(outputDir, "index.html");
  const json = resolve(outputDir, "scan.json");
  await Promise.all([
    writeFile(html, htmlText, "utf8"),
    writeFile(json, JSON.stringify(data, null, 2), "utf8"),
  ]);
  return { html, json };
}
