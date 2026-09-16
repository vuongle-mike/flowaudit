import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { chmod } from "node:fs/promises";

const root = fileURLToPath(new URL("..", import.meta.url));
await build({
  entryPoints: [resolve(root, "report/main.tsx")],
  outfile: resolve(root, "dist/report/client.js"),
  bundle: true,
  minify: true,
  format: "iife",
  platform: "browser",
  target: ["es2022"],
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "none",
});
await chmod(resolve(root, "dist/src/cli.js"), 0o755);
console.log("Built standalone report assets in dist/report");
