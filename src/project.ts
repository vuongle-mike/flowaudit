import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function findProjectRoot(from = fileURLToPath(import.meta.url)): string {
  let current = dirname(from);
  while (true) {
    const manifest = join(current, "package.json");
    if (existsSync(manifest)) {
      try {
        if (JSON.parse(readFileSync(manifest, "utf8")).name === "flowaudit")
          return current;
      } catch {}
    }
    const parent = dirname(current);
    if (parent === current) throw Error("Cannot locate flowaudit project root");
    current = parent;
  }
}

export function slugify(value: string): string {
  const slug = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 64);
  if (!slug) throw Error("Project name must contain a letter or number");
  return slug;
}

export function projectDirectory(root: string, slug: string): string {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug))
    throw Error("Invalid project name");
  return resolve(root, "projects", slug);
}
