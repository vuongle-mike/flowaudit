import Database from "better-sqlite3";
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  unlinkSync,
} from "node:fs";
import { join, resolve } from "node:path";
import type { ScanData, ProjectConfig } from "./types.js";
export class Store {
  db: Database.Database;
  root: string;
  lock: string;
  constructor(root: string) {
    this.root = resolve(root);
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
    this.lock = join(this.root, "worker.lock");
    if (existsSync(this.lock)) {
      const pid = Number(readFileSync(this.lock, "utf8"));
      let alive = false;
      try {
        process.kill(pid, 0);
        alive = true;
      } catch {}
      if (alive) throw Error("Another scanner worker owns this store");
      unlinkSync(this.lock);
    }
    writeFileSync(this.lock, String(process.pid), { flag: "wx", mode: 0o600 });
    this.db = new Database(join(this.root, "scans.sqlite"));
    this.db.pragma("journal_mode = WAL");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,status TEXT NOT NULL,data TEXT NOT NULL,config TEXT NOT NULL)",
    );
    for (const row of this.db
      .prepare("SELECT data FROM scans WHERE status='running'")
      .all() as any[]) {
      const d: ScanData = JSON.parse(row.data);
      d.status = "interrupted";
      d.coverage.notes.push(
        "Worker stopped; browser state was lost. Artifacts retained.",
      );
      d.jobs.forEach((j) => {
        if (j.status === "running") j.status = "interrupted";
      });
      this.save(d);
    }
  }
  dir(id: string) {
    if (!/^[a-f0-9-]{36}$/.test(id)) throw Error("Invalid scan ID");
    return join(this.root, id);
  }
  create(d: ScanData, c: ProjectConfig) {
    if (this.db.prepare("SELECT id FROM scans WHERE status='running'").get())
      throw Error("Only one active scan allowed");
    mkdirSync(join(this.dir(d.id), "screens"), {
      recursive: true,
      mode: 0o700,
    });
    this.db
      .prepare("INSERT INTO scans VALUES(?,?,?,?)")
      .run(d.id, d.status, JSON.stringify(d), JSON.stringify(c));
  }
  save(d: ScanData) {
    this.db
      .prepare("UPDATE scans SET status=?,data=? WHERE id=?")
      .run(d.status, JSON.stringify(d), d.id);
  }
  get(id: string): ScanData {
    this.dir(id);
    const r = this.db
      .prepare("SELECT data FROM scans WHERE id=?")
      .get(id) as any;
    if (!r) throw Error("Unknown scan");
    return JSON.parse(r.data);
  }
  config(id: string): ProjectConfig {
    this.get(id);
    return JSON.parse(
      (this.db.prepare("SELECT config FROM scans WHERE id=?").get(id) as any)
        .config,
    );
  }
  list() {
    return this.db.prepare("SELECT id,status FROM scans").all();
  }
  close() {
    this.db.close();
    try {
      if (readFileSync(this.lock, "utf8") === String(process.pid))
        unlinkSync(this.lock);
    } catch {}
  }
}
