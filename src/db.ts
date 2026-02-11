import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type JobStatus = "queued" | "running" | "succeeded" | "failed";

export function openDb(dbPath: string) {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);

  // Concurrencia decente en SQLite
  db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA temp_store=MEMORY;
    PRAGMA busy_timeout=5000;
    PRAGMA foreign_keys=ON;
  `);

  // Schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      repo_url TEXT NOT NULL,
      ref TEXT,
      created_at TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      workdir TEXT,
      error TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_jobs_status_created
      ON jobs(status, created_at);

    CREATE TABLE IF NOT EXISTS job_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      ts TEXT NOT NULL,
      level TEXT NOT NULL,
      line TEXT NOT NULL,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_job_logs_job_id_id
      ON job_logs(job_id, id);

    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      tool TEXT NOT NULL,
      created_at TEXT NOT NULL,
      summary_json TEXT NOT NULL,
      raw_json TEXT NOT NULL,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_findings_job_id_tool
      ON findings(job_id, tool);
  `);

  return db;
}

export function nowIso() {
  return new Date().toISOString();
}

export function genId() {
  // id simple: timestamp + random
  const r = crypto.getRandomValues(new Uint8Array(8));
  const hex = [...r].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${Date.now()}-${hex}`;
}

export function logLine(db: Database, jobId: string, level: "info" | "warn" | "error", line: string) {
  db.prepare(
    `INSERT INTO job_logs(job_id, ts, level, line) VALUES(?, ?, ?, ?)`
  ).run(jobId, nowIso(), level, line);
}

export function setJobStatus(
  db: Database,
  jobId: string,
  status: JobStatus,
  fields?: Partial<{ started_at: string; finished_at: string; error: string; workdir: string }>
) {
  const cols: string[] = ["status = ?"];
  const vals: any[] = [status];

  if (fields?.started_at) { cols.push("started_at = ?"); vals.push(fields.started_at); }
  if (fields?.finished_at) { cols.push("finished_at = ?"); vals.push(fields.finished_at); }
  if (fields?.error !== undefined) { cols.push("error = ?"); vals.push(fields.error); }
  if (fields?.workdir) { cols.push("workdir = ?"); vals.push(fields.workdir); }

  vals.push(jobId);
  db.prepare(`UPDATE jobs SET ${cols.join(", ")} WHERE id = ?`).run(...vals);
}

export function insertFinding(db: Database, jobId: string, tool: string, summary: unknown, raw: unknown) {
  db.prepare(
    `INSERT INTO findings(job_id, tool, created_at, summary_json, raw_json)
     VALUES(?, ?, ?, ?, ?)`
  ).run(jobId, tool, nowIso(), JSON.stringify(summary), JSON.stringify(raw));
}
