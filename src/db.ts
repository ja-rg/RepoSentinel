import { Database } from "bun:sqlite";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";

export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "canceled";
export type InputType =
  | "git_url"
  | "workspace_path"
  | "archive_upload"
  | "docker_image"
  | "dockerfile_upload"
  | "k8s_manifest_upload";

export type LogLevel = "info" | "warn" | "error";

export function openDb(dbPath: string) {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA temp_store=MEMORY;
    PRAGMA busy_timeout=5000;
    PRAGMA foreign_keys=ON;
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      input_type TEXT NOT NULL,
      input_payload_json TEXT NOT NULL,
      policy_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      workdir TEXT,
      error TEXT,
      summary_json TEXT,
      deploy_status TEXT,
      nuclei_status TEXT,
      cancel_requested INTEGER NOT NULL DEFAULT 0
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
      severity TEXT,
      summary_json TEXT NOT NULL,
      raw_json TEXT NOT NULL,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_findings_job_id_tool
      ON findings(job_id, tool);

    CREATE TABLE IF NOT EXISTS uploads (
      id TEXT PRIMARY KEY,
      job_id TEXT,
      kind TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT,
      stored_path TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS worker_heartbeats (
      worker_id TEXT PRIMARY KEY,
      host TEXT,
      pid INTEGER,
      started_at TEXT NOT NULL,
      last_seen_ms INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_last_seen
      ON worker_heartbeats(last_seen_ms);
  `);

  ensureJobColumns(db, [
    ["input_type", "TEXT NOT NULL DEFAULT 'git_url'"],
    ["input_payload_json", "TEXT NOT NULL DEFAULT '{}'"],
    ["policy_json", "TEXT NOT NULL DEFAULT '{}'"],
    ["summary_json", "TEXT"],
    ["deploy_status", "TEXT"],
    ["nuclei_status", "TEXT"],
    ["cancel_requested", "INTEGER NOT NULL DEFAULT 0"]
  ]);

  return db;
}

export function nowIso() {
  return new Date().toISOString();
}

export function genId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${Date.now()}-${hex}`;
}

export function logLine(db: Database, jobId: string, level: LogLevel, line: string) {
  db.prepare(`INSERT INTO job_logs(job_id, ts, level, line) VALUES(?, ?, ?, ?)`).run(
    jobId,
    nowIso(),
    level,
    line
  );
}

export function createJob(
  db: Database,
  params: {
    id: string;
    inputType: InputType;
    payload: unknown;
    policy?: unknown;
    workdir: string;
  }
) {
  db.prepare(`
    INSERT INTO jobs(
      id, status, input_type, input_payload_json, policy_json, created_at, workdir
    ) VALUES(?, 'queued', ?, ?, ?, ?, ?)
  `).run(
    params.id,
    params.inputType,
    JSON.stringify(params.payload ?? {}),
    JSON.stringify(params.policy ?? {}),
    nowIso(),
    params.workdir
  );
}

export function setJobStatus(
  db: Database,
  jobId: string,
  status: JobStatus,
  fields?: Partial<{
    started_at: string;
    finished_at: string;
    error: string;
    workdir: string;
    summary_json: string;
    deploy_status: string;
    nuclei_status: string;
  }>
) {
  const cols: string[] = ["status = ?"];
  const vals: unknown[] = [status];

  if (fields?.started_at) {
    cols.push("started_at = ?");
    vals.push(fields.started_at);
  }
  if (fields?.finished_at) {
    cols.push("finished_at = ?");
    vals.push(fields.finished_at);
  }
  if (fields?.error !== undefined) {
    cols.push("error = ?");
    vals.push(fields.error);
  }
  if (fields?.workdir) {
    cols.push("workdir = ?");
    vals.push(fields.workdir);
  }
  if (fields?.summary_json !== undefined) {
    cols.push("summary_json = ?");
    vals.push(fields.summary_json);
  }
  if (fields?.deploy_status !== undefined) {
    cols.push("deploy_status = ?");
    vals.push(fields.deploy_status);
  }
  if (fields?.nuclei_status !== undefined) {
    cols.push("nuclei_status = ?");
    vals.push(fields.nuclei_status);
  }

  vals.push(jobId);
  db.prepare(`UPDATE jobs SET ${cols.join(", ")} WHERE id = ?`).run(...vals);
}

export function requestCancel(db: Database, jobId: string) {
  return db.prepare(`UPDATE jobs SET cancel_requested = 1 WHERE id = ?`).run(jobId);
}

export function insertFinding(
  db: Database,
  jobId: string,
  tool: string,
  summary: unknown,
  raw: unknown,
  severity?: string
) {
  db.prepare(`
    INSERT INTO findings(job_id, tool, created_at, severity, summary_json, raw_json)
    VALUES(?, ?, ?, ?, ?, ?)
  `).run(jobId, tool, nowIso(), severity ?? null, JSON.stringify(summary), JSON.stringify(raw));
}

export function attachUploadToJob(db: Database, uploadId: string, jobId: string) {
  db.prepare(`UPDATE uploads SET job_id = ? WHERE id = ?`).run(jobId, uploadId);
}

function ensureJobColumns(db: Database, columns: Array<[string, string]>) {
  const info = db.prepare(`PRAGMA table_info(jobs)`).all() as Array<{ name: string }>;
  const existing = new Set(info.map((c) => c.name));
  for (const [name, ddl] of columns) {
    if (!existing.has(name)) {
      db.exec(`ALTER TABLE jobs ADD COLUMN ${name} ${ddl}`);
    }
  }
}
