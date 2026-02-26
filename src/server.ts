import { mkdirSync, rmSync } from "node:fs";
import { basename, extname, join } from "node:path";
import { Hono } from "hono";
import {
  attachUploadToJob,
  createJob,
  genId,
  InputType,
  logLine,
  openDb,
  requestCancel
} from "./db";
import { runHostCommand } from "./docker";

const PORT = Number(process.env.PORT ?? "3000");
const DB_PATH = process.env.DB_PATH ?? "./data/scanner.sqlite";
const WORK_ROOT = process.env.WORK_ROOT ?? "./data/work";
const UPLOAD_ROOT = process.env.UPLOAD_ROOT ?? "./data/uploads";
const PUBLIC_ROOT = process.env.PUBLIC_ROOT ?? "./docs";
const WEBHOOK_TOKEN = process.env.WEBHOOK_TOKEN ?? "";
const RUNNER_TTL_MS = Number(process.env.RUNNER_TTL_MS ?? "15000");
const IMG_TRIVY = process.env.IMG_TRIVY ?? "aquasec/trivy:0.50.2";
const IMG_SEMGREP = process.env.IMG_SEMGREP ?? "returntocorp/semgrep:1.78.0";
const IMG_GRYPE = process.env.IMG_GRYPE ?? "anchore/grype:v0.78.0";
const ALLOWED_GIT_HOSTS = (process.env.ALLOWED_GIT_HOSTS ?? "github.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

mkdirSync(WORK_ROOT, { recursive: true });
mkdirSync(UPLOAD_ROOT, { recursive: true });

const db = openDb(DB_PATH);
const app = new Hono();
const STARTED_AT_MS = Date.now();
let preflightCache: { deep: boolean; atMs: number; data: unknown } | null = null;

type UploadRow = {
  id: string;
  job_id: string | null;
  kind: string;
  original_name: string;
  mime_type: string | null;
  stored_path: string;
  created_at: string;
};

app.get("/health", (c) => c.json({ ok: true, service: "reposentinel-api" }));

app.get("/system/status", (c) => {
  const nowMs = Date.now();

  const rows = db
    .prepare(`SELECT status, COUNT(*) AS count FROM jobs GROUP BY status`)
    .all() as Array<{ status: string; count: number }>;
  const jobsByStatus: Record<string, number> = {
    queued: 0,
    running: 0,
    succeeded: 0,
    failed: 0,
    canceled: 0
  };
  for (const row of rows) jobsByStatus[row.status] = Number(row.count ?? 0);

  const workers = db.prepare(`
    SELECT worker_id, host, pid, started_at, last_seen_ms
    FROM worker_heartbeats
    ORDER BY last_seen_ms DESC
  `).all() as Array<{
    worker_id: string;
    host: string | null;
    pid: number | null;
    started_at: string;
    last_seen_ms: number;
  }>;

  const aliveWorkers = workers.filter((w) => nowMs - Number(w.last_seen_ms) <= RUNNER_TTL_MS);

  const recentJobs = db.prepare(`
    SELECT
      j.id,
      j.status,
      j.input_type,
      j.input_payload_json,
      j.created_at,
      j.started_at,
      j.finished_at,
      j.error,
      j.deploy_status,
      j.nuclei_status,
      (SELECT COUNT(*) FROM findings f WHERE f.job_id = j.id) AS findings_count
    FROM jobs j
    ORDER BY j.created_at DESC
    LIMIT 15
  `).all() as Array<{
    id: string;
    status: string;
    input_type: string;
    input_payload_json: string;
    created_at: string;
    started_at: string | null;
    finished_at: string | null;
    error: string | null;
    deploy_status: string | null;
    nuclei_status: string | null;
    findings_count: number;
  }>;

  return c.json({
    ok: true,
    api: {
      uptimeSec: Math.floor((nowMs - STARTED_AT_MS) / 1000),
      startedAt: new Date(STARTED_AT_MS).toISOString()
    },
    jobs: jobsByStatus,
    runners: {
      total: workers.length,
      alive: aliveWorkers.length,
      ttlMs: RUNNER_TTL_MS,
      items: workers.slice(0, 50).map((w) => ({
        workerId: w.worker_id,
        host: w.host,
        pid: w.pid,
        startedAt: w.started_at,
        lastSeenMs: Number(w.last_seen_ms),
        isAlive: nowMs - Number(w.last_seen_ms) <= RUNNER_TTL_MS
      }))
    },
    recentJobs: recentJobs.map((j) => ({
      id: j.id,
      status: j.status,
      inputType: j.input_type,
      inputSummary: summarizeInput(j.input_type, j.input_payload_json),
      createdAt: j.created_at,
      startedAt: j.started_at,
      finishedAt: j.finished_at,
      error: j.error,
      deployStatus: j.deploy_status,
      nucleiStatus: j.nuclei_status,
      findingsCount: Number(j.findings_count ?? 0)
    }))
  });
});

app.get("/system/preflight", async (c) => {
  const deep = c.req.query("deep") === "1";
  const force = c.req.query("force") === "1";
  const cacheTtlMs = deep ? 15000 : 5000;
  if (!force && preflightCache && preflightCache.deep === deep && Date.now() - preflightCache.atMs < cacheTtlMs) {
    return c.json({ ...(preflightCache.data as any), cached: true });
  }

  const checks: Array<{
    name: string;
    ok: boolean;
    required: boolean;
    detail: string;
  }> = [];

  const dockerCli = await checkCommand(["docker", "--help"], "docker_cli", true, 8000);
  checks.push(dockerCli);

  const dockerDaemon = await checkCommand(["docker", "info"], "docker_daemon", true, 12000);
  checks.push(dockerDaemon);

  if (deep && dockerDaemon.ok) {
    checks.push(await checkCommand(["docker", "run", "--rm", IMG_TRIVY, "--version"], "trivy_container", true, 25000));
    checks.push(await checkCommand(["docker", "run", "--rm", IMG_SEMGREP, "semgrep", "--version"], "semgrep_container", true, 25000));
    checks.push(await checkCommand(["docker", "run", "--rm", IMG_GRYPE, "version"], "grype_container", true, 25000));
  }

  const ok = checks.filter((cInfo) => cInfo.required).every((cInfo) => cInfo.ok);
  const data = {
    ok,
    mode: deep ? "deep" : "quick",
    checkedAt: new Date().toISOString(),
    checks
  };
  preflightCache = { deep, atMs: Date.now(), data };
  return c.json(data);
});

app.get("/", async (c) => {
  const f = Bun.file(join(PUBLIC_ROOT, "frontend.html"));
  if (!(await f.exists())) return c.text("Frontend not found", 404);
  return c.body(await f.text(), 200, { "content-type": "text/html; charset=utf-8" });
});

app.get("/app.js", async (c) => {
  const f = Bun.file(join(PUBLIC_ROOT, "frontend.js"));
  if (!(await f.exists())) return c.text("Not found", 404);
  return c.body(await f.text(), 200, { "content-type": "application/javascript; charset=utf-8" });
});

app.get("/styles.css", async (c) => {
  const f = Bun.file(join(PUBLIC_ROOT, "frontend.css"));
  if (!(await f.exists())) return c.text("Not found", 404);
  return c.body(await f.text(), 200, { "content-type": "text/css; charset=utf-8" });
});

app.post("/uploads", async (c) => {
  if (!hasAuth(c.req.raw)) return c.text("Unauthorized", 401);

  const form = await c.req.formData();
  const file = form.get("file");
  const kind = String(form.get("kind") ?? "archive");
  if (!(file instanceof File)) return c.json({ error: "file is required" }, 400);

  const uploadId = genId();
  const uploadDir = join(UPLOAD_ROOT, uploadId);
  const originalName = basename(file.name || "upload.bin");
  const suffix = extname(originalName);
  const storedPath = join(uploadDir, `input${suffix || ".bin"}`);
  mkdirSync(uploadDir, { recursive: true });
  await Bun.write(storedPath, file);

  db.prepare(`
    INSERT INTO uploads(id, job_id, kind, original_name, mime_type, stored_path, created_at)
    VALUES(?, NULL, ?, ?, ?, ?, datetime('now'))
  `).run(uploadId, kind, originalName, file.type || null, storedPath);

  return c.json({ uploadId, kind, originalName }, 201);
});

app.post("/jobs", async (c) => {
  if (!hasAuth(c.req.raw)) return c.text("Unauthorized", 401);

  const body = (await c.req.json().catch(() => null)) as any;
  const inputType = parseInputType(body?.inputType);
  if (!inputType) return c.json({ error: "invalid inputType" }, 400);

  const payload = body?.payload ?? {};
  let policy: any;
  try {
    policy = normalizePolicyForInput(inputType, body?.policy ?? {});
  } catch (error: any) {
    return c.json({ error: String(error?.message ?? error) }, 400);
  }
  const validation = validatePayload(inputType, payload);
  if (!validation.ok) return c.json({ error: validation.reason }, 400);

  if (inputType === "k8s_manifest_upload") {
    const upload = getUploadById(String(payload.uploadId ?? ""));
    if (!upload) return c.json({ error: "manifest upload not found" }, 400);
    if (!isYamlUpload(upload.original_name, upload.mime_type)) {
      return c.json({ error: "only .yaml/.yml files are deployable" }, 400);
    }
  }

  const jobId = genId();
  const workdir = join(WORK_ROOT, jobId);
  createJob(db, { id: jobId, inputType, payload, policy, workdir });
  logLine(db, jobId, "info", `Job queued (${inputType})`);

  if (typeof payload?.uploadId === "string" && payload.uploadId) {
    attachUploadToJob(db, payload.uploadId, jobId);
  }

  return c.json({ jobId, status: "queued" }, 202);
});

app.get("/jobs", (c) => {
  const limitRaw = Number(c.req.query("limit") ?? "20");
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 20;
  const status = String(c.req.query("status") ?? "").trim();

  const where = status ? "WHERE j.status = ?" : "";
  const stmt = db.prepare(`
    SELECT
      j.id,
      j.status,
      j.input_type,
      j.input_payload_json,
      j.created_at,
      j.started_at,
      j.finished_at,
      j.error,
      j.deploy_status,
      j.nuclei_status,
      (SELECT COUNT(*) FROM findings f WHERE f.job_id = j.id) AS findings_count
    FROM jobs j
    ${where}
    ORDER BY j.created_at DESC
    LIMIT ?
  `);

  const rows = (status ? stmt.all(status, limit) : stmt.all(limit)) as Array<{
    id: string;
    status: string;
    input_type: string;
    input_payload_json: string;
    created_at: string;
    started_at: string | null;
    finished_at: string | null;
    error: string | null;
    deploy_status: string | null;
    nuclei_status: string | null;
    findings_count: number;
  }>;

  return c.json({
    jobs: rows.map((j) => ({
      id: j.id,
      status: j.status,
      inputType: j.input_type,
      inputSummary: summarizeInput(j.input_type, j.input_payload_json),
      createdAt: j.created_at,
      startedAt: j.started_at,
      finishedAt: j.finished_at,
      error: j.error,
      deployStatus: j.deploy_status,
      nucleiStatus: j.nuclei_status,
      findingsCount: Number(j.findings_count ?? 0)
    }))
  });
});

app.get("/jobs/:id", (c) => {
  const id = c.req.param("id");
  const row = db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(id);
  if (!row) return c.json({ error: "not found" }, 404);
  return c.json(row);
});

app.get("/jobs/:id/findings", (c) => {
  const id = c.req.param("id");
  const includeRaw = c.req.query("includeRaw") === "1";
  const rows = db.prepare(`
    SELECT id, tool, severity, created_at, summary_json, raw_json
    FROM findings WHERE job_id = ? ORDER BY id ASC
  `).all(id) as Array<{
    id: number;
    tool: string;
    severity: string | null;
    created_at: string;
    summary_json: string;
    raw_json: string;
  }>;

  return c.json({
    jobId: id,
    findings: rows.map((r) => ({
      id: r.id,
      tool: r.tool,
      severity: r.severity,
      createdAt: r.created_at,
      summary: safeJsonParse(r.summary_json),
      rawPreview: summarizeRawFinding(r.raw_json),
      raw: includeRaw ? safeJsonParse(r.raw_json) : undefined
    }))
  });
});

app.get("/jobs/:id/findings/:findingId", (c) => {
  const jobId = c.req.param("id");
  const findingId = Number(c.req.param("findingId"));
  if (!Number.isFinite(findingId)) return c.json({ error: "invalid finding id" }, 400);

  const row = db.prepare(`
    SELECT id, tool, severity, created_at, summary_json, raw_json
    FROM findings
    WHERE id = ? AND job_id = ?
  `).get(findingId, jobId) as
    | {
        id: number;
        tool: string;
        severity: string | null;
        created_at: string;
        summary_json: string;
        raw_json: string;
      }
    | undefined;

  if (!row) return c.json({ error: "finding not found" }, 404);
  return c.json({
    id: row.id,
    jobId,
    tool: row.tool,
    severity: row.severity,
    createdAt: row.created_at,
    summary: safeJsonParse(row.summary_json),
    raw: safeJsonParse(row.raw_json)
  });
});

app.get("/jobs/:id/results", (c) => {
  const id = c.req.param("id");
  const rows = db.prepare(`
    SELECT id, tool, severity, created_at, summary_json
    FROM findings WHERE job_id = ? ORDER BY id ASC
  `).all(id) as Array<{ id: number; tool: string; severity: string | null; created_at: string; summary_json: string }>;

  return c.json({
    jobId: id,
    findings: rows.map((r) => ({
      id: r.id,
      tool: r.tool,
      severity: r.severity,
      createdAt: r.created_at,
      summary: safeJsonParse(r.summary_json)
    }))
  });
});

app.get("/jobs/:id/logs", (c) => {
  const id = c.req.param("id");
  const after = Number(c.req.query("after") ?? "0");
  const rows = db.prepare(`
    SELECT id, ts, level, line
    FROM job_logs
    WHERE job_id = ? AND id > ?
    ORDER BY id ASC
    LIMIT 1000
  `).all(id, after);
  return c.json({ jobId: id, logs: rows });
});

app.post("/jobs/:id/cancel", (c) => {
  if (!hasAuth(c.req.raw)) return c.text("Unauthorized", 401);
  const id = c.req.param("id");
  const r = requestCancel(db, id);
  if (r.changes !== 1) return c.json({ error: "not found" }, 404);
  logLine(db, id, "warn", "Cancel requested by API");
  return c.json({ jobId: id, cancelRequested: true });
});

app.delete("/jobs/:id", (c) => {
  if (!hasAuth(c.req.raw)) return c.text("Unauthorized", 401);

  const jobId = c.req.param("id");
  const job = db.prepare(`SELECT id, workdir FROM jobs WHERE id = ?`).get(jobId) as
    | { id: string; workdir: string | null }
    | undefined;
  if (!job) return c.json({ error: "not found" }, 404);

  const uploads = db.prepare(`SELECT id, stored_path FROM uploads WHERE job_id = ?`).all(jobId) as Array<{
    id: string;
    stored_path: string;
  }>;

  const tx = db.transaction(() => {
    db.prepare(`DELETE FROM uploads WHERE job_id = ?`).run(jobId);
    db.prepare(`DELETE FROM jobs WHERE id = ?`).run(jobId);
  });
  tx();

  for (const upload of uploads) {
    rmSync(upload.stored_path, { recursive: true, force: true });
  }
  if (job.workdir) {
    rmSync(job.workdir, { recursive: true, force: true });
  }

  return c.json({
    deleted: true,
    jobId,
    uploadsDeleted: uploads.length
  });
});

Bun.serve({ port: PORT, fetch: app.fetch });
console.log(`API listening on http://localhost:${PORT}`);

function hasAuth(req: Request) {
  if (!WEBHOOK_TOKEN) return true;
  return req.headers.get("authorization") === `Bearer ${WEBHOOK_TOKEN}`;
}

function parseInputType(value: unknown): InputType | null {
  const v = String(value ?? "");
  if (
    v === "git_url" ||
    v === "workspace_path" ||
    v === "archive_upload" ||
    v === "docker_image" ||
    v === "dockerfile_upload" ||
    v === "k8s_manifest_upload"
  ) {
    return v;
  }
  return null;
}

function validatePayload(inputType: InputType, payload: any): { ok: true } | { ok: false; reason: string } {
  if (inputType === "git_url") {
    const repoUrl = String(payload?.repoUrl ?? "");
    const valid = validateRepoUrl(repoUrl);
    if (!valid.ok) return valid;
  }
  if (inputType === "workspace_path" && !String(payload?.path ?? "")) {
    return { ok: false, reason: "payload.path is required" };
  }
  if (
    (inputType === "archive_upload" || inputType === "dockerfile_upload" || inputType === "k8s_manifest_upload") &&
    !String(payload?.uploadId ?? "")
  ) {
    return { ok: false, reason: "payload.uploadId is required" };
  }
  if (inputType === "docker_image" && !String(payload?.image ?? "")) {
    return { ok: false, reason: "payload.image is required" };
  }
  if (inputType !== "k8s_manifest_upload" && payload?.manifestUploadId) {
    return { ok: false, reason: "deploy gate is only supported for k8s_manifest_upload jobs" };
  }
  return { ok: true };
}

function validateRepoUrl(repoUrl: string): { ok: true } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(repoUrl);
  } catch {
    return { ok: false, reason: "invalid repo URL" };
  }
  if (!["https:", "http:"].includes(url.protocol)) {
    return { ok: false, reason: "only http/https URLs are allowed" };
  }
  if (!ALLOWED_GIT_HOSTS.includes(url.hostname)) {
    return { ok: false, reason: `host not allowed: ${url.hostname}` };
  }
  return { ok: true };
}

function safeJsonParse(raw: string) {
  try {
    return JSON.parse(raw);
  } catch {
    return { raw };
  }
}

async function checkCommand(
  cmd: string[],
  name: string,
  required: boolean,
  timeoutMs: number
) {
  try {
    const r = await runHostCommand({ cmd, timeoutMs });
    const ok = !r.timedOut && r.code === 0;
    return {
      name,
      ok,
      required,
      detail: ok
        ? "ok"
        : compactText(r.stderr || r.stdout || `exit code ${r.code}${r.timedOut ? " (timeout)" : ""}`)
    };
  } catch (error: any) {
    return {
      name,
      ok: false,
      required,
      detail: compactText(String(error?.message ?? error))
    };
  }
}

function compactText(input: string) {
  return input.replace(/\s+/g, " ").trim().slice(0, 220);
}

function summarizeInput(inputType: string, payloadRaw: string) {
  const payload = safeJsonParse(payloadRaw) as Record<string, unknown>;
  if (inputType === "git_url") {
    const repoUrl = String(payload.repoUrl ?? "");
    const ref = String(payload.ref ?? "");
    return ref ? `${repoUrl} @ ${ref}` : repoUrl;
  }
  if (inputType === "workspace_path") return String(payload.path ?? "");
  if (inputType === "docker_image") return String(payload.image ?? "");
  if (inputType === "k8s_manifest_upload") return `manifest:${String(payload.uploadId ?? "")}`;
  if (inputType === "archive_upload" || inputType === "dockerfile_upload" || inputType === "k8s_manifest_upload") {
    return String(payload.uploadId ?? payload.uploadPath ?? "");
  }
  return inputType;
}

function getUploadById(uploadId: string) {
  if (!uploadId) return null;
  const row = db.prepare(`
    SELECT id, job_id, kind, original_name, mime_type, stored_path, created_at
    FROM uploads
    WHERE id = ?
  `).get(uploadId) as UploadRow | undefined;
  return row ?? null;
}

function isYamlUpload(fileName: string, mimeType: string | null) {
  const lower = String(fileName || "").toLowerCase();
  const mime = String(mimeType || "").toLowerCase();
  return (
    lower.endsWith(".yaml") ||
    lower.endsWith(".yml") ||
    mime.includes("yaml") ||
    mime.includes("x-yaml")
  );
}

function normalizePolicyForInput(inputType: InputType, policyRaw: any) {
  const policy = policyRaw && typeof policyRaw === "object" ? policyRaw : {};
  const deployGateEnabled = Boolean(policy?.deployGate?.enabled);
  if (deployGateEnabled && inputType !== "k8s_manifest_upload") {
    throw new Error("deploy gate is only supported for k8s_manifest_upload jobs");
  }
  if (inputType === "k8s_manifest_upload" && deployGateEnabled) {
    const targetUrl = String(policy?.deployGate?.targetUrl ?? "").trim();
    if (!targetUrl) {
      throw new Error("deploy gate for manifests requires policy.deployGate.targetUrl");
    }
  }
  if (inputType !== "k8s_manifest_upload") {
    const { deployGate: _, ...rest } = policy;
    return rest;
  }
  return policy;
}

function summarizeRawFinding(rawJson: string) {
  const parsed = safeJsonParse(rawJson);
  const type = Array.isArray(parsed) ? "array" : typeof parsed;
  return {
    type,
    bytes: rawJson.length
  };
}
