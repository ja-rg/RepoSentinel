import { genId, logLine, nowIso, openDb } from "./db";

const PORT = Number(process.env.PORT ?? "3000");
const DB_PATH = process.env.DB_PATH ?? "./data/scanner.sqlite";
const WORK_ROOT = process.env.WORK_ROOT ?? "./data/work";

const WEBHOOK_TOKEN = process.env.WEBHOOK_TOKEN ?? "";
const ALLOWED_GIT_HOSTS = (process.env.ALLOWED_GIT_HOSTS ?? "github.com").split(
  ",",
).map((s) => s.trim()).filter(Boolean);

const db = openDb(DB_PATH);

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function unauthorized() {
  return new Response("Unauthorized", { status: 401 });
}

function validateAuth(req: Request) {
  if (!WEBHOOK_TOKEN) return true; // si no configuraste token, no bloqueamos (pero NO recomendado)
  const auth = req.headers.get("authorization") || "";
  return auth === `Bearer ${WEBHOOK_TOKEN}`;
}

function validateRepoUrl(repoUrl: string) {
  let u: URL;
  try {
    u = new URL(repoUrl);
  } catch {
    return { ok: false, reason: "Invalid URL" };
  }

  if (u.protocol !== "https:" && u.protocol !== "http:") {
    return { ok: false, reason: "Only http/https URLs allowed" };
  }
  if (!ALLOWED_GIT_HOSTS.includes(u.hostname)) {
    return { ok: false, reason: `Host not allowed: ${u.hostname}` };
  }
  return { ok: true as const };
}

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    /**
     * Jobs endpoints:
      - GET /health -> { ok: true }
      - POST /scan { repoUrl, ref? } -> crea job y devuelve { jobId }
      - GET /scans -> lista de scans recientes (id, repoUrl, ref, status, created_at)
     */

    // Health
    if (url.pathname === "/health") return json({ ok: true });

    // Crear scan
    if (url.pathname === "/scan" && req.method === "POST") {
      if (!validateAuth(req)) return unauthorized();

      const body = await req.json().catch(() => null) as any;
      const repoUrl = String(body?.repoUrl ?? "");
      const ref = body?.ref ? String(body.ref) : null;

      const v = validateRepoUrl(repoUrl);
      if (!v.ok) return json({ error: v.reason }, 400);

      const id = genId();
      db.prepare(`
        INSERT INTO jobs(id, status, repo_url, ref, created_at, workdir)
        VALUES(?, 'queued', ?, ?, ?, ?)
      `).run(id, repoUrl, ref, nowIso(), `${WORK_ROOT}/${id}`);

      logLine(
        db,
        id,
        "info",
        `Job queued for ${repoUrl}${ref ? ` @ ${ref}` : ""}`,
      );

      return json({ jobId: id, status: "queued" }, 202);
    }

    if (url.pathname === "/scan" && req.method === "GET") {
      return json({
        message: "Send a POST with { repoUrl, ref? } to create a scan job",
      });
    }

    if (url.pathname === "/scans") {
      const jobs = db.prepare(
        `SELECT id, status, repo_url, ref, created_at FROM jobs ORDER BY created_at DESC LIMIT 100`,
      ).all();
      return json({ jobs });
    }

    /**
     * Per Job endpoints: status, results, findings, logs (polling)
      - GET /jobs/:id -> status + metadata
      - GET /jobs/:id/results -> resumen de findings por herramienta
      - GET /jobs/:id/findings -> detalles de findings (summary + raw)
      - GET /jobs/:id/logs?after=123 -> logs nuevas desde id > 123 (para polling)
     */

    // Estado job
    const jobMatch = url.pathname.match(/^\/jobs\/([^/]+)$/);
    if (jobMatch && req.method === "GET") {
      const id = jobMatch[1];
      const job = db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(id);
      if (!job) return json({ error: "Not found" }, 404);
      return json(job);
    }

    // Resultados
    const resMatch = url.pathname.match(/^\/jobs\/([^/]+)\/results$/);
    if (resMatch && req.method === "GET") {
      const id = resMatch[1];
      const findings = db.prepare(
        `SELECT tool, created_at, summary_json FROM findings WHERE job_id = ? ORDER BY id ASC`,
      ).all(id) as any[];

      return json({
        jobId: id,
        findings: findings.map((f) => ({
          tool: f.tool,
          created_at: f.created_at,
          summary: JSON.parse(f.summary_json),
        })),
      });
    }

    // Findings
    const findMatch = url.pathname.match(/^\/jobs\/([^/]+)\/findings$/);
    if (findMatch && req.method === "GET") {
      const id = findMatch[1];
      const findings = db.prepare(
        `SELECT tool, created_at, summary_json, raw_json FROM findings WHERE job_id = ? ORDER BY id ASC`,
      ).all(id) as any[];

      return json({
        jobId: id,
        findings: findings.map((f) => ({
          tool: f.tool,
          created_at: f.created_at,
          summary: JSON.parse(f.summary_json),
          details: JSON.parse(f.raw_json),
        })),
      });
    }

    // Logs (polling)
    const logsMatch = url.pathname.match(/^\/jobs\/([^/]+)\/logs$/);
    if (logsMatch && req.method === "GET") {
      const id = logsMatch[1];
      const after = Number(url.searchParams.get("after") ?? "0");

      const rows = db.prepare(
        `SELECT id, ts, level, line FROM job_logs WHERE job_id = ? AND id > ? ORDER BY id ASC LIMIT 500`,
      ).all(id, after);

      return json({ jobId: id, logs: rows });
    }

    return new Response("Not found", { status: 404 });
  },
});

console.log(`API listening on http://localhost:${PORT} ✅`);
