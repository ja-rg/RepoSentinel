import { mkdirSync, rmSync } from "node:fs";
import { openDb, logLine, nowIso, setJobStatus, insertFinding } from "./db";
import { dockerGitClone } from "./git";
import {
  runTrivy, runSemgrep, runGrype,
  summarizeTrivy, summarizeSemgrep, summarizeGrype
} from "./scanners";

const DB_PATH = process.env.DB_PATH ?? "./data/scanner.sqlite";
const WORK_ROOT = process.env.WORK_ROOT ?? "./data/work";

const WORKER_CONCURRENCY = Number(process.env.WORKER_CONCURRENCY ?? "1");

const CLONE_TIMEOUT_MS = Number(process.env.CLONE_TIMEOUT_MS ?? "600000");
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS ?? "900000");

const IMG_GIT = process.env.IMG_GIT ?? "alpine/git:2.45.2";
const IMG_TRIVY = process.env.IMG_TRIVY ?? "aquasec/trivy:0.50.2";
const IMG_SEMGREP = process.env.IMG_SEMGREP ?? "returntocorp/semgrep:1.78.0";
const IMG_GRYPE = process.env.IMG_GRYPE ?? "anchore/grype:v0.78.0";

const db = openDb(DB_PATH);
mkdirSync(WORK_ROOT, { recursive: true });

function sleep(ms: number) {
  return new Promise(res => setTimeout(res, ms));
}

/**
 * Claim atómico: cambia 1 queued -> running y devuelve su row.
 * En SQLite no hay SKIP LOCKED, así que usamos transacción corta.
 */
function claimJob(): any | null {
  const tx = db.transaction(() => {
    const row = db.prepare(
      `SELECT id FROM jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1`
    ).get() as any;

    if (!row?.id) return null;

    const upd = db.prepare(
      `UPDATE jobs SET status='running', started_at=? WHERE id=? AND status='queued'`
    ).run(nowIso(), row.id);

    if (upd.changes !== 1) return null;

    return db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(row.id);
  });

  return tx();
}

async function processJob(job: any) {
  const jobId = job.id as string;
  const repoUrl = job.repo_url as string;
  const ref = job.ref as string | null;

  const workdir = `${WORK_ROOT}/${jobId}`;

  try {
    // limpia workdir para evitar basura
    rmSync(workdir, { recursive: true, force: true });
    mkdirSync(workdir, { recursive: true });

    setJobStatus(db, jobId, "running", { started_at: nowIso(), workdir });
    logLine(db, jobId, "info", `Starting job: ${repoUrl}${ref ? ` @ ${ref}` : ""}`);

    logLine(db, jobId, "info", "Cloning repository (docker git)...");
    const { jobDir } = await dockerGitClone({
      imgGit: IMG_GIT,
      repoUrl,
      ref,
      timeoutMs: CLONE_TIMEOUT_MS,
      workRoot: WORK_ROOT,
      jobId
    });

    // Scans
    logLine(db, jobId, "info", "Running Trivy...");
    const trivy = await runTrivy({ imgTrivy: IMG_TRIVY, jobDir, timeoutMs: SCAN_TIMEOUT_MS });
    insertFinding(db, jobId, "trivy", summarizeTrivy(trivy), trivy);

    logLine(db, jobId, "info", "Running Semgrep...");
    const semgrep = await runSemgrep({ imgSemgrep: IMG_SEMGREP, jobDir, timeoutMs: SCAN_TIMEOUT_MS });
    insertFinding(db, jobId, "semgrep", summarizeSemgrep(semgrep), semgrep);

    logLine(db, jobId, "info", "Running Grype...");
    const grype = await runGrype({ imgGrype: IMG_GRYPE, jobDir, timeoutMs: SCAN_TIMEOUT_MS });
    insertFinding(db, jobId, "grype", summarizeGrype(grype), grype);

    setJobStatus(db, jobId, "succeeded", { finished_at: nowIso(), error: "" });
    logLine(db, jobId, "info", "Job finished ✅");

    // opcional: limpiar workdir
    // rmSync(workdir, { recursive: true, force: true });

  } catch (e: any) {
    const msg = e?.message ? String(e.message) : String(e);
    logLine(db, jobId, "error", msg);
    setJobStatus(db, jobId, "failed", { finished_at: nowIso(), error: msg });
  }
}

async function workerLoop(workerId: number) {
  console.log(`Worker #${workerId} up ✅`);
  while (true) {
    const job = claimJob();
    if (!job) {
      await sleep(800);
      continue;
    }
    await processJob(job);
  }
}

const workers = Array.from({ length: Math.max(1, WORKER_CONCURRENCY) }, (_, i) => workerLoop(i + 1));
await Promise.all(workers);
