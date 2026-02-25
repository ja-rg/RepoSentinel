import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { Database } from "bun:sqlite";
import { dockerGitClone } from "./git";
import { runDocker, runHostCommand } from "./docker";
import {
  insertFinding,
  logLine,
  nowIso,
  openDb,
  setJobStatus
} from "./db";
import {
  runGrype,
  runGrypeImage,
  runSemgrep,
  runTrivy,
  runTrivyImage,
  summarizeGrype,
  summarizeSemgrep,
  summarizeTrivy
} from "./scanners";

const DB_PATH = process.env.DB_PATH ?? "./data/scanner.sqlite";
const WORK_ROOT = process.env.WORK_ROOT ?? "./data/work";
const UPLOAD_ROOT = process.env.UPLOAD_ROOT ?? "./data/uploads";
const WORKER_CONCURRENCY = Number(process.env.WORKER_CONCURRENCY ?? "1");
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS ?? "1000");
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS ?? "5000");
const CLONE_TIMEOUT_MS = Number(process.env.CLONE_TIMEOUT_MS ?? "600000");
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS ?? "1200000");
const CLEANUP_WORKDIR = (process.env.CLEANUP_WORKDIR ?? "true").toLowerCase() === "true";
const CLEANUP_UPLOADS = (process.env.CLEANUP_UPLOADS ?? "false").toLowerCase() === "true";
const RUNNER_NAMESPACE = process.env.RUNNER_NAMESPACE ?? "default";
const HOSTNAME = process.env.COMPUTERNAME ?? process.env.HOSTNAME ?? "unknown-host";

const IMG_GIT = process.env.IMG_GIT ?? "alpine/git:2.45.2";
const IMG_TRIVY = process.env.IMG_TRIVY ?? "aquasec/trivy:0.50.2";
const IMG_SEMGREP = process.env.IMG_SEMGREP ?? "returntocorp/semgrep:1.78.0";
const IMG_GRYPE = process.env.IMG_GRYPE ?? "anchore/grype:v0.78.0";
const IMG_KUBECTL = process.env.IMG_KUBECTL ?? "bitnami/kubectl:1.30";
const IMG_NUCLEI = process.env.IMG_NUCLEI ?? "projectdiscovery/nuclei:latest";

mkdirSync(WORK_ROOT, { recursive: true });
mkdirSync(UPLOAD_ROOT, { recursive: true });

const db = openDb(DB_PATH);

type JobRow = {
  id: string;
  status: string;
  input_type: string;
  input_payload_json: string;
  policy_json: string;
  created_at: string;
  workdir: string | null;
  cancel_requested: number;
};

function sleep(ms: number) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

function heartbeat(workerId: string) {
  db.prepare(`
    INSERT INTO worker_heartbeats(worker_id, host, pid, started_at, last_seen_ms)
    VALUES(?, ?, ?, ?, ?)
    ON CONFLICT(worker_id) DO UPDATE SET
      host = excluded.host,
      pid = excluded.pid,
      last_seen_ms = excluded.last_seen_ms
  `).run(workerId, HOSTNAME, process.pid, nowIso(), Date.now());
}

function claimJob(): JobRow | null {
  const tx = db.transaction(() => {
    const row = db.prepare(`
      SELECT id FROM jobs
      WHERE status = 'queued' AND cancel_requested = 0
      ORDER BY created_at ASC LIMIT 1
    `).get() as { id?: string } | undefined;
    if (!row?.id) return null;

    const r = db.prepare(`
      UPDATE jobs
      SET status = 'running', started_at = ?
      WHERE id = ? AND status = 'queued'
    `).run(nowIso(), row.id);
    if (r.changes !== 1) return null;

    return db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(row.id) as JobRow;
  });
  return tx();
}

async function processJob(job: JobRow) {
  const jobId = job.id;
  const inputType = String(job.input_type);
  const payload = safeJsonParse(job.input_payload_json);
  const policy = safeJsonParse(job.policy_json);
  const workdir = resolve(job.workdir || join(WORK_ROOT, jobId));
  const sourceDir = join(workdir, "source");
  const sourceJobDir = join(sourceDir, "job");
  const repoDir = join(sourceJobDir, "repo");

  try {
    rmSync(workdir, { recursive: true, force: true });
    mkdirSync(repoDir, { recursive: true });
    setJobStatus(db, jobId, "running", { workdir, started_at: nowIso(), error: "" });
    logLine(db, jobId, "info", `Starting job ${jobId} (${inputType})`);

    if (isCancelRequested(db, jobId)) return markCanceled(jobId, workdir);

    if (inputType === "git_url") {
      await dockerGitClone({
        imgGit: IMG_GIT,
        repoUrl: String(payload.repoUrl),
        ref: payload.ref ? String(payload.ref) : null,
        timeoutMs: CLONE_TIMEOUT_MS,
        destinationDir: sourceJobDir
      });
    } else if (inputType === "workspace_path") {
      const src = String(payload.path ?? "");
      if (!src || !isAbsolute(src)) throw new Error("workspace_path requires absolute payload.path");
      cpSync(src, repoDir, { recursive: true, force: true });
    } else if (inputType === "archive_upload") {
      const archivePath = resolveUploadPath(payload);
      await extractArchive(archivePath, repoDir);
    } else if (inputType === "dockerfile_upload") {
      const dockerfilePath = resolveUploadPath(payload);
      cpSync(dockerfilePath, join(repoDir, "Dockerfile"), { force: true });
    } else if (inputType === "k8s_manifest_upload") {
      const manifestPath = resolveUploadPath(payload);
      cpSync(manifestPath, join(repoDir, "manifest.yaml"), { force: true });
    }

    if (isCancelRequested(db, jobId)) return markCanceled(jobId, workdir);

    const toolSummaries: Record<string, unknown> = {};
    if (inputType === "docker_image") {
      const imageRef = String(payload.image ?? "");
      if (!imageRef) throw new Error("docker_image requires payload.image");

      logLine(db, jobId, "info", `Pulling image ${imageRef}`);
      const pull = await runHostCommand({ cmd: ["docker", "pull", imageRef], timeoutMs: SCAN_TIMEOUT_MS });
      if (pull.timedOut || pull.code !== 0) throw new Error(`docker pull failed: ${pull.stderr || pull.stdout}`);

      if (payload.saveTar === true) {
        const tarPath = join(workdir, "docker-image.tar");
        const save = await runHostCommand({
          cmd: ["docker", "save", imageRef, "-o", tarPath],
          timeoutMs: SCAN_TIMEOUT_MS
        });
        if (save.timedOut || save.code !== 0) {
          throw new Error(`docker save failed: ${save.stderr || save.stdout}`);
        }
      }

      const trivy = await runTrivyImage({ imgTrivy: IMG_TRIVY, imageRef, timeoutMs: SCAN_TIMEOUT_MS });
      const trivySummary = summarizeTrivy(trivy);
      insertFinding(db, jobId, "trivy", trivySummary, trivy);
      toolSummaries.trivy = trivySummary;

      const grype = await runGrypeImage({ imgGrype: IMG_GRYPE, imageRef, timeoutMs: SCAN_TIMEOUT_MS });
      const grypeSummary = summarizeGrype(grype);
      insertFinding(db, jobId, "grype", grypeSummary, grype);
      toolSummaries.grype = grypeSummary;

      if (payload.removeImageAfterScan !== false) {
        await runHostCommand({ cmd: ["docker", "rmi", imageRef], timeoutMs: 120000 });
      }
    } else {
      logLine(db, jobId, "info", "Running Trivy fs scan");
      const trivy = await runTrivy({ imgTrivy: IMG_TRIVY, jobDir: sourceJobDir, timeoutMs: SCAN_TIMEOUT_MS });
      const trivySummary = summarizeTrivy(trivy);
      insertFinding(db, jobId, "trivy", trivySummary, trivy);
      toolSummaries.trivy = trivySummary;

      logLine(db, jobId, "info", "Running Semgrep");
      const semgrep = await runSemgrep({ imgSemgrep: IMG_SEMGREP, jobDir: sourceJobDir, timeoutMs: SCAN_TIMEOUT_MS });
      const semgrepSummary = summarizeSemgrep(semgrep);
      insertFinding(db, jobId, "semgrep", semgrepSummary, semgrep);
      toolSummaries.semgrep = semgrepSummary;

      logLine(db, jobId, "info", "Running Grype dir scan");
      const grype = await runGrype({ imgGrype: IMG_GRYPE, jobDir: sourceJobDir, timeoutMs: SCAN_TIMEOUT_MS });
      const grypeSummary = summarizeGrype(grype);
      insertFinding(db, jobId, "grype", grypeSummary, grype);
      toolSummaries.grype = grypeSummary;
    }

    if (isCancelRequested(db, jobId)) return markCanceled(jobId, workdir);

    const gate = await runDeployGateIfNeeded(db, jobId, workdir, payload, policy, toolSummaries);
    const summary = { toolSummaries, deployGate: gate };

    setJobStatus(db, jobId, "succeeded", {
      finished_at: nowIso(),
      summary_json: JSON.stringify(summary),
      error: ""
    });
    logLine(db, jobId, "info", "Job completed");
  } catch (error: any) {
    const message = String(error?.message ?? error);
    logLine(db, jobId, "error", message);
    setJobStatus(db, jobId, "failed", { finished_at: nowIso(), error: message });
  } finally {
    if (CLEANUP_WORKDIR) rmSync(workdir, { recursive: true, force: true });
    if (CLEANUP_UPLOADS) cleanupJobUploads(db, jobId);
  }
}

async function runDeployGateIfNeeded(
  dbConn: Database,
  jobId: string,
  workdir: string,
  payload: any,
  policy: any,
  toolSummaries: Record<string, unknown>
) {
  const enabled = Boolean(policy?.deployGate?.enabled);
  if (!enabled) return { enabled: false };

  const blockingFindings = exceedsPolicyThreshold(toolSummaries, policy?.blockOn ?? {});
  if (blockingFindings) {
    logLine(dbConn, jobId, "warn", "Deploy gate blocked due to findings threshold");
    setJobStatus(dbConn, jobId, "succeeded", { deploy_status: "blocked_by_findings", nuclei_status: "skipped" });
    return { enabled: true, deployed: false, reason: "blocked_by_findings" };
  }

  const manifestPath = resolveManifestPath(payload, policy);
  if (!manifestPath) {
    logLine(dbConn, jobId, "warn", "Deploy gate enabled without manifest, skipping deployment");
    setJobStatus(dbConn, jobId, "succeeded", { deploy_status: "skipped_no_manifest", nuclei_status: "skipped" });
    return { enabled: true, deployed: false, reason: "missing_manifest" };
  }

  logLine(dbConn, jobId, "info", `Deploying manifest ${manifestPath}`);
  await runKubectl(manifestPath, ["apply", "-f", "/work/manifest.yaml"]);
  setJobStatus(dbConn, jobId, "succeeded", { deploy_status: "deployed", nuclei_status: "pending" });

  const targetUrl = String(policy?.deployGate?.targetUrl ?? "");
  if (!targetUrl) {
    setJobStatus(dbConn, jobId, "succeeded", { nuclei_status: "skipped_no_target" });
    return { enabled: true, deployed: true, nuclei: "skipped_no_target" };
  }

  const nuclei = await runNuclei(targetUrl, workdir);
  const findingsCount = Array.isArray(nuclei) ? nuclei.length : 0;
  insertFinding(dbConn, jobId, "nuclei_postdeploy", { findings: findingsCount }, nuclei);
  if (findingsCount > 0) {
    logLine(dbConn, jobId, "warn", `Nuclei found ${findingsCount} issues, undeploying`);
    await runKubectl(manifestPath, ["delete", "-f", "/work/manifest.yaml"]);
    setJobStatus(dbConn, jobId, "succeeded", { deploy_status: "rolled_back", nuclei_status: "failed" });
    return { enabled: true, deployed: false, nuclei: "failed", findings: findingsCount };
  }

  setJobStatus(dbConn, jobId, "succeeded", { nuclei_status: "passed" });
  return { enabled: true, deployed: true, nuclei: "passed", findings: 0 };
}

async function runKubectl(manifestPath: string, args: string[]) {
  const dir = dirname(manifestPath);
  const input = join(dir, "manifest.yaml");
  cpSync(manifestPath, input, { force: true });
  const r = await runDocker({
    image: IMG_KUBECTL,
    args,
    mounts: [{ hostPath: dir, containerPath: "/work" }],
    timeoutMs: 300000
  });
  if (r.timedOut || r.code !== 0) throw new Error(`kubectl failed: ${r.stderr || r.stdout}`);
}

async function runNuclei(targetUrl: string, workdir: string) {
  const outPath = join(workdir, "nuclei.jsonl");
  const r = await runDocker({
    image: IMG_NUCLEI,
    args: ["-u", targetUrl, "-jsonl", "-silent", "-o", "/work/nuclei.jsonl"],
    mounts: [{ hostPath: workdir, containerPath: "/work" }],
    timeoutMs: 300000
  });
  if (r.timedOut || r.code !== 0) throw new Error(`nuclei failed: ${r.stderr || r.stdout}`);
  const content = await Bun.file(outPath).text().catch(() => "");
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => safeJsonParse(line));
}

function resolveManifestPath(payload: any, policy: any): string | null {
  if (typeof policy?.deployGate?.manifestPath === "string" && policy.deployGate.manifestPath) {
    return resolve(policy.deployGate.manifestPath);
  }
  if (typeof payload?.manifestUploadId === "string" && payload.manifestUploadId) {
    const row = db.prepare(`SELECT stored_path FROM uploads WHERE id = ?`).get(payload.manifestUploadId) as { stored_path?: string } | undefined;
    if (row?.stored_path) return resolve(row.stored_path);
  }
  return null;
}

function resolveUploadPath(payload: any): string {
  if (typeof payload?.uploadPath === "string" && payload.uploadPath) return resolve(payload.uploadPath);
  if (typeof payload?.uploadId === "string" && payload.uploadId) {
    const row = db.prepare(`SELECT stored_path FROM uploads WHERE id = ?`).get(payload.uploadId) as { stored_path?: string } | undefined;
    if (row?.stored_path) return resolve(row.stored_path);
  }
  throw new Error("uploadId/uploadPath not found");
}

async function extractArchive(archivePath: string, destinationDir: string) {
  mkdirSync(destinationDir, { recursive: true });
  const ext = extname(archivePath).toLowerCase();
  if (ext === ".zip") {
    if (process.platform === "win32") {
      const command = `Expand-Archive -LiteralPath '${escapePs(archivePath)}' -DestinationPath '${escapePs(destinationDir)}' -Force`;
      const r = await runHostCommand({ cmd: ["powershell", "-NoProfile", "-Command", command], timeoutMs: 120000 });
      if (r.timedOut || r.code !== 0) throw new Error(`zip extract failed: ${r.stderr || r.stdout}`);
      return;
    }
    const r = await runHostCommand({ cmd: ["unzip", "-o", archivePath, "-d", destinationDir], timeoutMs: 120000 });
    if (r.timedOut || r.code !== 0) throw new Error(`zip extract failed: ${r.stderr || r.stdout}`);
    return;
  }

  const r = await runHostCommand({ cmd: ["tar", "-xf", archivePath, "-C", destinationDir], timeoutMs: 120000 });
  if (r.timedOut || r.code !== 0) throw new Error(`tar extract failed: ${r.stderr || r.stdout}`);
}

function escapePs(input: string) {
  return input.replace(/'/g, "''");
}

function isCancelRequested(dbConn: Database, jobId: string) {
  const row = dbConn.prepare(`SELECT cancel_requested FROM jobs WHERE id = ?`).get(jobId) as { cancel_requested?: number } | undefined;
  return Number(row?.cancel_requested ?? 0) === 1;
}

function markCanceled(jobId: string, workdir: string) {
  logLine(db, jobId, "warn", "Job canceled");
  setJobStatus(db, jobId, "canceled", {
    finished_at: nowIso(),
    error: "Canceled by user",
    workdir
  });
}

function cleanupJobUploads(dbConn: Database, jobId: string) {
  const rows = dbConn.prepare(`SELECT stored_path FROM uploads WHERE job_id = ?`).all(jobId) as Array<{ stored_path: string }>;
  for (const row of rows) {
    rmSync(resolve(row.stored_path), { recursive: true, force: true });
  }
}

function safeJsonParse(raw: string) {
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function exceedsPolicyThreshold(toolSummaries: Record<string, unknown>, blockOn: any) {
  const criticalLimit = Number(blockOn?.critical ?? 0);
  const highLimit = Number(blockOn?.high ?? Number.MAX_SAFE_INTEGER);
  const trivy = (toolSummaries.trivy ?? {}) as any;
  const grype = (toolSummaries.grype ?? {}) as any;
  const totalCritical = Number(trivy.critical ?? 0) + Number(grype.bySeverity?.CRITICAL ?? 0);
  const totalHigh = Number(trivy.high ?? 0) + Number(grype.bySeverity?.HIGH ?? 0);
  return totalCritical > criticalLimit || totalHigh > highLimit;
}

async function loop(workerId: number) {
  const runnerId = `${RUNNER_NAMESPACE}:${HOSTNAME}:${process.pid}:w${workerId}`;
  heartbeat(runnerId);
  const timer = setInterval(() => heartbeat(runnerId), HEARTBEAT_INTERVAL_MS);

  console.log(`worker-${workerId} ready (${runnerId})`);
  try {
    while (true) {
      const job = claimJob();
      if (!job) {
        await sleep(POLL_INTERVAL_MS);
        continue;
      }
      heartbeat(runnerId);
      await processJob(job);
      heartbeat(runnerId);
    }
  } finally {
    clearInterval(timer);
  }
}

const workers = Array.from({ length: Math.max(1, WORKER_CONCURRENCY) }, (_, index) => loop(index + 1));
await Promise.all(workers);
