import { runDocker } from "./docker";

export type ScanOutputs = {
  trivy?: any;
  semgrep?: any;
  grype?: any;
};

export async function runTrivy(params: {
  imgTrivy: string;
  jobDir: string;
  timeoutMs: number;
}) {
  // trivy fs /repo --format json
  const r = await runDocker({
    image: params.imgTrivy,
    args: ["fs", "/work/repo", "--format", "json", "--quiet"],
    mounts: [{ hostPath: params.jobDir, containerPath: "/work" }],
    workdir: "/",
    env: {
      // cache dentro del job para evitar ensuciar el host
      TRIVY_CACHE_DIR: "/work/.trivy-cache"
    },
    timeoutMs: params.timeoutMs
  });

  if (r.timedOut) throw new Error("trivy timed out");
  if (r.code !== 0) throw new Error(`trivy failed: ${r.stderr || r.stdout}`);

  // Montamos repo como /repo via bind adicional
  // Solución simple: usamos /work/repo montado en /work y apuntamos a /work/repo con -w
  // (si prefieres /repo, cambia el mount)
  // Para no complicar: re-ejecutamos con path real:
  const r2 = await runDocker({
    image: params.imgTrivy,
    args: ["fs", "/work/repo", "--format", "json", "--quiet"],
    mounts: [{ hostPath: params.jobDir, containerPath: "/work" }],
    timeoutMs: params.timeoutMs,
    env: { TRIVY_CACHE_DIR: "/work/.trivy-cache" }
  });

  if (r2.timedOut) throw new Error("trivy timed out");
  if (r2.code !== 0) throw new Error(`trivy failed: ${r2.stderr || r2.stdout}`);

  return safeJsonParse(r2.stdout);
}

export async function runSemgrep(params: {
  imgSemgrep: string;
  jobDir: string;
  timeoutMs: number;
}) {
  // semgrep --config auto --json
  const r = await runDocker({
    image: params.imgSemgrep,
    args: ["semgrep", "--config", "auto", "--json", "/work/repo"],
    mounts: [{ hostPath: params.jobDir, containerPath: "/work" }],
    timeoutMs: params.timeoutMs
  });

  if (r.timedOut) throw new Error("semgrep timed out");
  if (r.code !== 0) throw new Error(`semgrep failed: ${r.stderr || r.stdout}`);

  return safeJsonParse(r.stdout);
}

export async function runGrype(params: {
  imgGrype: string;
  jobDir: string;
  timeoutMs: number;
}) {
  // grype dir:/work/repo -o json
  const r = await runDocker({
    image: params.imgGrype,
    args: ["dir:/work/repo", "-o", "json"],
    mounts: [{ hostPath: params.jobDir, containerPath: "/work" }],
    timeoutMs: params.timeoutMs
  });

  if (r.timedOut) throw new Error("grype timed out");
  if (r.code !== 0) throw new Error(`grype failed: ${r.stderr || r.stdout}`);

  return safeJsonParse(r.stdout);
}

export function summarizeTrivy(json: any) {
  const results = Array.isArray(json?.Results) ? json.Results : [];
  let vulns = 0;
  let critical = 0, high = 0, medium = 0, low = 0;

  for (const r of results) {
    const vs = Array.isArray(r?.Vulnerabilities) ? r.Vulnerabilities : [];
    vulns += vs.length;
    for (const v of vs) {
      const sev = String(v?.Severity || "").toUpperCase();
      if (sev === "CRITICAL") critical++;
      else if (sev === "HIGH") high++;
      else if (sev === "MEDIUM") medium++;
      else if (sev === "LOW") low++;
    }
  }
  return { vulns, critical, high, medium, low };
}

export function summarizeSemgrep(json: any) {
  const findings = Array.isArray(json?.results) ? json.results : [];
  return { findings: findings.length };
}

export function summarizeGrype(json: any) {
  const matches = Array.isArray(json?.matches) ? json.matches : [];
  return { matches: matches.length };
}

function safeJsonParse(s: string) {
  try { return JSON.parse(s); }
  catch {
    // a veces herramientas meten warnings; intenta extraer último JSON “grande”
    const i = s.indexOf("{");
    const j = s.lastIndexOf("}");
    if (i >= 0 && j > i) return JSON.parse(s.slice(i, j + 1));
    throw new Error("Failed to parse JSON output");
  }
}
