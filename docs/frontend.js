const els = {
  token: byId("token"),
  btnRefreshStatus: byId("btnRefreshStatus"),
  btnQuickCheck: byId("btnQuickCheck"),
  btnDeepCheck: byId("btnDeepCheck"),
  badgeApi: byId("badgeApi"),
  badgeDocker: byId("badgeDocker"),
  badgeRunners: byId("badgeRunners"),
  badgeQueue: byId("badgeQueue"),
  preflightChecks: byId("preflightChecks"),

  mainTabs: byId("mainTabs"),
  sourceMode: byId("sourceMode"),
  dockerMode: byId("dockerMode"),

  repoUrl: byId("repoUrl"),
  repoRef: byId("repoRef"),
  workspacePath: byId("workspacePath"),

  archiveFile: byId("archiveFile"),
  btnUploadArchive: byId("btnUploadArchive"),
  archiveUploadId: byId("archiveUploadId"),

  dockerImage: byId("dockerImage"),
  dockerSaveTar: byId("dockerSaveTar"),
  dockerRemoveAfter: byId("dockerRemoveAfter"),
  dockerfileFile: byId("dockerfileFile"),
  btnUploadDockerfile: byId("btnUploadDockerfile"),
  dockerfileUploadId: byId("dockerfileUploadId"),
  dockerfileImageTag: byId("dockerfileImageTag"),

  manifestFile: byId("manifestFile"),
  btnUploadManifest: byId("btnUploadManifest"),
  manifestUploadId: byId("manifestUploadId"),

  deployGateEnabled: byId("deployGateEnabled"),
  targetUrl: byId("targetUrl"),
  policyCritical: byId("policyCritical"),
  policyHigh: byId("policyHigh"),
  policyJson: byId("policyJson"),

  btnCreateSource: byId("btnCreateSource"),
  btnCreateDocker: byId("btnCreateDocker"),
  btnCreateManifest: byId("btnCreateManifest"),
  createOut: byId("createOut"),

  btnRefreshJobs: byId("btnRefreshJobs"),
  jobId: byId("jobId"),
  btnLoadJob: byId("btnLoadJob"),
  jobsTableBody: byId("jobsTableBody"),

  btnGetJob: byId("btnGetJob"),
  btnGetFindings: byId("btnGetFindings"),
  btnGetLogs: byId("btnGetLogs"),
  btnPoll: byId("btnPoll"),
  btnCancel: byId("btnCancel"),
  btnDeleteJob: byId("btnDeleteJob"),

  jobMeta: byId("jobMeta"),
  findingsList: byId("findingsList"),
  timeline: byId("timeline"),
  logsOut: byId("logsOut")
};

const state = {
  selectedJobId: "",
  selectedJobStatus: "",
  logCursor: 0,
  logPollTimer: null,
  systemTimer: null,
  jobsTimer: null,
  preflightTimer: null,
  latestPreflightOk: false,
  logs: []
};

bindEvents();
init().catch((error) => {
  print(els.createOut, { error: toErrorText(error) });
});

async function init() {
  syncSourceMode();
  syncDockerMode();
  await refreshSystemStatus();
  await runPreflight(false, false);
  await refreshJobs(false);

  state.systemTimer = setInterval(() => {
    refreshSystemStatus().catch(() => {
      // noop
    });
  }, 5000);

  state.jobsTimer = setInterval(() => {
    refreshJobs(false).catch(() => {
      // noop
    });
  }, 8000);

  state.preflightTimer = setInterval(() => {
    runPreflight(false, false).catch(() => {
      // noop
    });
  }, 20000);
}

function bindEvents() {
  els.btnRefreshStatus.addEventListener("click", () => refreshSystemStatus());
  els.btnQuickCheck.addEventListener("click", () => runPreflight(false, true));
  els.btnDeepCheck.addEventListener("click", () => runPreflight(true, true));

  els.mainTabs.addEventListener("click", onMainTabClick);
  els.sourceMode.addEventListener("change", syncSourceMode);
  els.dockerMode.addEventListener("change", syncDockerMode);

  els.btnUploadArchive.addEventListener("click", () => uploadFile("archive", els.archiveFile, els.archiveUploadId));
  els.btnUploadDockerfile.addEventListener("click", () => uploadFile("dockerfile", els.dockerfileFile, els.dockerfileUploadId));
  els.btnUploadManifest.addEventListener("click", () => uploadFile("k8s", els.manifestFile, els.manifestUploadId));

  els.btnCreateSource.addEventListener("click", createSourceJob);
  els.btnCreateDocker.addEventListener("click", createDockerJob);
  els.btnCreateManifest.addEventListener("click", createManifestJob);

  els.btnRefreshJobs.addEventListener("click", () => refreshJobs(true));
  els.btnLoadJob.addEventListener("click", () => loadSelectedJob(true));

  els.btnGetJob.addEventListener("click", () => getJobState());
  els.btnGetFindings.addEventListener("click", () => getFindings());
  els.btnGetLogs.addEventListener("click", () => getLogs(true));
  els.btnPoll.addEventListener("click", toggleAutoRefresh);
  els.btnCancel.addEventListener("click", () => cancelJob());
  els.btnDeleteJob.addEventListener("click", () => deleteJob());
}

function onMainTabClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const tab = target.dataset.tab;
  if (!tab) return;

  document.querySelectorAll("#mainTabs .tab").forEach((item) => item.classList.remove("is-active"));
  target.classList.add("is-active");

  document.querySelectorAll("[data-panel]").forEach((panel) => {
    if (!(panel instanceof HTMLElement)) return;
    panel.classList.toggle("is-active", panel.dataset.panel === tab);
  });
}

function syncSourceMode() {
  const mode = els.sourceMode.value;
  document.querySelectorAll("[data-source-mode]").forEach((group) => {
    if (!(group instanceof HTMLElement)) return;
    group.classList.toggle("is-active", group.dataset.sourceMode === mode);
  });
}

function syncDockerMode() {
  const mode = els.dockerMode.value;
  document.querySelectorAll("[data-docker-mode]").forEach((group) => {
    if (!(group instanceof HTMLElement)) return;
    group.classList.toggle("is-active", group.dataset.dockerMode === mode);
  });
}

async function refreshSystemStatus() {
  try {
    const [health, system] = await Promise.all([
      apiGet("/health"),
      apiGet("/system/status")
    ]);

    setBadge(els.badgeApi, health?.ok ? "API online" : "API issue", health?.ok ? "ok" : "error");

    const queued = Number(system?.jobs?.queued ?? 0);
    const running = Number(system?.jobs?.running ?? 0);
    const failed = Number(system?.jobs?.failed ?? 0);
    setBadge(els.badgeQueue, `Queue ${queued} | Running ${running} | Failed ${failed}`, failed > 0 ? "warn" : "neutral");

    const alive = Number(system?.runners?.alive ?? 0);
    const total = Number(system?.runners?.total ?? 0);
    setBadge(els.badgeRunners, `Runners ${alive}/${total}`, alive > 0 ? "ok" : "error");

    setBadge(
      els.badgeDocker,
      state.latestPreflightOk ? "Docker/tooling ready" : "Docker/tooling pending",
      state.latestPreflightOk ? "ok" : "warn"
    );

    if (Array.isArray(system?.recentJobs)) {
      renderJobsTable(system.recentJobs);
    }
  } catch (error) {
    setBadge(els.badgeApi, "API offline", "error");
    setBadge(els.badgeDocker, "Docker/tooling unknown", "warn");
    setBadge(els.badgeRunners, "Runners unknown", "warn");
    setBadge(els.badgeQueue, "Queue unknown", "warn");
    setCreateEnabled(false, "API offline");
    renderChecks([{ name: "api", ok: false, detail: toErrorText(error) }]);
  }
}

async function runPreflight(deep, force) {
  try {
    const qs = new URLSearchParams();
    if (deep) qs.set("deep", "1");
    if (force) qs.set("force", "1");

    const data = await apiGet(`/system/preflight?${qs.toString()}`);
    state.latestPreflightOk = Boolean(data?.ok);

    setBadge(
      els.badgeDocker,
      data?.ok ? `Docker/tooling ${data.mode}` : "Docker/tooling error",
      data?.ok ? "ok" : "error"
    );

    renderChecks(Array.isArray(data?.checks) ? data.checks : []);
    setCreateEnabled(Boolean(data?.ok), data?.ok ? "" : "Preflight fallo");
    return data;
  } catch (error) {
    state.latestPreflightOk = false;
    setCreateEnabled(false, "Preflight no disponible");
    renderChecks([{ name: "preflight", ok: false, detail: toErrorText(error) }]);
    throw error;
  }
}

function renderChecks(checks) {
  els.preflightChecks.innerHTML = "";
  if (!checks.length) {
    els.preflightChecks.textContent = "Sin datos";
    return;
  }

  for (const check of checks) {
    const row = document.createElement("div");
    row.className = `check ${check.ok ? "ok" : "error"}`;
    row.textContent = `${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.detail}`;
    els.preflightChecks.appendChild(row);
  }
}

function setCreateEnabled(enabled, reason) {
  [els.btnCreateSource, els.btnCreateDocker, els.btnCreateManifest].forEach((btn) => {
    btn.disabled = !enabled;
    btn.title = enabled ? "" : reason || "Deshabilitado";
  });
}

async function uploadFile(kind, fileInput, targetInput) {
  const file = fileInput.files?.[0];
  if (!file) {
    print(els.createOut, { error: "Selecciona archivo" });
    return;
  }

  const form = new FormData();
  form.set("file", file);
  form.set("kind", kind);

  const response = await fetch("/uploads", {
    method: "POST",
    headers: authHeaders(),
    body: form
  });
  const data = await response.json().catch(() => ({}));
  print(els.createOut, data);

  if (response.ok && data.uploadId) {
    targetInput.value = data.uploadId;
  }
}

async function createSourceJob() {
  const pre = await runPreflight(false, true);
  if (!pre.ok) {
    print(els.createOut, { error: "Preflight fallo", checks: pre.checks });
    return;
  }

  const mode = els.sourceMode.value;
  let payload = {};
  if (mode === "git_url") {
    payload = {
      repoUrl: els.repoUrl.value.trim(),
      ref: els.repoRef.value.trim() || undefined
    };
  } else if (mode === "workspace_path") {
    payload = { path: els.workspacePath.value.trim() };
  } else {
    payload = { uploadId: els.archiveUploadId.value.trim() };
  }

  await createJob(mode, payload, buildBlockPolicyOnly());
}

async function createDockerJob() {
  const pre = await runPreflight(false, true);
  if (!pre.ok) {
    print(els.createOut, { error: "Preflight fallo", checks: pre.checks });
    return;
  }

  const mode = els.dockerMode.value;
  if (mode === "docker_image") {
    await createJob("docker_image", {
      image: els.dockerImage.value.trim(),
      saveTar: els.dockerSaveTar.checked,
      removeImageAfterScan: els.dockerRemoveAfter.checked
    }, buildBlockPolicyOnly());
    return;
  }

  await createJob("dockerfile_upload", {
    uploadId: els.dockerfileUploadId.value.trim(),
    image: els.dockerfileImageTag.value.trim() || undefined,
    saveTar: els.dockerSaveTar.checked,
    removeImageAfterScan: els.dockerRemoveAfter.checked
  }, buildBlockPolicyOnly());
}

async function createManifestJob() {
  const pre = await runPreflight(true, true);
  if (!pre.ok) {
    print(els.createOut, { error: "Preflight profundo fallo", checks: pre.checks });
    return;
  }

  await createJob("k8s_manifest_upload", {
    uploadId: els.manifestUploadId.value.trim()
  }, buildManifestPolicy());
}

async function createJob(inputType, payload, policy) {
  const response = await fetch("/jobs", {
    method: "POST",
    headers: { ...authHeaders(), "content-type": "application/json" },
    body: JSON.stringify({ inputType, payload, policy })
  });

  const data = await response.json().catch(() => ({}));
  print(els.createOut, data);

  if (response.ok && data.jobId) {
    selectJob(data.jobId);
    state.logCursor = 0;
    await refreshJobs(true);
    await loadSelectedJob(true);
  }
}

function buildBlockPolicyOnly() {
  return {
    blockOn: {
      critical: toNum(els.policyCritical.value, 0),
      high: toNum(els.policyHigh.value, 0)
    }
  };
}

function buildManifestPolicy() {
  const raw = els.policyJson.value.trim();
  if (raw) {
    const parsed = parseJsonSafe(raw);
    if (!parsed) throw new Error("Policy JSON invalido");
    return parsed;
  }

  return {
    blockOn: {
      critical: toNum(els.policyCritical.value, 0),
      high: toNum(els.policyHigh.value, 0)
    },
    deployGate: {
      enabled: Boolean(els.deployGateEnabled.checked),
      targetUrl: els.targetUrl.value.trim() || undefined
    }
  };
}

async function refreshJobs(keepSelection) {
  const data = await apiGet("/jobs?limit=30");
  const jobs = Array.isArray(data?.jobs) ? data.jobs : [];
  renderJobsTable(jobs);

  if (!keepSelection && jobs.length > 0 && !state.selectedJobId) {
    selectJob(jobs[0].id);
  }
}

function renderJobsTable(jobs) {
  els.jobsTableBody.innerHTML = "";

  for (const job of jobs) {
    const tr = document.createElement("tr");
    tr.className = `st-${String(job.status || "").toLowerCase()}`;
    tr.innerHTML = `
      <td>${escapeHtml(shortId(job.id))}</td>
      <td>${escapeHtml(job.inputType || "")}</td>
      <td><span class="pill ${statusClass(job.status)}">${escapeHtml(job.status || "")}</span></td>
      <td>${Number(job.findingsCount || 0)}</td>
      <td>${escapeHtml(formatDate(job.createdAt))}</td>
      <td>${escapeHtml(job.inputSummary || "")}</td>
    `;
    tr.title = job.id;

    if (job.id === state.selectedJobId) {
      tr.classList.add("is-selected");
    }

    tr.addEventListener("click", async () => {
      selectJob(job.id);
      await loadSelectedJob(true);
    });

    els.jobsTableBody.appendChild(tr);
  }
}

function selectJob(jobId) {
  state.selectedJobId = jobId;
  els.jobId.value = jobId;
}

function selectedJobId() {
  const manual = els.jobId.value.trim();
  return manual || state.selectedJobId;
}

async function loadSelectedJob(resetLogs) {
  if (resetLogs) {
    state.logCursor = 0;
    state.logs = [];
    els.logsOut.textContent = "";
  }

  await Promise.all([getJobState(), getFindings(), getLogs(false)]);
}

async function getJobState() {
  const jobId = selectedJobId();
  if (!jobId) return;

  const job = await apiGet(`/jobs/${encodeURIComponent(jobId)}`);
  state.selectedJobStatus = String(job?.status || "");
  renderJobMeta(job);
}

function renderJobMeta(job) {
  const items = [
    ["ID", job.id],
    ["Estado", job.status],
    ["Input", job.input_type],
    ["Creado", formatDate(job.created_at)],
    ["Iniciado", formatDate(job.started_at)],
    ["Finalizado", formatDate(job.finished_at)],
    ["Deploy", job.deploy_status || "-"],
    ["Nuclei", job.nuclei_status || "-"],
    ["Workdir", job.workdir || "-"],
    ["Error", job.error || "-"]
  ];

  els.jobMeta.innerHTML = "";
  for (const [label, value] of items) {
    const card = document.createElement("article");
    card.className = "meta-card";
    card.innerHTML = `<h4>${escapeHtml(label)}</h4><p>${escapeHtml(String(value ?? "-"))}</p>`;
    els.jobMeta.appendChild(card);
  }
}

async function getFindings() {
  const jobId = selectedJobId();
  if (!jobId) return;

  const data = await apiGet(`/jobs/${encodeURIComponent(jobId)}/findings`);
  const findings = Array.isArray(data?.findings) ? data.findings : [];

  els.findingsList.innerHTML = "";
  if (!findings.length) {
    els.findingsList.innerHTML = `<div class="empty">Sin hallazgos para este job.</div>`;
    return;
  }

  for (const finding of findings) {
    const card = document.createElement("article");
    card.className = "finding-card";

    const summary = renderSummaryKv(finding.summary);
    card.innerHTML = `
      <header>
        <strong>${escapeHtml(finding.tool || "tool")}</strong>
        <span class="pill ${severityClass(finding.severity)}">${escapeHtml(String(finding.severity || "n/a"))}</span>
      </header>
      <small>${escapeHtml(formatDate(finding.createdAt))}</small>
      <div class="summary">${summary}</div>
      <details>
        <summary>Raw JSON</summary>
        <pre id="raw-${finding.id}">cargando...</pre>
      </details>
    `;

    const details = card.querySelector("details");
    if (details) {
      details.addEventListener("toggle", async () => {
        if (!details.open) return;
        const rawBox = card.querySelector(`#raw-${finding.id}`);
        if (!(rawBox instanceof HTMLElement)) return;
        if (rawBox.dataset.loaded === "1") return;

        try {
          const raw = await apiGet(`/jobs/${encodeURIComponent(jobId)}/findings/${encodeURIComponent(String(finding.id))}`);
          rawBox.textContent = JSON.stringify(raw?.raw ?? {}, null, 2);
          rawBox.dataset.loaded = "1";
        } catch (error) {
          rawBox.textContent = toErrorText(error);
          rawBox.dataset.loaded = "1";
        }
      });
    }

    els.findingsList.appendChild(card);
  }
}

function renderSummaryKv(summary) {
  if (!summary || typeof summary !== "object") return `<p>-</p>`;
  const entries = Object.entries(summary).slice(0, 8);
  if (!entries.length) return `<p>-</p>`;
  return entries
    .map(([k, v]) => `<div class="kv"><span>${escapeHtml(k)}</span><b>${escapeHtml(formatSimple(v))}</b></div>`)
    .join("");
}

async function getLogs(resetCursor) {
  const jobId = selectedJobId();
  if (!jobId) return;

  if (resetCursor) {
    state.logCursor = 0;
    state.logs = [];
    els.logsOut.textContent = "";
  }

  const data = await apiGet(`/jobs/${encodeURIComponent(jobId)}/logs?after=${state.logCursor}`);
  const logs = Array.isArray(data?.logs) ? data.logs : [];
  if (!logs.length) {
    renderTimeline(state.logs, state.selectedJobStatus);
    return;
  }

  state.logCursor = Number(logs[logs.length - 1]?.id ?? state.logCursor);
  state.logs.push(...logs);

  const lines = logs.map((row) => `${row.ts} [${row.level}] ${row.line}`).join("\n") + "\n";
  els.logsOut.textContent += lines;
  els.logsOut.scrollTop = els.logsOut.scrollHeight;

  renderTimeline(state.logs, state.selectedJobStatus);
}

function renderTimeline(logs, jobStatus) {
  const stages = [
    { key: "queued", label: "Job en cola" },
    { key: "prepare", label: "Preparando entorno" },
    { key: "clone", label: "Ingesta/Clonado" },
    { key: "trivy", label: "Trivy" },
    { key: "semgrep", label: "Semgrep" },
    { key: "grype", label: "Grype" },
    { key: "deploy", label: "Deploy manifest" },
    { key: "nuclei", label: "Nuclei" },
    { key: "done", label: "Finalizado" }
  ];

  const stageState = new Map(stages.map((s) => [s.key, "pending"]));
  stageState.set("queued", "done");

  let current = "prepare";
  stageState.set(current, "running");

  for (const log of logs) {
    const next = detectStage(log.line);
    if (!next) continue;
    if (next !== current) {
      stageState.set(current, stageState.get(current) === "error" ? "error" : "done");
      current = next;
      stageState.set(current, "running");
    }
    if (String(log.level).toLowerCase() === "error") {
      stageState.set(current, "error");
    }
  }

  if (jobStatus === "succeeded") {
    stageState.set(current, stageState.get(current) === "error" ? "error" : "done");
    stageState.set("done", "done");
  } else if (jobStatus === "failed" || jobStatus === "canceled") {
    stageState.set(current, "error");
    stageState.set("done", "error");
  }

  els.timeline.innerHTML = "";
  for (const stage of stages) {
    const li = document.createElement("li");
    li.className = `t-${stageState.get(stage.key)}`;
    li.innerHTML = `<span class="dot"></span><div><strong>${escapeHtml(stage.label)}</strong><small>${stageState.get(stage.key)}</small></div>`;
    els.timeline.appendChild(li);
  }
}

function detectStage(line) {
  const text = String(line || "").toLowerCase();
  if (text.includes("queued")) return "queued";
  if (text.includes("starting job") || text.includes("starting")) return "prepare";
  if (text.includes("cloning") || text.includes("clone") || text.includes("extract")) return "clone";
  if (text.includes("trivy")) return "trivy";
  if (text.includes("semgrep")) return "semgrep";
  if (text.includes("grype")) return "grype";
  if (text.includes("deploy") || text.includes("kubectl")) return "deploy";
  if (text.includes("nuclei")) return "nuclei";
  if (text.includes("completed") || text.includes("finished")) return "done";
  return null;
}

async function cancelJob() {
  const jobId = selectedJobId();
  if (!jobId) return;

  const response = await fetch(`/jobs/${encodeURIComponent(jobId)}/cancel`, {
    method: "POST",
    headers: authHeaders()
  });
  const data = await response.json().catch(() => ({}));
  print(els.createOut, data);
  await loadSelectedJob(false);
  await refreshJobs(true);
}

async function deleteJob() {
  const jobId = selectedJobId();
  if (!jobId) return;

  if (!confirm(`Eliminar job ${jobId} y todo lo asociado?`)) return;

  const response = await fetch(`/jobs/${encodeURIComponent(jobId)}`, {
    method: "DELETE",
    headers: authHeaders()
  });
  const data = await response.json().catch(() => ({}));
  print(els.createOut, data);

  if (response.ok) {
    if (state.logPollTimer) {
      clearInterval(state.logPollTimer);
      state.logPollTimer = null;
      els.btnPoll.textContent = "Auto refresh";
    }
    state.selectedJobId = "";
    state.selectedJobStatus = "";
    state.logCursor = 0;
    state.logs = [];
    els.jobId.value = "";
    els.jobMeta.innerHTML = "";
    els.findingsList.innerHTML = "";
    els.timeline.innerHTML = "";
    els.logsOut.textContent = "";
    await refreshJobs(false);
  }
}

function toggleAutoRefresh() {
  if (state.logPollTimer) {
    clearInterval(state.logPollTimer);
    state.logPollTimer = null;
    els.btnPoll.textContent = "Auto refresh";
    return;
  }

  state.logPollTimer = setInterval(async () => {
    try {
      await getJobState();
      await getLogs(false);
      await refreshJobs(true);
    } catch {
      // noop
    }
  }, 2000);

  els.btnPoll.textContent = "Detener auto refresh";
}

async function apiGet(path) {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`${response.status} ${response.statusText} ${body}`.trim());
  }
  return response.json().catch(() => ({}));
}

function authHeaders() {
  const token = els.token.value.trim();
  return token ? { authorization: `Bearer ${token}` } : {};
}

function setBadge(el, text, kind) {
  el.className = `badge ${kind}`;
  el.textContent = text;
}

function print(el, value) {
  el.textContent = JSON.stringify(value, null, 2);
}

function toNum(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function parseJsonSafe(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function statusClass(status) {
  const v = String(status || "").toLowerCase();
  if (v === "succeeded") return "ok";
  if (v === "running") return "info";
  if (v === "failed") return "error";
  if (v === "canceled") return "warn";
  return "neutral";
}

function severityClass(value) {
  const v = String(value || "").toLowerCase();
  if (v.includes("critical")) return "critical";
  if (v.includes("high")) return "high";
  if (v.includes("medium")) return "medium";
  if (v.includes("low")) return "low";
  return "neutral";
}

function shortId(value) {
  const s = String(value || "");
  return s.length > 18 ? `${s.slice(0, 10)}...${s.slice(-6)}` : s;
}

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function formatSimple(value) {
  if (value === null || value === undefined) return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function toErrorText(error) {
  if (!error) return "unknown error";
  if (error instanceof Error) return error.message;
  return String(error);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function byId(id) {
  return document.getElementById(id);
}
