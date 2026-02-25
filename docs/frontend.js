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
  jobOut: byId("jobOut"),
  jobId: byId("jobId"),
  btnRefreshJobs: byId("btnRefreshJobs"),
  btnLoadJob: byId("btnLoadJob"),
  jobsTableBody: byId("jobsTableBody"),
  btnGetJob: byId("btnGetJob"),
  btnGetFindings: byId("btnGetFindings"),
  btnGetLogs: byId("btnGetLogs"),
  btnPoll: byId("btnPoll"),
  btnCancel: byId("btnCancel"),
  jobStateOut: byId("jobStateOut"),
  findingsOut: byId("findingsOut"),
  logsOut: byId("logsOut"),

  repoMode: byId("repoMode"),
  repoUrl: byId("repoUrl"),
  repoRef: byId("repoRef"),
  workspacePath: byId("workspacePath"),

  archiveFile: byId("archiveFile"),
  archiveUploadId: byId("archiveUploadId"),

  dockerImage: byId("dockerImage"),
  dockerSaveTar: byId("dockerSaveTar"),
  dockerRemoveAfter: byId("dockerRemoveAfter"),

  dockerfileFile: byId("dockerfileFile"),
  dockerfileUploadId: byId("dockerfileUploadId"),

  manifestFile: byId("manifestFile"),
  manifestUploadId: byId("manifestUploadId"),

  deployGateEnabled: byId("deployGateEnabled"),
  targetUrl: byId("targetUrl"),
  policyCritical: byId("policyCritical"),
  policyHigh: byId("policyHigh"),
  policyJson: byId("policyJson")
};

const state = {
  selectedJobId: "",
  logCursor: 0,
  logPollTimer: null,
  systemTimer: null,
  jobsTimer: null,
  preflightTimer: null,
  latestPreflightOk: false
};

bindEvents();
init().catch((error) => {
  print(els.jobOut, { error: toErrorText(error) });
});

async function init() {
  await refreshSystemStatus();
  await runPreflight(false, false);
  await refreshJobs();

  state.systemTimer = setInterval(() => {
    refreshSystemStatus().catch(() => {
      // handled by refreshSystemStatus
    });
  }, 5000);

  state.jobsTimer = setInterval(() => {
    refreshJobs(false).catch(() => {
      // ignore background errors
    });
  }, 8000);

  state.preflightTimer = setInterval(() => {
    runPreflight(false, false).catch(() => {
      // ignore background errors
    });
  }, 20000);
}

function bindEvents() {
  els.btnRefreshStatus.addEventListener("click", () => refreshSystemStatus());
  els.btnQuickCheck.addEventListener("click", () => runPreflight(false, true));
  els.btnDeepCheck.addEventListener("click", () => runPreflight(true, true));

  byId("jobTabs").addEventListener("click", onTabClick);
  document.querySelectorAll("[data-upload]").forEach((btn) => {
    btn.addEventListener("click", onUploadClick);
  });
  document.querySelectorAll("[data-create]").forEach((btn) => {
    btn.addEventListener("click", onCreateClick);
  });

  els.btnRefreshJobs.addEventListener("click", () => refreshJobs(true));
  els.btnLoadJob.addEventListener("click", () => loadSelectedJob(true));

  els.btnGetJob.addEventListener("click", () => getJobState());
  els.btnGetFindings.addEventListener("click", () => getFindings());
  els.btnGetLogs.addEventListener("click", () => getLogs(true));
  els.btnPoll.addEventListener("click", toggleJobAutoRefresh);
  els.btnCancel.addEventListener("click", () => cancelJob());
}

async function refreshSystemStatus() {
  try {
    const [health, status] = await Promise.all([
      apiGet("/health"),
      apiGet("/system/status")
    ]);

    setBadge(els.badgeApi, health?.ok ? "API: online" : "API: issue", health?.ok ? "ok" : "error");

    const queueCount = Number(status?.jobs?.queued ?? 0);
    const runningCount = Number(status?.jobs?.running ?? 0);
    const failedCount = Number(status?.jobs?.failed ?? 0);
    setBadge(
      els.badgeQueue,
      `Queue: ${queueCount} / Running: ${runningCount} / Failed: ${failedCount}`,
      failedCount > 0 ? "warn" : "neutral"
    );

    const aliveRunners = Number(status?.runners?.alive ?? 0);
    const totalRunners = Number(status?.runners?.total ?? 0);
    setBadge(
      els.badgeRunners,
      `Runners: ${aliveRunners}/${totalRunners}`,
      aliveRunners > 0 ? "ok" : "error"
    );

    const dockerOk = state.latestPreflightOk;
    setBadge(els.badgeDocker, dockerOk ? "Docker/tooling: ready" : "Docker/tooling: pending", dockerOk ? "ok" : "warn");

    if (Array.isArray(status?.recentJobs)) {
      renderJobsTable(status.recentJobs);
    }
  } catch (error) {
    setBadge(els.badgeApi, "API: offline", "error");
    setBadge(els.badgeDocker, "Docker/tooling: unknown", "warn");
    setBadge(els.badgeRunners, "Runners: unknown", "warn");
    setBadge(els.badgeQueue, "Queue: unknown", "warn");
    setCreateEnabled(false, "API no disponible");
    renderChecks([
      {
        name: "api_connection",
        ok: false,
        required: true,
        detail: toErrorText(error)
      }
    ]);
  }
}

async function runPreflight(deep, force) {
  try {
    const query = new URLSearchParams();
    if (deep) query.set("deep", "1");
    if (force) query.set("force", "1");

    const result = await apiGet(`/system/preflight?${query.toString()}`);
    state.latestPreflightOk = Boolean(result?.ok);

    renderChecks(Array.isArray(result?.checks) ? result.checks : []);
    setCreateEnabled(Boolean(result?.ok), result?.ok ? "" : "Preflight no saludable");

    setBadge(
      els.badgeDocker,
      result?.ok ? `Docker/tooling: ${result.mode || "ok"}` : "Docker/tooling: error",
      result?.ok ? "ok" : "error"
    );

    return result;
  } catch (error) {
    state.latestPreflightOk = false;
    setCreateEnabled(false, "Preflight no disponible");
    renderChecks([
      { name: "preflight", ok: false, required: true, detail: toErrorText(error) }
    ]);
    throw error;
  }
}

function renderChecks(checks) {
  els.preflightChecks.innerHTML = "";
  if (!checks.length) {
    els.preflightChecks.textContent = "Sin datos de preflight";
    return;
  }

  for (const check of checks) {
    const line = document.createElement("div");
    line.className = `check ${check.ok ? "ok" : "error"}`;
    line.textContent = `${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.detail}`;
    els.preflightChecks.appendChild(line);
  }
}

function setCreateEnabled(enabled, reason) {
  document.querySelectorAll("[data-create]").forEach((btn) => {
    btn.disabled = !enabled;
    btn.title = enabled ? "" : reason || "Deshabilitado";
  });
}

function onTabClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const tabName = target.dataset.tab;
  if (!tabName) return;

  document.querySelectorAll(".tab").forEach((el) => el.classList.remove("is-active"));
  target.classList.add("is-active");

  document.querySelectorAll(".panel").forEach((el) => {
    if (!(el instanceof HTMLElement)) return;
    el.classList.toggle("is-active", el.dataset.panel === tabName);
  });
}

async function onUploadClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const kind = target.dataset.upload;
  if (!kind) return;

  try {
    const map = {
      archive: [els.archiveFile, els.archiveUploadId],
      dockerfile: [els.dockerfileFile, els.dockerfileUploadId],
      k8s: [els.manifestFile, els.manifestUploadId]
    };
    const item = map[kind];
    if (!item) return;

    const fileInput = item[0];
    const outputInput = item[1];
    const file = fileInput.files?.[0];
    if (!file) {
      print(els.jobOut, { error: "Selecciona un archivo primero" });
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
    print(els.jobOut, data);
    if (response.ok && data.uploadId) {
      outputInput.value = data.uploadId;
    }
  } catch (error) {
    print(els.jobOut, { error: toErrorText(error) });
  }
}

async function onCreateClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const mode = target.dataset.create;
  if (!mode) return;

  try {
    const quick = await runPreflight(false, true);
    if (!quick.ok) {
      print(els.jobOut, {
        error: "Preflight fallo. Corrige Docker/tooling antes de crear jobs.",
        checks: quick.checks
      });
      return;
    }

    const { inputType, payload } = buildJobByMode(mode);
    const policy = buildPolicy();

    const response = await fetch("/jobs", {
      method: "POST",
      headers: { ...authHeaders(), "content-type": "application/json" },
      body: JSON.stringify({ inputType, payload, policy })
    });

    const data = await response.json().catch(() => ({}));
    print(els.jobOut, data);

    if (response.ok && data.jobId) {
      setSelectedJob(data.jobId);
      state.logCursor = 0;
      await refreshJobs(true);
      await loadSelectedJob(true);
    }
  } catch (error) {
    print(els.jobOut, { error: toErrorText(error) });
  }
}

function buildJobByMode(mode) {
  if (mode === "repo") {
    const repoMode = els.repoMode.value;
    if (repoMode === "git_url") {
      return {
        inputType: "git_url",
        payload: {
          repoUrl: els.repoUrl.value.trim(),
          ref: els.repoRef.value.trim() || undefined,
          manifestUploadId: els.manifestUploadId.value.trim() || undefined
        }
      };
    }

    return {
      inputType: "workspace_path",
      payload: {
        path: els.workspacePath.value.trim(),
        manifestUploadId: els.manifestUploadId.value.trim() || undefined
      }
    };
  }

  if (mode === "archive") {
    return {
      inputType: "archive_upload",
      payload: {
        uploadId: els.archiveUploadId.value.trim(),
        manifestUploadId: els.manifestUploadId.value.trim() || undefined
      }
    };
  }

  if (mode === "docker-image") {
    return {
      inputType: "docker_image",
      payload: {
        image: els.dockerImage.value.trim(),
        saveTar: els.dockerSaveTar.checked,
        removeImageAfterScan: els.dockerRemoveAfter.checked,
        manifestUploadId: els.manifestUploadId.value.trim() || undefined
      }
    };
  }

  if (mode === "dockerfile") {
    return {
      inputType: "dockerfile_upload",
      payload: {
        uploadId: els.dockerfileUploadId.value.trim(),
        manifestUploadId: els.manifestUploadId.value.trim() || undefined
      }
    };
  }

  if (mode === "manifest") {
    return {
      inputType: "k8s_manifest_upload",
      payload: {
        uploadId: els.manifestUploadId.value.trim()
      }
    };
  }

  throw new Error(`Modo no soportado: ${mode}`);
}

function buildPolicy() {
  const raw = els.policyJson.value.trim();
  if (raw) {
    const parsed = parseJsonSafe(raw);
    if (parsed) return parsed;
    throw new Error("Policy JSON override invalido");
  }

  const policy = {
    blockOn: {
      critical: Number(els.policyCritical.value || "0"),
      high: Number(els.policyHigh.value || "0")
    }
  };

  if (els.deployGateEnabled.checked) {
    policy.deployGate = {
      enabled: true,
      targetUrl: els.targetUrl.value.trim() || undefined
    };
  }

  return policy;
}

async function refreshJobs(selectFirst) {
  const data = await apiGet("/jobs?limit=25");
  const jobs = Array.isArray(data?.jobs) ? data.jobs : [];
  renderJobsTable(jobs);

  if (selectFirst && jobs.length > 0 && !state.selectedJobId) {
    setSelectedJob(jobs[0].id);
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
      <td>${escapeHtml(job.status || "")}</td>
      <td>${Number(job.findingsCount || 0)}</td>
      <td>${escapeHtml(formatDate(job.createdAt))}</td>
      <td>${escapeHtml(job.inputSummary || "")}</td>
    `;
    tr.title = job.id;
    tr.addEventListener("click", async () => {
      setSelectedJob(job.id);
      await loadSelectedJob(true);
    });
    els.jobsTableBody.appendChild(tr);
  }
}

async function loadSelectedJob(resetLogs) {
  const id = selectedJobId();
  if (!id) return;
  if (resetLogs) {
    state.logCursor = 0;
    els.logsOut.textContent = "";
  }

  await Promise.all([getJobState(), getFindings(), getLogs(false)]);
}

function selectedJobId() {
  const manual = els.jobId.value.trim();
  return manual || state.selectedJobId;
}

function setSelectedJob(jobId) {
  state.selectedJobId = jobId;
  els.jobId.value = jobId;
}

async function getJobState() {
  const id = selectedJobId();
  if (!id) return;
  const data = await apiGet(`/jobs/${encodeURIComponent(id)}`);
  print(els.jobStateOut, data);
}

async function getFindings() {
  const id = selectedJobId();
  if (!id) return;
  const data = await apiGet(`/jobs/${encodeURIComponent(id)}/findings`);
  print(els.findingsOut, data);
}

async function getLogs(resetCursor) {
  const id = selectedJobId();
  if (!id) return;
  if (resetCursor) {
    state.logCursor = 0;
    els.logsOut.textContent = "";
  }

  const data = await apiGet(`/jobs/${encodeURIComponent(id)}/logs?after=${state.logCursor}`);
  const logs = Array.isArray(data?.logs) ? data.logs : [];
  if (!logs.length) return;

  state.logCursor = Number(logs[logs.length - 1]?.id ?? state.logCursor);

  const lines = logs.map((row) => `${row.ts} [${row.level}] ${row.line}`).join("\n") + "\n";
  els.logsOut.textContent += lines;
  els.logsOut.scrollTop = els.logsOut.scrollHeight;
}

async function cancelJob() {
  const id = selectedJobId();
  if (!id) return;

  const response = await fetch(`/jobs/${encodeURIComponent(id)}/cancel`, {
    method: "POST",
    headers: authHeaders()
  });
  const data = await response.json().catch(() => ({}));
  print(els.jobStateOut, data);
  await refreshJobs(false);
}

function toggleJobAutoRefresh() {
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
    } catch {
      // ignore intermittent poll errors
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

function setBadge(el, text, stateClass) {
  el.className = `badge ${stateClass || "neutral"}`;
  el.textContent = text;
}

function shortId(value) {
  const v = String(value || "");
  return v.length > 18 ? `${v.slice(0, 10)}...${v.slice(-6)}` : v;
}

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function parseJsonSafe(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function print(el, value) {
  el.textContent = JSON.stringify(value, null, 2);
}

function byId(id) {
  return document.getElementById(id);
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
