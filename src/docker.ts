export type DockerMount = {
  hostPath: string;
  containerPath: string;
  readOnly?: boolean;
};

export type RunResult = {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
};

function buildDockerArgs(params: {
  image: string;
  args: string[];
  mounts?: DockerMount[];
  workdir?: string;
  env?: Record<string, string>;
}) {
  const out: string[] = ["run", "--rm"];

  // Montajes
  for (const m of params.mounts ?? []) {
    const ro = m.readOnly ? ":ro" : "";
    out.push("-v", `${m.hostPath}:${m.containerPath}${ro}`);
  }

  // Workdir
  if (params.workdir) out.push("-w", params.workdir);

  // Env
  for (const [k, v] of Object.entries(params.env ?? {})) {
    out.push("-e", `${k}=${v}`);
  }

  out.push(params.image, ...params.args);
  return out;
}

export async function runDocker(params: {
  image: string;
  args: string[];
  mounts?: DockerMount[];
  workdir?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}): Promise<RunResult> {
  const dockerArgs = buildDockerArgs(params);

  const proc = Bun.spawn(["docker", ...dockerArgs], {
    stdout: "pipe",
    stderr: "pipe"
  });

  let timedOut = false;
  let timeout: Timer | undefined;
  if (params.timeoutMs && params.timeoutMs > 0) {
    timeout = setTimeout(() => {
      timedOut = true;
      try { proc.kill("SIGKILL"); } catch {}
    }, params.timeoutMs);
  }

  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited
  ]);

  if (timeout) clearTimeout(timeout);

  return { code, stdout, stderr, timedOut };
}
