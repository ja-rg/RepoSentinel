import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { runDocker } from "./docker";
import { $ } from "bun";

export async function dockerGitClone(params: {
  imgGit: string;
  repoUrl: string;
  ref?: string | null;
  timeoutMs: number;
  workRoot: string;
  jobId: string;
}) {
  const fullPath = process.cwd();
  const jobDir = join(fullPath, params.workRoot, params.jobId);
  const repoDir = join(jobDir, "repo");

  mkdirSync(jobDir, { recursive: true });
  rmSync(repoDir, { recursive: true, force: true });
  mkdirSync(repoDir, { recursive: true });

  // Clonamos dentro de /work/repo montado
  // Nota: para repos privados necesitarías token/ssh; aquí lo dejamos público.
  const cloneArgs = [
    "clone",
    "--depth",
    "1",
    params.repoUrl,
    "/work/repo",
  ];

  const clone = await runDocker({
    image: params.imgGit,
    args: cloneArgs,
    mounts: [{ hostPath: jobDir, containerPath: "/work" }],
    timeoutMs: params.timeoutMs,
  });

  if (clone.timedOut) throw new Error("git clone timed out");
  if (clone.code !== 0) {
    throw new Error(`git clone failed: ${clone.stderr || clone.stdout}`);
  }

  // Checkout ref si viene (branch/tag/commit)
  if (params.ref) {
    const co = await runDocker({
      image: params.imgGit,
      args: [
        "sh",
        "-lc",
        `cd /work/repo && git fetch --all --tags && git checkout ${
          shellEscape(params.ref)
        }`,
      ],
      mounts: [{ hostPath: jobDir, containerPath: "/work" }],
      timeoutMs: params.timeoutMs,
    });
    if (co.timedOut) throw new Error("git checkout timed out");
    if (co.code !== 0) {
      throw new Error(`git checkout failed: ${co.stderr || co.stdout}`);
    }
  }

  return { jobDir, repoDir };
}

// escape mínimo para refs (evita espacios raros)
function shellEscape(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
