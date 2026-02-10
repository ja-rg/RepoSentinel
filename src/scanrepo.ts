import { parseArgs } from "util";
import showHelp from "./scope/help";
import { $ } from "bun";

const { values, positionals } = parseArgs({
    args: Bun.argv,
    options: {
        help: {
            type: "boolean",
            short: "h",
            description: "Show this help message and exit",
        },
    },
    strict: true,
    allowPositionals: true,
});

if (values.help) {
    showHelp();
    // Exit the process after showing help
    process.exit(0);
}

// Validate that a path is provided (the first is bun.exe, the second is the script name scanrepo.ts, so we need at least 3 arguments)
if (positionals.length < 3) {
    showHelp();
    console.error("Error: No path provided.");
    process.exit(1);
}

const repoPath = positionals[2];

if (!repoPath) {
    showHelp();
    console.error("Error: No path provided.");
    process.exit(1);
}

// Sanity check for the provided path (non empty and must contain the .git directory)
import {
    exists
} from 'node:fs/promises'

const gitPath = `${repoPath}/.git`;

if (!await exists(gitPath)) {
    console.error("Error: The provided path does not appear to be a valid Git repository.");
    process.exit(1);
}

// Pull the latest Semgrep Docker image
try {
    console.log("Pulling the latest Semgrep Docker image...");
    await $`docker pull returntocorp/semgrep:latest`;
} catch (error) {
    console.error("Error pulling Semgrep Docker image:", error);
    process.exit(1);
}

// Semgrep scan command using Docker
try {
    console.log(`Scanning repository at: ${repoPath}`);
    const scan = await $`docker run --rm -v ${repoPath}:/repo returntocorp/semgrep:latest semgrep --config=auto /repo`;
    await Bun.write('./dist/semgrep_results.txt', scan.stdout);
    console.log("Scan completed. Results saved to dist/semgrep_results.txt");
} catch (error) {
    console.error("Error during scanning:", error);
    process.exit(1);
}