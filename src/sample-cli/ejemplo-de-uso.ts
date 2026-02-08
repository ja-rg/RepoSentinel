import { $ } from "bun";

try {
    const docker = $`docker run --rm alpine:latest echo "Hello from Docker!"`;
    const output = await docker.text();
    console.log(output.trim());
} catch (error) {
    console.error("Error running Docker command:", error);
}