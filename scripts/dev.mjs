import { spawn } from "node:child_process";

const commands = [
  { name: "VITE", command: "npm run dev:frontend" },
  { name: "API", command: "npm run dev:api" },
  { name: "ML", command: "npm run dev:ml" },
];

const children = [];
let shuttingDown = false;

function startProcess({ name, command }) {
  const child = spawn(command, [], {
    stdio: "inherit",
    shell: true,
  });

  child.on("exit", (code, signal) => {
    if (shuttingDown) {
      return;
    }

    if (code === 0) {
      return;
    }

    shuttingDown = true;
    console.error(`[${name}] exited with code ${code ?? "null"}${signal ? ` signal ${signal}` : ""}`);

    for (const proc of children) {
      if (!proc.killed) {
        proc.kill();
      }
    }

    process.exit(code ?? 1);
  });

  return child;
}

for (const entry of commands) {
  children.push(startProcess(entry));
}

function shutdown() {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  for (const proc of children) {
    if (!proc.killed) {
      proc.kill();
    }
  }
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
