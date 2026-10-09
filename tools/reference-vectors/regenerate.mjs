// Runs every fixture generator against the pinned signify-ts; with --check, fails if any fixture changed.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("../..", import.meta.url));
const generators = readdirSync(here)
  .filter((name) => name.endsWith(".mjs") && !["reference.mjs", "regenerate.mjs"].includes(name))
  .sort();

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.error) {
    throw result.error;
  }
  return result.status ?? 1;
}

for (const generator of generators) {
  if (run(process.execPath, [generator, "--write"], here) !== 0) {
    process.exit(1);
  }
}

if (process.argv.includes("--check")) {
  process.exit(run("git", ["diff", "--exit-code", "--stat", "--", "fixtures"], root));
}
