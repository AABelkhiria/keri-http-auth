// The signify-ts commit the generators run against, read from the pinned dependency in package-lock.json.
import { readFileSync } from "node:fs";

const lock = JSON.parse(readFileSync(new URL("package-lock.json", import.meta.url), "utf8"));
const resolved = lock.packages?.["node_modules/signify-ts"]?.resolved ?? "";
const match = /#([0-9a-f]{40})$/.exec(resolved);
if (!match) {
  throw new Error(`package-lock.json does not pin signify-ts to a commit: ${resolved}`);
}

export const referenceSha = match[1];
