// Runs the Rust integration tests against the local Supabase stack.
// Usage: pnpm db:start && pnpm test:e2e [-- extra cargo test args]
import { execFileSync, spawnSync } from "node:child_process";

// The CLI may print notices before the JSON object.
const out = execFileSync("pnpm", ["exec", "supabase", "status", "-o", "json"], { encoding: "utf8" });
const status = JSON.parse(out.slice(out.indexOf("{"), out.lastIndexOf("}") + 1));

const env = {
  ...process.env,
  HERMES_TEST_SUPABASE_URL: status.API_URL,
  HERMES_TEST_SUPABASE_ANON_KEY: status.ANON_KEY,
  HERMES_TEST_DB_URL: status.DB_URL,
};
const extra = process.argv.slice(2).filter((a) => a !== "--");
const result = spawnSync(
  "cargo",
  ["test", "-p", "hermes-core", "--test", "local_supabase", "--", "--ignored", ...extra],
  { stdio: "inherit", env },
);
process.exit(result.status ?? 1);
