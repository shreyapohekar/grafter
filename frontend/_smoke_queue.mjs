import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const require = createRequire(import.meta.url);
const root = path.dirname(fileURLToPath(import.meta.url));

function loadComponent(name, extraSource = "") {
  const tsxPath = path.join(root, "src", `${name}.tsx`);
  const source = fs.readFileSync(fs.existsSync(tsxPath) ? tsxPath : path.join(root, "src", `${name}.ts`), "utf8");
  const { outputText } = ts.transpileModule(source + extraSource, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  });
  const module = { exports: {} };
  const componentRequire = (id) => id.startsWith(".")
    ? loadComponent(id.slice(2))
    : require(id);
  vm.runInNewContext(
    "(function(require, module, exports) {" + outputText + "\n})",
  )(componentRequire, module, module.exports);
  return module.exports;
}

const { QueueRow } = loadComponent("QueueView", "\nexport { QueueRow };\n");
const job = {
  id: "job", scan_id: "scan", org: "example", state: "running", priority: 0,
  created_at: 1, updated_at: Date.now() / 1000,
  retry_count: 1, max_retries: 10,
  repos_total: 1000, repos_completed: 248, repos_failed: 572,
  workflows_scanned: 77076, findings_count: 8859,
  all_rules: true, selected_rule_count: 9, selected_rule_labels: [], selected_rules: [],
  activity: "example/repo: Checking policy", active_repositories: 8,
  requests_queued: 2, requests_in_flight: 8, requests_completed: 99,
  token_pool_size: 2, token_rotations: 1, pool_tokens_checked: 2,
  rate_limit_limit: 5000, rate_limit_remaining: 4500,
  pool_rate_limit_limit: 10000, pool_rate_limit_remaining: 9500,
  pool_rate_limit_reset: Date.now() / 1000 + 3600,
  pool_accounts: [
    { account: "alice", limit: 5000, remaining: 4500 },
    { account: "bob", limit: 5000, remaining: 5000 },
  ],
};
const render = (overrides = {}) => renderToStaticMarkup(React.createElement(QueueRow, {
  job: { ...job, ...overrides }, busy: false, onOpenScan() {}, onAction() {},
}));
const running = render();
for (const expected of [
  "248", "572", "180", "8859 unique findings saved",
  "workflow downloads (includes retries)", "Checking policy",
  "9500/10000", "4500/5000", "a***e 4500/5000", "b*b 5000/5000",
  "10 pending (2 queued, 8 in flight)", "99 responses received",
  "8 active repositories", "Retry will revisit them",
]) {
  assert.ok(running.includes(expected), expected);
}
assert.ok(!running.includes("alice") && !running.includes("bob"), "Account labels must follow existing login redaction");
const waiting = render({ state: "waiting_rate_limit" });
assert.ok(waiting.includes("findings are saved"));
assert.ok(waiting.includes("interrupted repositories restart from their beginning"));
assert.ok(render({ state: "failed" }).includes(">Retry</button>"));
assert.ok(render({ pool_rate_limit_reset: 1 }).includes("quota reset due; refreshing quota"));
assert.ok(!render({ pool_rate_limit_reset: 1 }).includes("next reset"));
assert.ok(render({ pool_tokens_checked: 1 }).includes("partial quota (1/2 tokens checked)"));
assert.ok(render({
  activity: undefined, requests_queued: undefined, requests_in_flight: undefined,
}).includes("backend must restart"));
console.log("queue saved findings, failures, account breakdown, requests and reset rendering: ok");
