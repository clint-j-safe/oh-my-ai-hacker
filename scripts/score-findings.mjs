#!/usr/bin/env node
/**
 * Score a scan's output against the human black-box ground truth.
 * Usage: node scripts/score-findings.mjs <scan-output.txt> [ground-truth.json]
 * Matches a ground-truth finding if the scan text mentions its endpoint OR
 * enough of its distinguishing keywords. Prints coverage and the misses.
 */
import { readFileSync } from "node:fs";

const [, , scanPath, gtPath = new URL("./ground-truth-blackbox.json", import.meta.url).pathname] = process.argv;
if (!scanPath) { console.error("usage: score-findings.mjs <scan-output.txt> [ground-truth.json]"); process.exit(2); }

const text = readFileSync(scanPath, "utf8").toLowerCase();
const gt = JSON.parse(readFileSync(gtPath, "utf8"));

const rows = gt.findings.map((f) => {
  const endpointHit = f.endpoint ? text.includes(f.endpoint.toLowerCase()) : false;
  const kw = f.any.filter((k) => text.includes(k.toLowerCase()));
  // endpoint + any keyword; or a strong keyword cluster (>=3) when the report
  // describes the issue without quoting the exact path; or, for findings with no
  // endpoint anchor, >=2 keywords.
  const matched = f.endpoint ? ((endpointHit && kw.length > 0) || kw.length >= 3) : kw.length >= 2;
  return { ...f, endpointHit, kw, matched };
});

const total = rows.length;
const hit = rows.filter((r) => r.matched);
const authRows = rows.filter((r) => r.auth);
const unauthRows = rows.filter((r) => !r.auth);
const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);

console.log(`\nCOVERAGE  ${hit.length}/${total}  (${pct(hit.length, total)}%)`);
console.log(`  unauthenticated : ${unauthRows.filter(r=>r.matched).length}/${unauthRows.length}`);
console.log(`  authenticated   : ${authRows.filter(r=>r.matched).length}/${authRows.length}`);
console.log("\nPER-FINDING");
for (const r of rows) {
  console.log(`  ${r.matched ? "HIT " : "MISS"} ${r.id.padEnd(4)} [${r.severity.padEnd(8)}${r.auth ? " auth" : "     "}] ${r.title}`);
  if (!r.matched) console.log(`         endpoint=${r.endpoint || "-"} seen=${r.endpointHit} kw=${r.kw.join("|") || "none"}`);
}
const missed = rows.filter((r) => !r.matched);
console.log(`\nMISSED (${missed.length}): ${missed.map((m) => m.id).join(", ") || "none"}`);
