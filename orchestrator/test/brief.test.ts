import { test } from "node:test";
import assert from "node:assert/strict";
import { buildHunterBrief, deriveOrigins, resolveRelativeEndpoint, type HunterBriefState } from "../src/brief.js";
import { VULN_CLASSES } from "../src/vuln-classes.js";

const EMPTY_STATE: HunterBriefState = {
  attackSurface: [], recoveredIntel: {}, proved: [], attempted: [],
  turnsRemaining: 40, findingsRemaining: 12,
};

function section(xml: string, name: string): string {
  const m = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(xml);
  assert.ok(m, `expected a <${name}> section in the brief`);
  return m![1];
}

test("the brief is well-formed: opens and closes with the root tag, one concern per house-style tag", () => {
  const xml = buildHunterBrief(EMPTY_STATE);
  assert.match(xml, /^<safe_ai_hacker_hunter>/);
  assert.match(xml.trim(), /<\/safe_ai_hacker_hunter>$/);
  for (const tag of [
    "system_identity", "operational_principles", "attack_surface", "recovered_intel",
    "already_proved", "target", "remaining_targets", "dead_ends", "thinking_framework", "parameter_analysis",
    "prioritization_rules", "evidence_discipline", "tool_guidance", "output_contract", "budget",
  ]) {
    assert.match(xml, new RegExp(`<${tag}>`), `missing <${tag}>`);
    assert.match(xml, new RegExp(`</${tag}>`), `missing </${tag}>`);
  }
});

test("beat 1 (empty spine): state-derived sections are EMPTY but carry an explicit populate instruction, not omitted", () => {
  const xml = buildHunterBrief(EMPTY_STATE);

  const attackSurface = section(xml, "attack_surface");
  assert.doesNotMatch(attackSurface, /<endpoint\b/, "beat 1 must not fabricate endpoint entries");
  assert.match(attackSurface, /map the attack surface/i);

  const recoveredIntel = section(xml, "recovered_intel");
  assert.doesNotMatch(recoveredIntel, /<api_base>/);
  assert.match(recoveredIntel, /recover|extract/i);

  const alreadyProved = section(xml, "already_proved");
  assert.doesNotMatch(alreadyProved, /<proved\b/);
  assert.match(alreadyProved, /nothing has been proved/i);

  const deadEnds = section(xml, "dead_ends");
  assert.doesNotMatch(deadEnds, /<attempt\b/);
  assert.match(deadEnds, /nothing has been tried/i);
});

test("a populated spine emits its endpoints, proved list and dead ends into the corresponding sections", () => {
  const state: HunterBriefState = {
    attackSurface: [
      { url: "http://10.0.0.1:3000/api/users", method: "GET", status: 200, content_type: "application/json", semantic_role: "data retrieval" },
    ],
    recoveredIntel: { api_base: "http://10.0.0.1:4000", source_maps_seen: true },
    proved: [
      { vuln_class: "idor", endpoint: "http://10.0.0.1:3000/api/users/2", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-abc12345" },
    ],
    attempted: [
      { vuln_class: "sqli", endpoint: "http://10.0.0.1:3000/api/users", invariant_type: "body_contains", outcome: "FALSE_POSITIVE", why: "control matched exploit" },
    ],
    turnsRemaining: 10, findingsRemaining: 3,
  };
  const xml = buildHunterBrief(state);

  // URLs are now rendered RELATIVE to the target base (:3000 is primary here — most
  // frequent), and the <target> block carries the base legend once.
  const target = section(xml, "target");
  assert.match(target, /BASE \(primary\) = http:\/\/10\.0\.0\.1:3000/);

  const attackSurface = section(xml, "attack_surface");
  assert.match(attackSurface, /url="\/api\/users"/);
  assert.match(attackSurface, /method="GET"/);
  assert.match(attackSurface, /status="200"/);

  const recoveredIntel = section(xml, "recovered_intel");
  // :4000 is a secondary origin -> aliased
  assert.match(recoveredIntel, /<api_base>\[:4000\]<\/api_base>/);

  const alreadyProved = section(xml, "already_proved");
  assert.match(alreadyProved, /vuln_class="idor"/);
  assert.match(alreadyProved, /endpoints="\/api\/users\/2"/);

  const deadEnds = section(xml, "dead_ends");
  assert.match(deadEnds, /vuln_class="sqli"/);
  assert.match(deadEnds, /control matched exploit/);

  const budget = section(xml, "budget");
  assert.match(budget, /<turns_remaining>10<\/turns_remaining>/);
  assert.match(budget, /<findings_remaining>3<\/findings_remaining>/);
});

test("a proved (vuln_class, endpoint) appears in <already_proved>, AND the vuln_class enum / invariant grammar still appear in <output_contract>", () => {
  const state: HunterBriefState = {
    ...EMPTY_STATE,
    proved: [
      { vuln_class: "path_traversal", endpoint: "http://10.0.0.1:3000/download", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-deadbeef" },
    ],
  };
  const xml = buildHunterBrief(state);
  const alreadyProved = section(xml, "already_proved");
  assert.match(alreadyProved, /vuln_class="path_traversal"/);
  // single origin -> primary base -> relative
  assert.match(alreadyProved, /endpoints="\/download"/);

  const outputContract = section(xml, "output_contract");
  for (const v of VULN_CLASSES) {
    assert.ok(outputContract.includes(v), `output_contract must still list ${v}`);
  }
  assert.match(outputContract, /body_contains/);
  assert.match(outputContract, /status_in/);
  assert.match(outputContract, /response_asserted/);
});

test("the composer contains no target-hostname literal of its own — every URL in the output came from state", () => {
  const xml = buildHunterBrief(EMPTY_STATE);
  assert.doesNotMatch(xml, /https?:\/\//, "an empty-state brief must not contain any URL");
});

test("recovered_intel rendering is BOUNDED: a huge intel map does not bloat the brief (regression: 79KB intel stalled the hunter)", () => {
  const bigIntel: Record<string, unknown> = {};
  for (let i = 0; i < 300; i++) bigIntel[`noise_${i}`] = "x".repeat(400);
  bigIntel["api_route_table"] = "/login /signup /contactUs /loan/apply";
  bigIntel["jwt_key_source"] = "the HS256 key literal 'unsafebank'";
  const xml = buildHunterBrief({ ...EMPTY_STATE, recoveredIntel: bigIntel as any });
  const sect = section(xml, "recovered_intel");
  assert.ok(sect.length < 14000, `recovered_intel must stay bounded, got ${sect.length} chars`);
  // high-signal keys are prioritised into the shown set
  assert.match(sect, /api_route_table/);
  assert.match(sect, /jwt_key_source/);
  assert.match(sect, /omitted to keep this brief lean/);
});

test("already_proved rendering is BOUNDED: an accumulated spine groups by class and caps endpoints (regression: 27KB per-finding rows bloated every turn)", () => {
  // 250 banked findings across a few recurring classes — the shape a long-running,
  // accumulated engagement produces. The old per-finding format made this ~27 KB.
  const proved = [] as HunterBriefState["proved"];
  for (let i = 0; i < 250; i++) {
    const cls = ["rate_limit_absence", "clickjacking", "info_disclosure"][i % 3];
    proved.push({ vuln_class: cls, endpoint: `http://10.0.0.1:3000/route/${i}`, invariant_type: "response_asserted", verdict: "CONFIRMED", finding_id: `SAHW-${i}` });
  }
  const xml = buildHunterBrief({ ...EMPTY_STATE, proved });
  const sect = section(xml, "already_proved");
  assert.ok(sect.length < 8000, `already_proved must stay bounded, got ${sect.length} chars`);
  // one grouped row per class, not 250 rows
  assert.equal((sect.match(/<proved\b/g) ?? []).length, 3, "one grouped row per vuln_class");
  // endpoints origin-stripped to paths and capped per class with a "+N more" marker
  assert.match(sect, /endpoints="\/route\//);
  assert.match(sect, /\+\d+ more/);
  assert.doesNotMatch(sect, /http:\/\//, "endpoints are origin-stripped");
  assert.doesNotMatch(sect, /finding_id/, "per-finding provenance the rule never uses is dropped");
});

test("<remaining_targets> renders the human-method probe for OPEN classes as PRIORITY, and widen-probes for recurring proved classes", () => {
  // proved covers sqli + xss_reflected but NOT the auth/signup classes → those stay open
  const state: HunterBriefState = {
    ...EMPTY_STATE,
    proved: [
      { vuln_class: "sqli", endpoint: "http://h/api/x", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-1" },
      { vuln_class: "info_disclosure", endpoint: "http://h/info.php", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-2" },
    ],
  };
  const xml = buildHunterBrief(state);
  const sect = section(xml, "remaining_targets");
  assert.match(sect, /PRIORITY \(open classes/);
  // open classes get a concrete behavioural method, not a path
  assert.match(sect, /weak_password_policy: .*1-character password/);
  assert.match(sect, /insecure_transport: .*tls_unavailable/);
  assert.match(sect, /improper_session_invalidation: .*OLD token/);
  // a proved recurring class shows up under WIDEN, not PRIORITY
  assert.match(sect, /WIDEN/);
  assert.match(sect, /info_disclosure: .*debug\/stack-trace/);
});

test("<canonical_targets> marks recovered routes tested vs UNTESTED from the proved list (recon+spine derived)", () => {
  const state: HunterBriefState = {
    ...EMPTY_STATE,
    recoveredIntel: { api_route_table: "/api/login /api/password/change /api/loan/apply /api/beneficiary/pay" },
    proved: [
      { vuln_class: "auth_bypass", endpoint: "http://h/api/password/change", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-1" },
    ],
  };
  const xml = buildHunterBrief(state);
  const sect = section(xml, "canonical_targets");
  // the route with a proved finding shows its class; other routes show [none]
  assert.match(sect, /\/api\/password\/change\s+— proved: auth_bypass/);
  assert.match(sect, /\/api\/loan\/apply\s+— proved: \[none\]/);
  assert.match(sect, /\/api\/beneficiary\/pay\s+— proved: \[none\]/);
  assert.match(sect, /route\(s\) with NO finding yet/);
});

test("<canonical_targets> is per (route × class): a route with one class still shows that class, flagging OTHER classes open there", () => {
  const state: HunterBriefState = {
    ...EMPTY_STATE,
    recoveredIntel: { api_route_table: "/api/loan/apply /api/login" },
    proved: [
      { vuln_class: "deserialization_rce", endpoint: "http://h/api/loan/apply", invariant_type: "state_changed", verdict: "CONFIRMED", finding_id: "SAHW-9" },
    ],
  };
  const sect = section(buildHunterBrief(state), "canonical_targets");
  // loan/apply shows the RCE but the directive makes clear other classes remain open there
  assert.match(sect, /\/api\/loan\/apply\s+— proved: deserialization_rce/);
  assert.match(sect, /per \(route × vuln_class\)/);
});

test("URL efficiency: brief relativizes to the target base once, and relative endpoints round-trip back to absolute", () => {
  const state: HunterBriefState = {
    ...EMPTY_STATE,
    attackSurface: [
      { url: "http://10.0.0.1/api/login", method: "POST", status: 200, content_type: "application/json", semantic_role: "auth" },
      { url: "http://10.0.0.1/api/loan/apply", method: "POST", status: 200, content_type: "application/json", semantic_role: "data" },
      { url: "http://10.0.0.1:3000/static/js/main.js.map", method: "GET", status: 200, content_type: "application/json", semantic_role: "asset" },
    ] as any,
    recoveredIntel: { api_route_table: "/api/login /api/loan/apply /api/loan" },
    proved: [{ vuln_class: "sqli", endpoint: "http://10.0.0.1/api/login", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-1" }],
  };
  const xml = buildHunterBrief(state);
  // primary base (most frequent = the :80 host) declared once; secondary :3000 aliased
  const target = section(xml, "target");
  assert.match(target, /BASE \(primary\) = http:\/\/10\.0\.0\.1\b/);
  assert.match(target, /\[:3000\] = http:\/\/10\.0\.0\.1:3000/);
  // the full primary origin should NOT be repeated in attack_surface (it's relative there)
  const as = section(xml, "attack_surface");
  assert.match(as, /url="\/api\/login"/);
  assert.doesNotMatch(as, /http:\/\/10\.0\.0\.1\/api\/login/);
  // the :3000 asset becomes alias-prefixed
  assert.match(as, /url="\[:3000\]\/static\/js\/main\.js\.map"/);

  // round-trip: what the model emits relative resolves back to the exact absolute URL
  const origins = deriveOrigins(state);
  assert.equal(resolveRelativeEndpoint("/api/loan/apply", origins), "http://10.0.0.1/api/loan/apply");
  assert.equal(resolveRelativeEndpoint("[:3000]/static/js/main.js.map", origins), "http://10.0.0.1:3000/static/js/main.js.map");
  // absolute in -> unchanged; unknown -> left as-is (rejected downstream, never a scope bypass)
  assert.equal(resolveRelativeEndpoint("http://10.0.0.1/api/x", origins), "http://10.0.0.1/api/x");
  assert.equal(resolveRelativeEndpoint("[:9999]/x", origins), "[:9999]/x");
});
