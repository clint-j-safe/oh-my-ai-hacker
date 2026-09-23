import { test } from "node:test";
import assert from "node:assert/strict";
import { buildHunterBrief, type HunterBriefState } from "../src/brief.js";
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
    "already_proved", "dead_ends", "thinking_framework", "parameter_analysis",
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

  const attackSurface = section(xml, "attack_surface");
  assert.match(attackSurface, /http:\/\/10\.0\.0\.1:3000\/api\/users/);
  assert.match(attackSurface, /method="GET"/);
  assert.match(attackSurface, /status="200"/);

  const recoveredIntel = section(xml, "recovered_intel");
  assert.match(recoveredIntel, /<api_base>http:\/\/10\.0\.0\.1:4000<\/api_base>/);

  const alreadyProved = section(xml, "already_proved");
  assert.match(alreadyProved, /vuln_class="idor"/);
  assert.match(alreadyProved, /endpoint="http:\/\/10\.0\.0\.1:3000\/api\/users\/2"/);

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
  assert.match(alreadyProved, /endpoint="http:\/\/10\.0\.0\.1:3000\/download"/);

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
