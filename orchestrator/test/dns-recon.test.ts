import { test } from "node:test";
import assert from "node:assert/strict";
import { isIp, baseDomainOf, candidateFqdns, isDistinctVhost, extractAxfrNames, discoverVhosts } from "../src/dns-recon.js";

test("baseDomainOf: last two labels; null for IP/bare", () => {
  assert.equal(baseDomainOf("ns1.cronos.htb"), "cronos.htb");
  assert.equal(baseDomainOf("admin.cronos.htb"), "cronos.htb");
  assert.equal(baseDomainOf("cronos.htb"), "cronos.htb");
  assert.equal(baseDomainOf("10.129.227.211"), null);
  assert.equal(baseDomainOf("localhost"), null);
  assert.equal(isIp("10.129.227.211"), true);
});

test("candidateFqdns: apex + prefix×base + axfr, only under a base domain", () => {
  const c = candidateFqdns(["cronos.htb"], ["admin.cronos.htb", "evil.example.com"]);
  assert.ok(c.includes("admin.cronos.htb"));   // from prefix AND axfr
  assert.ok(c.includes("cronos.htb"));          // apex
  assert.ok(!c.includes("evil.example.com"));   // axfr name outside base is dropped
});

test("isDistinctVhost: different title / status / size => real vhost", () => {
  const def = { status: 200, body: "<title>Apache2 Ubuntu Default Page: It works</title>" + "x".repeat(200) };
  const app = { status: 200, body: "<title>Login Page</title><form>password</form>" };
  assert.equal(isDistinctVhost(def, app), true);            // different title
  assert.equal(isDistinctVhost(def, def), false);           // identical => not a vhost
  assert.equal(isDistinctVhost(def, { status: 0, body: "" }), false); // unreachable
  assert.equal(isDistinctVhost(def, { status: 403, body: def.body }), true); // status differs
});

test("extractAxfrNames: pulls names under the base domain from raw AXFR output", () => {
  const raw = "cronos.htb. IN SOA ns1.cronos.htb.\nadmin.cronos.htb. IN A 10.10.10.13\nns1.cronos.htb. IN A 10.10.10.13\n";
  const names = extractAxfrNames(raw, ["cronos.htb"]);
  assert.ok(names.includes("admin.cronos.htb") && names.includes("ns1.cronos.htb"));
});

test("discoverVhosts: end-to-end over injected executors finds the admin vhost (Cronos shape)", async () => {
  const exec = {
    ptr: async (ip: string) => ip === "10.129.227.211" ? ["ns1.cronos.htb"] : [],
    axfr: async (_d: string, _s: string) => ["admin.cronos.htb", "ns1.cronos.htb"],
    httpHost: async (_ip: string, host: string) => host === "admin.cronos.htb"
      ? { status: 200, body: "<title>Login Page</title><form>password</form>" }
      : { status: 200, body: "<title>Apache2 Ubuntu Default Page: It works</title>" + "x".repeat(300) },
  };
  const found = await discoverVhosts(["http://10.129.227.211"], exec);
  assert.deepEqual(found, [{ fqdn: "admin.cronos.htb", ip: "10.129.227.211" }]);
});

import { collectDnsNames } from "../src/dns-recon.js";

test("collectDnsNames: reconstructs dotted names from DNS wire labels", () => {
  // wire for admin.cronos.htb : 05 'admin' 06 'cronos' 03 'htb' 00
  const wire = Uint8Array.from([5,0x61,0x64,0x6d,0x69,0x6e, 6,0x63,0x72,0x6f,0x6e,0x6f,0x73, 3,0x68,0x74,0x62, 0]);
  const names = collectDnsNames(wire);
  assert.ok(names.includes("admin.cronos.htb"), names.join(","));
});
