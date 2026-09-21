import { describe, it, expect } from "vitest";
import { SecurityFabric, type GraphDriver } from "./graph.js";

class FakeDriver implements GraphDriver {
  calls: Array<{ cypher: string; params: Record<string, unknown> }> = [];
  result: Record<string, unknown> = {};
  async run(cypher: string, params?: Record<string, unknown>) {
    this.calls.push({ cypher, params: params ?? {} });
    return { records: Object.keys(this.result).length ? [{ get: (k: string) => this.result[k] }] : [] };
  }
}

function makeFabric(d: FakeDriver): SecurityFabric {
  return new SecurityFabric({ uri: "x", user: "x", password: "x", driver: d });
}

describe("SecurityFabric — upserts", () => {
  it("MERGEs an asset, vuln, and identity", async () => {
    const d = new FakeDriver();
    const f = makeFabric(d);
    await f.upsertAsset({ asset_key: "http://t:3000", type: "endpoint", url: "http://t:3000/api/show" });
    await f.upsertVuln({ vuln_id: "F1", vuln_class: "path_traversal", verdict: "CONFIRMED", confidence: 0.95 });
    await f.upsertIdentity({ identity_id: "BNK95153", type: "account", userid: "BNK95153", compromised: true });

    expect(d.calls[0].cypher).toContain("MERGE (a:Asset {asset_key: $asset_key})");
    expect(d.calls[1].cypher).toContain("MERGE (v:Vuln {vuln_id: $vuln_id})");
    expect(d.calls[2].cypher).toContain("MERGE (id:Identity {identity_id: $identity_id})");
    expect(d.calls[2].params.compromised).toBe(true);
  });
});

describe("SecurityFabric — links (correlation edges)", () => {
  it("writes HAS_VULN, COMPROMISES, EXPOSES, ACCESSES, LEADS_TO", async () => {
    const d = new FakeDriver();
    const f = makeFabric(d);
    await f.linkAssetHasVuln("http://t:3000", "F1");
    await f.linkVulnCompromises("F1", "BNK95153");
    await f.linkVulnExposes("F2", "internal:5432");
    await f.linkIdentityAccesses("BNK95153", "http://t:3000");
    await f.linkChain("F1", "F3");

    expect(d.calls[0].cypher).toContain("HAS_VULN");
    expect(d.calls[1].cypher).toContain("COMPROMISES");
    expect(d.calls[2].cypher).toContain("EXPOSES");
    expect(d.calls[3].cypher).toContain("ACCESSES");
    expect(d.calls[4].cypher).toContain("LEADS_TO");
  });
});

describe("SecurityFabric — correlation queries", () => {
  it("blastRadius returns reachable assets + identities", async () => {
    const d = new FakeDriver();
    d.result = { assets: ["internal:5432", "http://t:3000"], identities: ["BNK95153"] };
    const f = makeFabric(d);
    const radius = await f.blastRadius("F2");
    expect(radius.assets).toEqual(["internal:5432", "http://t:3000"]);
    expect(radius.identities).toEqual(["BNK95153"]);
    expect(d.calls[0].cypher).toContain("EXPOSES");
  });

  it("identitiesWithAccessTo returns identities on a vulnerable asset", async () => {
    const d = new FakeDriver();
    d.result = { identities: ["BNK95153", "BNK88888"] };
    const f = makeFabric(d);
    expect(await f.identitiesWithAccessTo("http://t:3000")).toEqual(["BNK95153", "BNK88888"]);
    expect(d.calls[0].cypher).toContain('verdict: "CONFIRMED"');
  });

  it("attackPathToAsset returns the chain of vulns reaching the asset", async () => {
    const d = new FakeDriver();
    d.result = { path: ["F1", "F3", "F9"] };
    const f = makeFabric(d);
    expect(await f.attackPathToAsset("http://t:3000")).toEqual(["F1", "F3", "F9"]);
    expect(d.calls[0].cypher).toContain("LEADS_TO*0..5");
  });
});
