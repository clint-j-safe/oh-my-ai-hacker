/**
 * Security fabric — Neo4j graph correlating Assets, Vulns and Identities.
 *
 *   Asset    — host / endpoint / service / application
 *   Vuln     — a (validated) finding
 *   Identity — user / account / role / session / credential
 *
 * Relationships encode the fabric:
 *   (Asset)-[:HAS_VULN]->(Vuln)          asset carries a vulnerability
 *   (Vuln)-[:COMPROMISES]->(Identity)    vuln compromises an identity
 *   (Vuln)-[:EXPOSES]->(Asset)           vuln exposes another asset (SSRF/XXE)
 *   (Identity)-[:ACCESSES]->(Asset)      identity has access to an asset
 *   (Vuln)-[:LEADS_TO]->(Vuln)           attack chain
 *
 * All writes are idempotent (MERGE). The driver is injected so Cypher is
 * testable without a live Neo4j.
 */

import neo4j from "neo4j-driver";

export interface GraphDriver {
  run(cypher: string, params?: Record<string, unknown>): Promise<{ records: Array<{ get(key: string): unknown }> }>;
  close?: () => Promise<void>;
}

export interface AssetNode {
  asset_key: string; // unique: url for endpoints, host:port for hosts
  type: string; // host | endpoint | service | application
  host?: string;
  port?: number;
  url?: string;
  tech?: string;
}

export interface VulnNode {
  vuln_id: string;
  vuln_class: string;
  title?: string;
  severity?: string;
  verdict: string;
  confidence: number;
  decided_by?: string;
  cwe?: string;
}

export interface IdentityNode {
  identity_id: string;
  type: string; // user | account | role | session | credential
  userid?: string;
  name?: string;
  role?: string;
  compromised?: boolean;
}

export interface FabricOptions {
  uri: string;
  user: string;
  password: string;
  driver?: GraphDriver;
}

export class SecurityFabric {
  private readonly driver: GraphDriver;

  constructor(opts: FabricOptions) {
    this.driver = opts.driver ?? createLiveDriver(opts.uri, opts.user, opts.password);
  }

  // ---- upserts ----
  async upsertAsset(a: AssetNode): Promise<void> {
    await this.driver.run(
      `MERGE (a:Asset {asset_key: $asset_key})
       SET a.type = $type, a.host = $host, a.port = $port, a.url = $url, a.tech = $tech`,
      {
        asset_key: a.asset_key,
        type: a.type,
        host: a.host ?? null,
        port: a.port ?? null,
        url: a.url ?? null,
        tech: a.tech ?? null,
      },
    );
  }

  async upsertVuln(v: VulnNode): Promise<void> {
    await this.driver.run(
      `MERGE (v:Vuln {vuln_id: $vuln_id})
       SET v.vuln_class = $vuln_class, v.title = $title, v.severity = $severity,
           v.verdict = $verdict, v.confidence = $confidence,
           v.decided_by = $decided_by, v.cwe = $cwe`,
      {
        vuln_id: v.vuln_id,
        vuln_class: v.vuln_class,
        title: v.title ?? null,
        severity: v.severity ?? null,
        verdict: v.verdict,
        confidence: v.confidence,
        decided_by: v.decided_by ?? null,
        cwe: v.cwe ?? null,
      },
    );
  }

  async upsertIdentity(i: IdentityNode): Promise<void> {
    await this.driver.run(
      `MERGE (id:Identity {identity_id: $identity_id})
       SET id.type = $type, id.userid = $userid, id.name = $name,
           id.role = $role, id.compromised = $compromised`,
      {
        identity_id: i.identity_id,
        type: i.type,
        userid: i.userid ?? null,
        name: i.name ?? null,
        role: i.role ?? null,
        compromised: i.compromised ?? null,
      },
    );
  }

  // ---- links ----
  async linkAssetHasVuln(asset_key: string, vuln_id: string): Promise<void> {
    await this.driver.run(
      `MATCH (a:Asset {asset_key: $asset_key}), (v:Vuln {vuln_id: $vuln_id}) MERGE (a)-[:HAS_VULN]->(v)`,
      { asset_key, vuln_id },
    );
  }

  async linkVulnCompromises(vuln_id: string, identity_id: string): Promise<void> {
    await this.driver.run(
      `MATCH (v:Vuln {vuln_id: $vuln_id}), (i:Identity {identity_id: $identity_id}) MERGE (v)-[:COMPROMISES]->(i)`,
      { vuln_id, identity_id },
    );
  }

  async linkVulnExposes(vuln_id: string, asset_key: string): Promise<void> {
    await this.driver.run(
      `MATCH (v:Vuln {vuln_id: $vuln_id}), (a:Asset {asset_key: $asset_key}) MERGE (v)-[:EXPOSES]->(a)`,
      { vuln_id, asset_key },
    );
  }

  async linkIdentityAccesses(identity_id: string, asset_key: string): Promise<void> {
    await this.driver.run(
      `MATCH (i:Identity {identity_id: $identity_id}), (a:Asset {asset_key: $asset_key}) MERGE (i)-[:ACCESSES]->(a)`,
      { identity_id, asset_key },
    );
  }

  async linkChain(fromVulnId: string, toVulnId: string): Promise<void> {
    await this.driver.run(
      `MATCH (a:Vuln {vuln_id: $from}), (b:Vuln {vuln_id: $to}) MERGE (a)-[:LEADS_TO]->(b)`,
      { from: fromVulnId, to: toVulnId },
    );
  }

  // ---- correlation ----
  /** Assets + identities reachable from a vuln (blast radius). */
  async blastRadius(vuln_id: string): Promise<{ assets: string[]; identities: string[] }> {
    const r = await this.driver.run(
      `MATCH (v:Vuln {vuln_id: $vuln_id})
       OPTIONAL MATCH (v)-[:EXPOSES]->(a:Asset)
       OPTIONAL MATCH (v)-[:COMPROMISES]->(i:Identity)
       OPTIONAL MATCH (i)-[:ACCESSES]->(a2:Asset)
       RETURN collect(DISTINCT a.asset_key) + collect(DISTINCT a2.asset_key) AS assets,
              collect(DISTINCT i.identity_id) AS identities`,
      { vuln_id },
    );
    const rec = r.records[0];
    return {
      assets: (rec?.get("assets") as string[]) ?? [],
      identities: (rec?.get("identities") as string[]) ?? [],
    };
  }

  /** Identities that access a vulnerable asset (compromise exposure). */
  async identitiesWithAccessTo(asset_key: string): Promise<string[]> {
    const r = await this.driver.run(
      `MATCH (a:Asset {asset_key: $asset_key})
       MATCH (a)-[:HAS_VULN]->(v:Vuln {verdict: "CONFIRMED"})
       MATCH (i:Identity)-[:ACCESSES]->(a)
       RETURN collect(DISTINCT i.identity_id) AS identities`,
      { asset_key },
    );
    return (r.records[0]?.get("identities") as string[]) ?? [];
  }

  /** Chain of vulns that lead to a compromised identity with access to the asset. */
  async attackPathToAsset(asset_key: string): Promise<string[]> {
    const r = await this.driver.run(
      `MATCH (i:Identity)-[:ACCESSES]->(a:Asset {asset_key: $asset_key})
       MATCH (v:Vuln)-[:COMPROMISES]->(i)
       OPTIONAL MATCH (v)-[:LEADS_TO*0..5]->(v2:Vuln)
       RETURN collect(DISTINCT v.vuln_id) + collect(DISTINCT v2.vuln_id) AS path`,
      { asset_key },
    );
    return (r.records[0]?.get("path") as string[]) ?? [];
  }

  async close(): Promise<void> {
    await this.driver.close?.();
  }
}

export { SecurityFabric as Graph };

function createLiveDriver(uri: string, user: string, password: string): GraphDriver {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  const session = driver.session();
  return {
    async run(cypher, params) {
      const r = await session.run(cypher, params);
      return { records: r.records.map((rec) => ({ get: (k: string) => rec.get(k) })) };
    },
    async close() {
      await session.close();
      await driver.close();
    },
  };
}
