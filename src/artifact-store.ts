/**
 * Artifact Store — content-addressed (SHA-256) store with audit.sh-style provenance.
 *
 * Every stored blob is addressed by its SHA-256 and persisted under
 * `artifacts/<sha[:2]>/<sha>`. Provenance entries follow the
 * `human-test/engage-bb-offline/audit.sh` model: `UTC | purpose | cmd | rc`,
 * plus the stdout SHA-256 and sandbox id (the Provenance Gate inputs).
 */

import { createHash } from "node:crypto";
import { mkdirSync, appendFileSync, writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

export interface ProvenanceEntry {
  utc: string;
  purpose: string;
  cmd: string;
  rc: number;
  stdoutSha256: string;
  sandboxId?: string;
}

export interface StoredArtifact {
  sha256: string;
  path: string; // content-addressed relative path (no leading artifacts/ prefix)
  size: number;
}

export interface PutMeta {
  purpose: string;
  cmd: string;
  rc: number;
}

export interface ArtifactStoreOptions {
  root: string;
  sandboxId?: string;
}

const HASH = "sha256";

export function hash(content: string | Buffer): string {
  return createHash(HASH).update(content).digest("hex");
}

export class ArtifactStore {
  readonly root: string;
  private readonly sandboxId?: string;
  private readonly artifactsDir: string;
  private readonly auditLogPath: string;
  private readonly indexPath: string;
  private readonly entries: ProvenanceEntry[] = [];

  constructor(opts: ArtifactStoreOptions) {
    this.root = opts.root;
    this.sandboxId = opts.sandboxId;
    this.artifactsDir = join(opts.root, "artifacts");
    this.auditLogPath = join(opts.root, "audit.log");
    this.indexPath = join(opts.root, "artifact-index.txt");
    mkdirSync(this.artifactsDir, { recursive: true });
  }

  private artifactPath(sha: string): string {
    return join(sha.slice(0, 2), sha.slice(2));
  }

  private record(entry: ProvenanceEntry): void {
    this.entries.push(entry);
    const line = `${entry.utc} | ${entry.purpose} | cmd: ${entry.cmd} | rc=${entry.rc} | sha256=${entry.stdoutSha256 || "-"}\n`;
    appendFileSync(this.auditLogPath, line);
  }

  /** Store content addressed by its SHA-256 and record provenance. */
  put(content: string | Buffer, meta: PutMeta): StoredArtifact {
    const digest = hash(content);
    const rel = this.artifactPath(digest);
    const abs = join(this.artifactsDir, rel);
    if (!existsSync(abs)) {
      mkdirSync(join(this.artifactsDir, digest.slice(0, 2)), { recursive: true });
      writeFileSync(abs, content);
    }
    const size = Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content);
    this.record({
      utc: new Date().toISOString(),
      purpose: meta.purpose,
      cmd: meta.cmd,
      rc: meta.rc,
      stdoutSha256: digest,
      sandboxId: this.sandboxId,
    });
    this.refreshIndex();
    return { sha256: digest, path: rel, size };
  }

  /** Record a provenance entry for a command whose stdout was not captured. */
  log(meta: PutMeta): ProvenanceEntry {
    const entry: ProvenanceEntry = {
      utc: new Date().toISOString(),
      purpose: meta.purpose,
      cmd: meta.cmd,
      rc: meta.rc,
      stdoutSha256: "",
      sandboxId: this.sandboxId,
    };
    this.record(entry);
    return entry;
  }

  /** All provenance entries (in-memory view; also persisted to audit.log). */
  provenance(): ProvenanceEntry[] {
    return [...this.entries];
  }

  /** Read a stored artifact by SHA-256. */
  get(sha: string): Buffer | null {
    const abs = join(this.artifactsDir, this.artifactPath(sha));
    if (!existsSync(abs)) return null;
    return readFileSync(abs);
  }

  /** Rebuild + persist the sha256sum-format index. */
  refreshIndex(): string {
    const lines: string[] = [];
    const prefix = join(this.artifactsDir);
    for (const entry of this.entries) {
      if (!entry.stdoutSha256) continue;
      const rel = this.artifactPath(entry.stdoutSha256);
      lines.push(`${entry.stdoutSha256}  ${rel}`);
    }
    const text = [...new Set(lines)].join("\n") + (lines.length ? "\n" : "");
    writeFileSync(this.indexPath, text);
    return text;
  }

  /** Read the current index text (from memory-backed rebuild). */
  index(): string {
    return this.refreshIndex();
  }
}
