import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, access } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface Artifact {
  sha256: string;
  path: string;
  bytes: number;
}

export class ArtifactStore {
  constructor(private readonly root: string) {}

  private pathFor(sha256: string): string {
    // Fan out by the first two hex chars so one directory never holds every artifact.
    return join(this.root, sha256.slice(0, 2), sha256);
  }

  async put(data: string | Uint8Array): Promise<Artifact> {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    const sha256 = createHash("sha256").update(buf).digest("hex");
    const path = this.pathFor(sha256);
    if (!(await this.has(sha256))) {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, buf);
    }
    return { sha256, path, bytes: buf.byteLength };
  }

  async get(sha256: string): Promise<Buffer> {
    return readFile(this.pathFor(sha256));
  }

  async has(sha256: string): Promise<boolean> {
    try {
      await access(this.pathFor(sha256));
      return true;
    } catch {
      return false;
    }
  }
}
