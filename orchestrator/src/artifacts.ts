import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, access, stat, rm, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

export interface Artifact {
  sha256: string;
  path: string;
  bytes: number;
}

export class ArtifactStore {
  constructor(private readonly root: string) {}

  private pathFor(sha256: string): string {
    // Validate that the input is a canonical SHA-256 hex string.
    // Fail closed: an input that is not a 64-character hex string is an error.
    if (!/^[0-9a-f]{64}$/.test(sha256)) {
      throw new Error(`Invalid SHA-256 hash: ${sha256}`);
    }
    // Fan out by the first two hex chars so one directory never holds every artifact.
    return join(this.root, sha256.slice(0, 2), sha256);
  }

  async put(data: string | Uint8Array): Promise<Artifact> {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    const sha256 = createHash("sha256").update(buf).digest("hex");
    const path = this.pathFor(sha256);
    if (!(await this.has(sha256))) {
      const dir = dirname(path);
      await mkdir(dir, { recursive: true });
      // Write to a temporary file and then atomically rename it into place.
      // This ensures that a visible file at the content-addressed path is always complete.
      const tmpName = join(dir, `.tmp-${randomBytes(4).toString("hex")}`);
      try {
        await writeFile(tmpName, buf);
        await rename(tmpName, path);
      } catch (err) {
        // Clean up the temp file if rename failed.
        try {
          await rm(tmpName);
        } catch {
          // Ignore cleanup errors.
        }
        throw err;
      }
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
    } catch (err: unknown) {
      // Return false only for ENOENT (file not found).
      // Rethrow other errors (e.g., EACCES) to avoid masking real problems.
      if (err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT") {
        return false;
      }
      throw err;
    }
  }
}
