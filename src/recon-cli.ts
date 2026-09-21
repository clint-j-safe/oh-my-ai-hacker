/**
 * recon-cli — run black-box surface discovery against a live target.
 * Usage: node dist/recon-cli.js <base-url>
 */

import { discoverSurface } from "./recon.js";
import { httpRequest } from "./http.js";

async function main(): Promise<void> {
  const url = process.argv[2];
  if (!url) {
    console.error("usage: recon-cli <base-url>");
    process.exit(2);
  }
  const surface = await discoverSurface(url, httpRequest);
  console.log(JSON.stringify(surface, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
