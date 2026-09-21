/**
 * OOB listener (OAST) — catches out-of-band callbacks and reverse shells.
 *
 * Three listeners, one process, no external deps:
 *   - DNS (UDP + TCP): answers every query with the listener IP and logs the
 *     queried canary subdomain (SSRF/XXE/SQLi-OOB proof).
 *   - HTTP: logs every request; canary in the path or ?c= (SSRF/XXE callback).
 *   - TCP connect-back: accepts reverse-shell / connect-back connections,
 *     captures the connect + first bytes, then closes (RCE proof).
 *
 * Config via env:
 *   OOB_ANSWER_IP   A-record answer (default 127.0.0.1)
 *   OOB_DNS_PORT    (default 5353; use 53 in the container)
 *   OOB_HTTP_PORT   (default 8080; use 80 in the container)
 *   OOB_SHELL_PORT  (default 4444)
 */

import { createSocket } from "node:dgram";
import { createServer as createTcpServer, type Socket } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { CallbackLog, extractCanaryFromDns, extractCanaryFromHttpPath } from "./oob.js";
import { parseDnsQuery, buildDnsResponse } from "./dns.js";

const ANSWER_IP = process.env.OOB_ANSWER_IP ?? "127.0.0.1";
const DNS_PORT = Number(process.env.OOB_DNS_PORT ?? 5353);
const HTTP_PORT = Number(process.env.OOB_HTTP_PORT ?? 8080);
const SHELL_PORT = Number(process.env.OOB_SHELL_PORT ?? 4444);

export const log = new CallbackLog();

function logLine(evt: { type: string; token: string | null; source: string; data: string }): void {
  const entry = log.record(evt as Parameters<CallbackLog["record"]>[0]);
  // eslint-disable-next-line no-console
  console.log(`[oob] ${entry.utc} ${entry.type.toUpperCase()} token=${entry.token} src=${entry.source} ${entry.data.slice(0, 200)}`);
}

function startDnsUdp(): void {
  const sock = createSocket("udp4");
  sock.on("message", (msg, rinfo) => {
    let qname: string;
    try {
      qname = parseDnsQuery(msg).qname;
    } catch {
      return; // malformed — ignore
    }
    const token = extractCanaryFromDns(qname);
    logLine({ type: "dns", token, source: rinfo.address, data: qname });
    try {
      sock.send(buildDnsResponse(msg, ANSWER_IP), rinfo.port, rinfo.address);
    } catch {
      /* ignore */
    }
  });
  sock.bind(DNS_PORT);
  console.log(`[oob] dns-udp listening :${DNS_PORT}`);
}

function startDnsTcp(): void {
  const server = createTcpServer((conn) => {
    let buf = Buffer.alloc(0);
    conn.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 2) return;
      const len = buf.readUInt16BE(0);
      if (buf.length < 2 + len) return;
      const msg = buf.subarray(2, 2 + len);
      try {
        const qname = parseDnsQuery(msg).qname;
        const token = extractCanaryFromDns(qname);
        logLine({ type: "dns", token, source: conn.remoteAddress ?? "", data: qname });
        const resp = buildDnsResponse(msg, ANSWER_IP);
        const out = Buffer.alloc(2 + resp.length);
        out.writeUInt16BE(resp.length, 0);
        resp.copy(out, 2);
        conn.write(out);
      } catch {
        /* ignore */
      }
      conn.end();
    });
  });
  server.listen(DNS_PORT);
  console.log(`[oob] dns-tcp listening :${DNS_PORT}`);
}

function startHttp(): void {
  const server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const token = extractCanaryFromHttpPath(req.url ?? "/");
      logLine({
        type: "http",
        token,
        source: req.socket.remoteAddress ?? "",
        data: `${req.method} ${req.url} host=${req.headers.host ?? "-"} body=${body.slice(0, 200)}`,
      });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });
  server.listen(HTTP_PORT);
  console.log(`[oob] http listening :${HTTP_PORT}`);
}

function startShell(): void {
  const server = createTcpServer((conn: Socket) => {
    const source = conn.remoteAddress ?? "";
    let data = "";
    conn.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    const finish = () => {
      logLine({ type: "tcp", token: null, source, data: data.slice(0, 500) || "(connect only)" });
    };
    const timer = setTimeout(() => {
      finish();
      conn.destroy();
    }, 5000);
    conn.on("close", () => {
      clearTimeout(timer);
      finish();
    });
  });
  server.listen(SHELL_PORT);
  console.log(`[oob] shell-tcp listening :${SHELL_PORT}`);
}

export function startOob(): void {
  startDnsUdp();
  startDnsTcp();
  startHttp();
  startShell();
}

// Run when executed directly: `node dist/oob-server.js`
import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startOob();
}
