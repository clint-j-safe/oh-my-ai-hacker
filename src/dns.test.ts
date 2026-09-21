import { describe, it, expect } from "vitest";
import { parseDnsQuery, buildDnsResponse, QTYPE_A } from "./dns.js";

function buildQuery(qname: string, qtype = QTYPE_A): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0); // id
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4); // QDCOUNT
  const labels = qname.replace(/\.$/, "").split(".");
  const parts: Buffer[] = [];
  for (const label of labels) {
    const l = Buffer.from(label, "ascii");
    parts.push(Buffer.from([l.length]), l);
  }
  parts.push(Buffer.from([0])); // terminating zero
  const question = Buffer.concat(parts);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2); // IN
  return Buffer.concat([header, question, tail]);
}

describe("parseDnsQuery", () => {
  it("parses id, qname, qtype, qclass", () => {
    const q = parseDnsQuery(buildQuery("a1b2c3d4e5f6.oast.test"));
    expect(q.id).toBe(0x1234);
    expect(q.qname).toBe("a1b2c3d4e5f6.oast.test.");
    expect(q.qtype).toBe(QTYPE_A);
    expect(q.qclass).toBe(1);
  });
});

describe("buildDnsResponse", () => {
  it("echoes the question and answers A queries with the listener IP", () => {
    const query = buildQuery("a1b2c3d4e5f6.oast.test");
    const resp = buildDnsResponse(query, "10.0.0.7");
    expect(resp.readUInt16BE(0)).toBe(0x1234); // id echoed
    expect(resp.readUInt16BE(2) & 0x8000).toBe(0x8000); // QR bit set
    expect(resp.readUInt16BE(6)).toBe(1); // ANCOUNT=1
    // the parsed response question matches
    const reparsed = parseDnsQuery(resp);
    expect(reparsed.qname).toBe("a1b2c3d4e5f6.oast.test.");
    // A record answer tail: rdata at resp.length-4.., rdlength at resp.length-6..
    expect(resp.readUInt16BE(resp.length - 6)).toBe(4); // RDLENGTH
    expect(resp[resp.length - 4]).toBe(10);
    expect(resp[resp.length - 3]).toBe(0);
    expect(resp[resp.length - 2]).toBe(0);
    expect(resp[resp.length - 1]).toBe(7);
  });

  it("returns NOERROR with no answer for non-A queries", () => {
    const resp = buildDnsResponse(buildQuery("x.oast.test", 16 /* TXT */), "10.0.0.7");
    expect(resp.readUInt16BE(6)).toBe(0); // ANCOUNT=0
    expect(resp.readUInt16BE(2) & 0x000f).toBe(0); // rcode NOERROR
  });
});
