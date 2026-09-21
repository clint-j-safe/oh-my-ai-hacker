/**
 * Minimal DNS message parse/build for the OAST listener.
 *
 * Parses the question section of a DNS query and builds a NOERROR response that
 * echoes the question and (for A/ANY queries) answers with the listener IP, so
 * the target receives a valid answer and the query itself is what we log.
 */

export interface DnsQuery {
  id: number;
  qname: string;
  qtype: number;
  qclass: number;
  questionLength: number; // bytes of the question section (qname + qtype + qclass)
}

export const QTYPE_A = 1;
export const QTYPE_ANY = 255;

export function parseDnsQuery(buf: Buffer): DnsQuery {
  if (buf.length < 12) throw new Error("DNS query too short");
  const id = buf.readUInt16BE(0);
  const qdcount = buf.readUInt16BE(4);
  if (qdcount < 1) throw new Error("DNS query has no question");

  let offset = 12;
  const labels: string[] = [];
  for (;;) {
    if (offset >= buf.length) throw new Error("DNS query truncated in qname");
    const len = buf.readUInt8(offset);
    offset += 1;
    if (len === 0) break;
    if (offset + len > buf.length) throw new Error("DNS query truncated in label");
    labels.push(buf.toString("ascii", offset, offset + len));
    offset += len;
  }
  const qname = labels.join(".") + ".";
  const qtype = buf.readUInt16BE(offset);
  const qclass = buf.readUInt16BE(offset + 2);
  offset += 4;
  return { id, qname, qtype, qclass, questionLength: offset - 12 };
}

export function buildDnsResponse(query: Buffer, answerIp: string): Buffer {
  const q = parseDnsQuery(query);
  const answerA = q.qtype === QTYPE_A || q.qtype === QTYPE_ANY;
  const ancount = answerA ? 1 : 0;

  const header = Buffer.alloc(12);
  header.writeUInt16BE(q.id, 0);
  header.writeUInt16BE(0x8180, 2); // QR=1, RD=1, RA=1
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(ancount, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  // Question section: echo the raw question bytes.
  const question = query.subarray(12, 12 + q.questionLength);

  let answer = Buffer.alloc(0);
  if (answerA) {
    const ip = answerIp.split(".").map((n) => Number(n));
    answer = Buffer.alloc(16);
    answer.writeUInt16BE(0xc00c, 0); // pointer to qname at offset 12
    answer.writeUInt16BE(QTYPE_A, 2);
    answer.writeUInt16BE(1, 4); // IN
    answer.writeUInt32BE(60, 6); // TTL
    answer.writeUInt16BE(4, 10); // RDLENGTH
    answer.writeUInt8(ip[0] ?? 127, 12);
    answer.writeUInt8(ip[1] ?? 0, 13);
    answer.writeUInt8(ip[2] ?? 0, 14);
    answer.writeUInt8(ip[3] ?? 1, 15);
  }

  return Buffer.concat([header, question, answer]);
}
