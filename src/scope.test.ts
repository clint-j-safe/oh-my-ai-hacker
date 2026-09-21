import { describe, it, expect } from "vitest";
import { parseScope, ScopeError } from "./scope.js";

describe("parseScope", () => {
  it("normalizes explicit host:port endpoints", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000"] });
    expect(scope.endpoints).toEqual([
      { scheme: "http", host: "139.59.15.10", port: 3000 },
    ]);
  });

  it("applies default ports (http=80, https=443) when omitted", () => {
    const scope = parseScope({
      inScopeUrls: ["http://api.example.com", "https://app.example.com"],
    });
    expect(scope.endpoints).toEqual([
      { scheme: "http", host: "api.example.com", port: 80 },
      { scheme: "https", host: "app.example.com", port: 443 },
    ]);
  });

  it("strips userinfo and trailing dots from the host", () => {
    const scope = parseScope({ inScopeUrls: ["http://user:pass@host.example.com."] });
    expect(scope.endpoints[0].host).toBe("host.example.com");
  });

  it("rejects non-http(s) schemes", () => {
    expect(() => parseScope({ inScopeUrls: ["ftp://host/"] })).toThrow(ScopeError);
    expect(() => parseScope({ inScopeUrls: ["file:///etc/passwd"] })).toThrow(ScopeError);
    expect(() => parseScope({ inScopeUrls: ["gopher://host/"] })).toThrow(ScopeError);
  });

  it("rejects a malformed URL", () => {
    expect(() => parseScope({ inScopeUrls: ["not a url"] })).toThrow(ScopeError);
  });
});

describe("Scope.isInScope", () => {
  it("accepts a URL matching an allowlisted host and port", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000"] });
    expect(scope.isInScope("http://139.59.15.10:3000/login")).toBe(true);
    expect(scope.isInScope("http://139.59.15.10:3000/api/show?file=x")).toBe(true);
  });

  it("rejects a different port on the same host", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000"] });
    expect(scope.isInScope("http://139.59.15.10:8080/")).toBe(false);
  });

  it("rejects a scheme mismatch", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000"] });
    expect(scope.isInScope("https://139.59.15.10:3000/")).toBe(false);
  });

  it("rejects a different host", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000"] });
    expect(scope.isInScope("http://203.0.113.7:3000/")).toBe(false);
  });

  it("treats http://host (port 80) and http://host:80 as equivalent", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10"] });
    expect(scope.isInScope("http://139.59.15.10:80/")).toBe(true);
  });

  it("rejects non-http(s) target URLs outright", () => {
    const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000"] });
    expect(scope.isInScope("file:///etc/passwd")).toBe(false);
    expect(scope.isInScope("gopher://139.59.15.10:3000/")).toBe(false);
  });

  it("honors an explicit out-of-scope deny over an allowlisted host", () => {
    const scope = parseScope({
      inScopeUrls: ["http://139.59.15.10:3000", "http://139.59.15.10/api"],
      outOfScope: ["http://139.59.15.10:3000/admin"],
    });
    // host:port still allowed generally…
    expect(scope.isInScope("http://139.59.15.10:3000/login")).toBe(true);
    // …but the explicitly out-of-scope path prefix is denied.
    expect(scope.isInScope("http://139.59.15.10:3000/admin/console")).toBe(false);
  });

  it("matches an IP within a provided in-scope CIDR", () => {
    const scope = parseScope({
      inScopeUrls: ["http://139.59.15.10:3000"],
      inScopeCidrs: ["10.10.0.0/16"],
    });
    expect(scope.isInScope("http://10.10.3.4:3000/")).toBe(true);
    expect(scope.isInScope("http://10.11.3.4:3000/")).toBe(false);
  });
});
