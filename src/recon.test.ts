import { describe, it, expect } from "vitest";
import {
  extractHttpUrls,
  extractPathStrings,
  extractApiEndpoints,
  isSourceMapUrl,
  discoverSurface,
  type Fetcher,
} from "./recon.js";

describe("extractHttpUrls", () => {
  it("extracts absolute http(s) URLs", () => {
    const text = 'fetch("http://x/api/1"); var a="https://y/z"; // http://ignored.example/x';
    expect(extractHttpUrls(text)).toEqual(["http://x/api/1", "https://y/z", "http://ignored.example/x"]);
  });
});

describe("extractPathStrings", () => {
  it("extracts path-like literals", () => {
    expect(extractPathStrings('fetch("/api/show?file=x")').includes("/api/show")).toBe(true);
    expect(extractPathStrings('x = "/login";')).toContain("/login");
  });
});

describe("extractApiEndpoints", () => {
  const js = `
    fetch("/api/show?file=" + f);
    axios.post("/api/ContactUs", body);
    axios.get("/api/beneficiary/fetch");
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/password/forgot");
    const u = "/api/account/details";
  `;
  const eps = extractApiEndpoints(js, "app.js");

  it("finds fetch/axios/xhr endpoints with methods", () => {
    const show = eps.find((e) => e.path === "/api/show");
    expect(show).toBeTruthy();
    expect(show?.method).toBe("GET");
    expect(show?.params).toContain("file");

    const contact = eps.find((e) => e.path === "/api/ContactUs");
    expect(contact?.method).toBe("POST");

    const forgot = eps.find((e) => e.path === "/api/password/forgot");
    expect(forgot?.method).toBe("GET");
  });

  it("records the source bundle", () => {
    expect(eps.every((e) => e.source === "app.js")).toBe(true);
  });
});

describe("isSourceMapUrl", () => {
  it("detects .map files", () => {
    expect(isSourceMapUrl("/static/app.js.map")).toBe(true);
    expect(isSourceMapUrl("/static/app.js")).toBe(false);
  });
});

describe("discoverSurface (black-box)", () => {
  it("discovers scripts, endpoints, source maps, and CORS from a served SPA", async () => {
    const fetcher: Fetcher = async (url) => {
      if (url.endsWith("/__cors_probe__")) {
        return { status: 200, headers: { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }, body: "" };
      }
      if (url === "http://x/") {
        return { status: 200, headers: { server: "nginx" }, body: '<html><script src="/static/app.js"></script></html>' };
      }
      if (url === "http://x/static/app.js") {
        return { status: 200, headers: {}, body: 'fetch("/api/show?file=x");\n//# sourceMappingURL=app.js.map' };
      }
      return { status: 404, headers: {}, body: "" };
    };

    const surface = await discoverSurface("http://x/", fetcher);
    expect(surface.scripts).toContain("http://x/static/app.js");
    expect(surface.endpoints.some((e) => e.path === "/api/show")).toBe(true);
    expect(surface.sourceMaps).toContain("http://x/static/app.js.map");
    expect(surface.cors).toEqual({ acao: "*", acac: "true" });
    expect(surface.tech).toContain("server:nginx");
  });
});
