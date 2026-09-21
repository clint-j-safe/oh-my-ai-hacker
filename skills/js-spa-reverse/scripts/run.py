#!/usr/bin/env python3
"""
run.py -- js-spa-reverse entry point.

Static reverse-engineering of JavaScript/SPA bundles for the loop-engineered
pentest framework. Downloads in-scope JS bundles and extracts the *real* attack
surface a modern app hides in its bundle: API endpoints, client routes, query
parameters, environment keys, framework fingerprints, and hardcoded secrets.

CONTRACT
--------
* Input  : JSON on argv[1] or stdin:
             {"js_urls": ["https://cdn.example.com/app.js"],
              "target": "example.com",
              "scope_policy_spill_id": "abc123"}   # optional
* Output : one strict JSON artifact on stdout (see references/ARTIFACT_SCHEMA.md).
           No prose. On fatal error, still a schema-valid artifact with
           meta.status == "error".
* Laws   : Offload Law (raw bundles + oversized match dumps -> spill_store),
           Artifact Contract (strict JSON), Scope discipline (only in-scope JS
           URLs are fetched), Secret custody (NEVER emit a raw secret -- only a
           SHA-256 hash, and the value is redacted out of the context snippet).

This skill fetches the target's PUBLIC static JS (the same bytes any browser
downloads). It performs no active probing, no auth, no mutation.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, parse_qsl, urljoin

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    import esprima  # type: ignore
except ImportError:  # pragma: no cover
    esprima = None

try:
    from spill_store import offload_list, read_spill, should_offload, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import offload_list, read_spill, should_offload, write_spill  # type: ignore

# --- Tunables (env-overridable) ----------------------------------------------
HTTP_TIMEOUT = float(os.environ.get("JSRE_HTTP_TIMEOUT", "45"))
MAX_BUNDLE_BYTES = int(os.environ.get("JSRE_MAX_BUNDLE_BYTES", str(15 * 1024 * 1024)))  # 15 MB
AST_MAX_BYTES = int(os.environ.get("JSRE_AST_MAX_BYTES", str(4 * 1024 * 1024)))          # 4 MB
MATCH_INLINE_CAP = int(os.environ.get("JSRE_MATCH_INLINE_CAP", "200"))                   # spec: >200 -> spill
CONCURRENCY = int(os.environ.get("JSRE_CONCURRENCY", "5"))
CONTEXT_RADIUS = int(os.environ.get("JSRE_CONTEXT_RADIUS", "25"))                        # ~50 char window
CONFIG_MAX = int(os.environ.get("JSRE_CONFIG_MAX", "300"))                               # cap config entries

_PATTERNS_PATH = os.environ.get(
    "JSRE_PATTERNS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "patterns.json"),
)
_ROUTE_KEYS = {"path", "route", "url", "endpoint", "to", "href"}
_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


class ScopePolicy:
    """In-scope host test for JS URLs (mirrors osint-passive-enum's policy).

    Policy dict (from the spill store):
        {"in_scope": ["example.com","*.example.com"], "out_of_scope": [...]}
    Leading '*.' matches any subdomain depth; out-of-scope wins. With no
    policy, hosts under the target apex are allowed and everything else is
    flagged unknown (recorded, not silently fetched off-target).
    """

    def __init__(self, policy: Optional[dict], target: str):
        self.raw = policy or {}
        self.target = target
        self.have_policy = policy is not None
        self.in_scope = [self._compile(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._compile(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope and target:
            self.in_scope = [self._compile(target), self._compile(f"*.{target}")]

    @staticmethod
    def _compile(pattern: str) -> re.Pattern:
        p = pattern.strip().lower().rstrip(".")
        if p.startswith("*."):
            return re.compile(rf"^([a-z0-9_-]+\.)*{re.escape(p[2:])}$")
        return re.compile(rf"^{re.escape(p)}$")

    def allowed(self, host: str) -> Optional[bool]:
        h = (host or "").strip().lower()
        if not h:
            return None
        if any(rx.match(h) for rx in self.out_scope):
            return False
        if any(rx.match(h) for rx in self.in_scope):
            return True
        return False if self.have_policy else None


def _load_patterns() -> dict:
    with open(_PATTERNS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


class JSReverseEngineer:
    def __init__(self, js_urls: List[str], target: str,
                 scope_policy_spill_id: Optional[str] = None,
                 config: Optional[dict] = None):
        self.js_urls = [u for u in (js_urls or []) if isinstance(u, str) and u.strip()]
        self.target = (target or "").strip().lower()
        self.config = config or {}
        self.errors: List[Dict[str, str]] = []
        self.scope_id = scope_policy_spill_id
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target)

        try:
            self.pat = _load_patterns()
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "patterns", "error": str(exc)})
            self.pat = {}
        self._compile_patterns()

        # url -> {"content": str, "sha256": str, "bytes": int}
        self.bundles: Dict[str, Dict[str, Any]] = {}
        self.skipped_urls: List[Dict[str, str]] = []
        # aggregation
        self._endpoints: Dict[str, dict] = {}   # path -> endpoint record
        self.source_maps: Dict[str, dict] = {}  # map url -> recovery stats
        self._secrets: Dict[str, dict] = {}      # value_hash -> secret record
        self._config: Dict[str, dict] = {}       # "kind:name" -> config record
        self._base_literals: Dict[str, str] = {}  # name -> base path (e.g. "/api")
        self._base_aliases: Dict[str, str] = {}   # name -> name it aliases
        self._base_url_literals: Dict[str, str] = {}  # base path -> raw URL literal
        self._concat_resolved = 0
        self._params_all: Set[str] = set()
        self._ast_ok = 0
        self._ast_skipped = 0

    # -- pattern compilation ---------------------------------------------------
    def _compile_patterns(self) -> None:
        def comp(lst):
            out = []
            for p in lst or []:
                try:
                    out.append(re.compile(p))
                except re.error as exc:
                    self.errors.append({"stage": "regex", "error": f"{p}: {exc}"})
            return out

        ep = self.pat.get("endpoints", {})
        self.rx_api = comp(ep.get("api_paths"))
        self.rx_urls = comp(ep.get("absolute_urls"))
        self.rx_routes = comp(self.pat.get("routes"))
        self.rx_params = comp(self.pat.get("params"))
        self.rx_env = comp(self.pat.get("env_keys"))
        self.rx_graphql = comp(self.pat.get("graphql_introspection"))
        self.rx_ws = comp(self.pat.get("websocket"))
        self.secret_rules = []
        for rule in self.pat.get("secrets", []):
            try:
                self.secret_rules.append((rule["type"], rule.get("name", rule["type"]),
                                          re.compile(rule["pattern"])))
            except (re.error, KeyError) as exc:
                self.errors.append({"stage": "regex", "error": f"secret rule {rule}: {exc}"})
        self.fw_rules = self.pat.get("framework_fingerprints", [])

    # -- download --------------------------------------------------------------
    async def download_bundles(self) -> None:
        if httpx is None:
            self.errors.append({"stage": "download", "error": "httpx not installed"})
            return
        sem = asyncio.Semaphore(CONCURRENCY)

        async def fetch(url: str):
            host = _host_of(url)
            verdict = self.scope.allowed(host)
            if verdict is False:
                self.skipped_urls.append({"url": url, "reason": "out_of_scope"})
                return
            if verdict is None and self.scope.have_policy:
                self.skipped_urls.append({"url": url, "reason": "not_in_scope_policy"})
                return
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                                 follow_redirects=True) as client:
                        resp = await client.get(
                            url, headers={"User-Agent": "js-spa-reverse/1.0"})
                    if resp.status_code != 200:
                        self.skipped_urls.append({"url": url, "reason": f"HTTP {resp.status_code}"})
                        return
                    content = resp.text
                    if len(content.encode("utf-8", "replace")) > MAX_BUNDLE_BYTES:
                        content = content[:MAX_BUNDLE_BYTES]
                        self.errors.append({"stage": "download", "error": f"{url}: truncated to {MAX_BUNDLE_BYTES}B"})
                    self.bundles[url] = {
                        "content": content,
                        "sha256": _sha256(content),
                        "bytes": len(content),
                    }
                    await self._recover_source_map(url, content)
                except Exception as exc:  # noqa: BLE001
                    self.skipped_urls.append({"url": url, "reason": str(exc)})

        await asyncio.gather(*(fetch(u) for u in self.js_urls))

    # -- source-map recovery (general: webpack / CRA / Vite / Next all emit these) --------------
    async def _recover_source_map(self, js_url: str, content: str) -> None:
        """Follow ``//# sourceMappingURL`` and recover the ORIGINAL source for extraction.

        This is the single highest-yield generalisation for SPAs, and it is not app-specific:
        bundlers emit source maps by default and hosts routinely serve them. Minified bundles hide
        the route table behind concatenation (``BASE_URL + "/login"``) and never spell out request
        body field names, so regex over the bundle yields noise (XML namespaces, library homepages)
        and zero parameters. The recovered ``sourcesContent`` spells both out literally.
        """
        m = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", content[-4096:])
        if m:
            map_url = urljoin(js_url, m.group(1).strip().strip("\"'"))
        else:
            # Deployments routinely strip the sourceMappingURL comment while still SERVING
            # the map beside the bundle, so the absence of a comment is not evidence that no
            # map exists. One speculative probe per bundle at the conventional path costs a
            # single 404 and recovers the whole original source tree when it succeeds.
            map_url = js_url.split("?", 1)[0] + ".map"
        if self.scope.allowed(_host_of(map_url)) is False:
            self.skipped_urls.append({"url": map_url, "reason": "out_of_scope"})
            return
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                         follow_redirects=True) as client:
                r = await client.get(map_url, headers={"User-Agent": "js-spa-reverse/1.0"})
            if r.status_code != 200:
                self.skipped_urls.append({"url": map_url, "reason": f"HTTP {r.status_code}"})
                return
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            self.skipped_urls.append({"url": map_url, "reason": f"source_map: {exc}"})
            return

        sources = data.get("sources") or []
        bodies = data.get("sourcesContent") or []
        recovered = 0
        for src, body in zip(sources, bodies):
            if not isinstance(body, str) or not body:
                continue
            src_name = str(src)
            if "node_modules" in src_name:
                continue  # vendor code: no target-specific routes, huge noise
            key = f"{map_url}#!{src_name}"
            self.bundles[key] = {
                "content": body, "sha256": _sha256(body), "bytes": len(body),
                "source_map": map_url, "original_source": src_name,
            }
            self._extract_route_literals(body, key, src_name)
            recovered += 1
        self.source_maps[map_url] = {
            "map_url": map_url, "js_url": js_url, "recovered_sources": recovered,
            "total_sources": len(sources),
        }

    # Route-table literals in original source: quoted absolute paths. Static assets are rejected so
    # the endpoint map stays about the API surface rather than the bundle's own images/styles.
    _ASSET_EXT = re.compile(
        r"\.(?:svg|png|jpe?g|gif|webp|ico|css|scss|less|woff2?|ttf|eot|map|md|json|"
        r"html?|txt|snap|test|spec)\b", re.I)
    _ROUTE_LITERAL = re.compile(r"""["'`](/[A-Za-z0-9_\-/{}:.$]{1,120})["'`]""")
    _API_HINT = re.compile(r"(route|api|thunk|service|slice|endpoint|client)", re.I)

    def _extract_route_literals(self, body: str, source_js: str, src_name: str) -> None:
        """Harvest quoted absolute paths from recovered source into the endpoint map."""
        api_ish = bool(self._API_HINT.search(src_name))
        for path in self._ROUTE_LITERAL.findall(body):
            if self._ASSET_EXT.search(path):
                continue
            if path in ("/", "//") or path.count("/") < 1:
                continue
            self._merge_endpoint(
                path, source_js, is_api=api_ish,
                base_conf="high" if api_ish else "medium",
            )

    # -- endpoint extraction ---------------------------------------------------
    def _merge_endpoint(self, path: str, source_js: str, *, is_api: bool,
                        base_conf: str, method: str = "unknown") -> None:
        path = path.strip()
        if not path or len(path) > 512:
            return
        # Normalize: dedup on the path WITHOUT query/fragment so the same
        # endpoint seen with and without a query string collapses to one
        # record, with the query's keys folded into params.
        params = [k for k, _ in parse_qsl(urlsplit(path).query)] if "?" in path else []
        self._params_all.update(params)
        canon = path.split("#", 1)[0].split("?", 1)[0].strip() or path
        rec = self._endpoints.get(canon)
        if rec is None:
            self._endpoints[canon] = {
                "path": canon,
                "method": method,
                "params": sorted(set(params)),
                "source_js": source_js,
                "confidence": base_conf,
                "is_api": is_api,
                "_hits": 1,
            }
            return
        # merge: strongest signal wins
        rec["_hits"] += 1
        rec["is_api"] = rec["is_api"] or is_api
        if method != "unknown" and rec["method"] == "unknown":
            rec["method"] = method
        rec["params"] = sorted(set(rec["params"]) | set(params))
        rec["confidence"] = self._rank_up(rec["confidence"], base_conf, rec["_hits"])

    @staticmethod
    def _rank_up(a: str, b: str, hits: int) -> str:
        order = {"low": 0, "medium": 1, "high": 2}
        best = max(a, b, key=lambda x: order[x])
        if hits >= 2 and order[best] < 2:  # corroborated by 2+ extractors -> bump
            best = "medium" if best == "low" else "high"
        return best

    def extract_endpoints(self, content: str, source_js: str) -> None:
        for rx in self.rx_api:
            for m in rx.finditer(content):
                self._merge_endpoint(m.group(0), source_js, is_api=True, base_conf="high")
        for rx in self.rx_urls:
            for m in rx.finditer(content):
                url = m.group(0)
                p = urlsplit(url).path or url
                is_api = bool(re.search(r"/(api|v[0-9]+|graphql|rest)(/|$)", p))
                self._merge_endpoint(url, source_js, is_api=is_api,
                                     base_conf="high" if is_api else "medium")
        for rx in self.rx_routes:
            for m in rx.finditer(content):
                val = m.group(1) if m.groups() else m.group(0)
                self._merge_endpoint(val, source_js, is_api=False, base_conf="medium")
        for rx in self.rx_ws:
            for m in rx.finditer(content):
                val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                self._merge_endpoint(val, source_js, is_api=False, base_conf="medium", method="WS")
        for rx in self.rx_params:
            for m in rx.finditer(content):
                self._params_all.add(m.group(1))

    # -- secret extraction (hash + redact; NEVER emit raw value) ---------------
    def extract_secrets(self, content: str, source_js: str) -> None:
        for stype, sname, rx in self.secret_rules:
            for m in rx.finditer(content):
                raw = m.group(0)
                vhash = _sha256(raw)
                if vhash in self._secrets:
                    continue
                start, end = m.span()
                lo, hi = max(0, start - CONTEXT_RADIUS), min(len(content), end + CONTEXT_RADIUS)
                snippet = content[lo:hi].replace("\n", " ")
                # redact the secret itself out of the context window
                snippet = snippet.replace(raw, f"<REDACTED:{stype}:{len(raw)}>")
                self._secrets[vhash] = {
                    "type": stype,
                    "detector": sname,
                    "value_hash": vhash,
                    "context": snippet.strip()[:120],
                    "source_js": source_js,
                }

    # -- configuration / environment keys --------------------------------------
    # General SPA build behaviour, not app-specific: bundlers inline build-time environment
    # values into the shipped JavaScript, so the names (and often the values) of a
    # deployment's configuration are readable by anyone who downloads the bundle. The names
    # alone map the deployment's surface — which API base a client talks to, which feature
    # flags exist. Values are hashed and previewed, never emitted raw, exactly as secrets are.
    # Case-SENSITIVE by design. An earlier case-insensitive version let the
    # SCREAMING_SNAKE_CASE branch match any three-letter word, which flooded the artifact
    # with minified identifiers and SVG namespace declarations. Requiring a real underscore
    # (or one of the explicit config-name shapes) is what keeps this to actual config.
    _CONFIG_ASSIGN = re.compile(
        r"""(?x)
        \b(
            [A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+           # SCREAMING_SNAKE_CASE build constants
          | (?i:(?:api|base|service|backend|gateway)[_-]?url)
          | (?i:(?:api|app|client)[_-]?(?:id|base|host|endpoint))
        )
        \b["'\]\s]{0,4}[:=]>?\s*["']([^"']{3,200})["']
        """
    )

    #: Standards namespaces that appear in every bundle and describe no deployment.
    _NAMESPACE_HOSTS = ("w3.org", "schema.org", "purl.org", "xml.org", "json-schema.org")

    # -- base-URL concatenation resolution -------------------------------------
    # SPAs almost never write their API paths out in full. They define one base and
    # concatenate onto it:
    #
    #     const BASE_URL = config.api.URL;          // -> app/config/config.ts
    #     login: get(BASE_URL + "/login"),
    #
    # Extracting the literals alone yields "/login", which is indistinguishable from a
    # client-side route and never reaches the API prefix. The result is a recovered route
    # table that looks complete and describes nothing callable. Resolving the base — through
    # one or two levels of aliasing — is what turns recovered source into an attack surface.
    _BASE_LITERAL = re.compile(
        r"""(?x)
        \b([A-Za-z_$][\w$]*)                 # name
        \s*[:=]\s*
        [`"']([^`"']*://[^`"']*)[`"']        # a URL-ish literal or template
        """
    )
    _BASE_ALIAS = re.compile(
        r"""(?x)
        \b(?:const|let|var)?\s*
        ([A-Za-z_$][\w$]*)                   # name
        \s*[:=]\s*
        ([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)   # another identifier / dotted ref
        \s*[;,\n]
        """
    )
    _CONCAT_PATH = re.compile(
        r"""(?x)
        \b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)  # base identifier
        \s*\+\s*
        [`"'](/[^`"'\s]*)[`"']                        # + "/path"
        """
    )

    @staticmethod
    def _path_of_url_literal(literal: str) -> Optional[str]:
        """Return the path component of a URL literal, tolerating ``${...}`` template holes."""
        after = literal.split("://", 1)[1] if "://" in literal else literal
        slash = after.find("/")
        if slash == -1:
            return None
        path = after[slash:].rstrip("/")
        return path or None

    def collect_base_definitions(self, content: str) -> None:
        """First pass: record base-URL literals and aliases from ONE source file.

        Collected across every recovered source before any resolution happens, because the
        definition and the use are routinely in different files — the base lives in a config
        module and the concatenations live in the route table.
        """
        for m in self._BASE_LITERAL.finditer(content):
            literal = m.group(2)
            if any(h in literal for h in self._NAMESPACE_HOSTS):
                continue  # an XML/SVG namespace declaration, not a service base
            path = self._path_of_url_literal(literal)
            if path:
                self._base_literals.setdefault(m.group(1), path)
                # The full literal is kept too. Its AUTHORITY is what says which origin
                # the API actually lives on, and that is routinely not the origin serving
                # the bundle: a SPA on one port commonly calls an API on the default port
                # via `${window.location.hostname}` with no port of its own.
                self._base_url_literals.setdefault(path, literal)
        for m in self._BASE_ALIAS.finditer(content):
            self._base_aliases.setdefault(m.group(1), m.group(2).split(".")[-1])

    def _resolve_base(self, name: str, hops: int = 0) -> Optional[str]:
        """Follow aliases to a concrete base path, bounded against reference cycles."""
        key = name.split(".")[-1]
        if key in self._base_literals:
            return self._base_literals[key]
        if hops >= 5:
            return None
        nxt = self._base_aliases.get(key)
        return self._resolve_base(nxt, hops + 1) if nxt else None

    def resolve_concatenations(self, content: str, source_js: str) -> None:
        """Second pass: turn ``BASE + "/path"`` into a concrete API endpoint."""
        for m in self._CONCAT_PATH.finditer(content):
            base = self._resolve_base(m.group(1))
            if not base:
                continue
            self._merge_endpoint(
                f"{base}{m.group(2)}", source_js, is_api=True,
                base_conf="high", method="unknown",
            )
            self._concat_resolved += 1

    def extract_config(self, content: str, source_js: str) -> None:
        """Record configuration/environment keys inlined into the bundle at build time."""
        for rx in self.rx_env:
            for m in rx.finditer(content):
                name = m.group(1) if m.groups() else m.group(0)
                self._record_config(str(name), None, "env", source_js)
        for m in self._CONFIG_ASSIGN.finditer(content):
            name, value = m.group(1), m.group(2)
            is_url = value.startswith(("http://", "https://", "ws://", "wss://"))
            if is_url and any(h in value for h in self._NAMESPACE_HOSTS):
                continue  # a standards namespace, not this deployment's configuration
            kind = "api_base" if is_url or "url" in name.lower() else "constant"
            self._record_config(name, value, kind, source_js)

    def _record_config(
        self, name: str, value: str | None, kind: str, source_js: str
    ) -> None:
        """Merge one configuration entry, hashing any value rather than emitting it."""
        key = f"{kind}:{name}"
        if key in self._config or len(self._config) >= CONFIG_MAX:
            return
        entry: dict[str, Any] = {
            "key": name,
            "kind": kind,
            "source_js": source_js,
            "value_hash": None,
            "value_preview": None,
        }
        if value:
            entry["value_hash"] = _sha256(value)
            # A preview is enough to recognise a value without disclosing it. URLs are the
            # exception: the whole point of an API base is the location, and it is not a
            # secret — it is the attack surface.
            entry["value_preview"] = (
                value[:120] if value.startswith("http") else f"{value[:4]}…{value[-2:]}"
            )
        self._config[key] = entry

    # -- AST route extraction (esprima) ----------------------------------------
    def extract_routes_ast(self, content: str, source_js: str) -> None:
        if esprima is None:
            return
        if len(content.encode("utf-8", "replace")) > AST_MAX_BYTES:
            self._ast_skipped += 1
            return
        tree = None
        for parser in ("parseModule", "parseScript"):
            try:
                tree = getattr(esprima, parser)(content, {"tolerant": True, "jsx": True})
                break
            except Exception:  # noqa: BLE001 - try the other parser, then give up
                tree = None
        if tree is None:
            self._ast_skipped += 1
            self.errors.append({"stage": "ast", "error": f"{source_js}: parse failed"})
            return
        self._ast_ok += 1
        found: List[Tuple[str, bool]] = []

        def visit(node: Any, parent_key: Optional[str]) -> None:
            if isinstance(node, list):
                for item in node:
                    visit(item, parent_key)
                return
            if not hasattr(node, "type"):
                return
            ntype = getattr(node, "type", None)
            if ntype == "Literal":
                val = getattr(node, "value", None)
                if isinstance(val, str) and val.startswith("/") and 1 < len(val) <= 256 \
                        and " " not in val:
                    is_api = bool(re.search(r"^/(api|v[0-9]+|graphql|rest)(/|$)", val))
                    found.append((val, is_api))
            if ntype == "Property":
                key = getattr(node, "key", None)
                kname = getattr(key, "name", None) or getattr(key, "value", None)
                val = getattr(node, "value", None)
                if kname in _ROUTE_KEYS and getattr(val, "type", None) == "Literal":
                    v = getattr(val, "value", None)
                    if isinstance(v, str) and v.startswith("/"):
                        is_api = bool(re.search(r"^/(api|v[0-9]+|graphql|rest)(/|$)", v))
                        found.append((v, is_api))
            for attr, child in vars(node).items():
                if attr.startswith("_"):
                    continue
                if hasattr(child, "type") or isinstance(child, list):
                    visit(child, attr)

        try:
            visit(tree, None)
        except RecursionError:
            self.errors.append({"stage": "ast", "error": f"{source_js}: recursion limit"})
        for path, is_api in found:
            self._merge_endpoint(path, source_js, is_api=is_api,
                                 base_conf="high" if is_api else "low")

    # -- framework fingerprinting ----------------------------------------------
    def extract_framework(self) -> dict:
        blob = "\n".join(b["content"] for b in self.bundles.values())
        best = {"name": "unknown", "version": "", "routing_type": "unknown", "_score": 0}
        for rule in self.fw_rules:
            score = sum(1 for mk in rule.get("markers", []) if mk in blob)
            if score > best["_score"]:
                version = ""
                vpat = rule.get("version")
                if vpat:
                    try:
                        vm = re.search(vpat, blob)
                        if vm and vm.groups():
                            version = vm.group(1)
                    except re.error:
                        pass
                best = {
                    "name": rule["name"],
                    "version": version,
                    "routing_type": rule.get("routing_type", "unknown"),
                    "_score": score,
                }
        has_gql = any(rx.search(blob) for rx in self.rx_graphql)
        best.pop("_score", None)
        best["graphql_detected"] = has_gql
        return best

    def classify_confidence(self) -> None:
        # confidence is assigned during merge; here we just strip internal keys.
        for rec in self._endpoints.values():
            rec.pop("_hits", None)

    # -- assembly --------------------------------------------------------------
    def offload_and_return(self, started: float) -> dict:
        # Base definitions first, across every source, so a concatenation can resolve
        # against a base declared in a different file.
        for info in self.bundles.values():
            self.collect_base_definitions(info["content"])
        for url, info in self.bundles.items():
            self.extract_endpoints(info["content"], url)
            self.extract_secrets(info["content"], url)
            self.extract_config(info["content"], url)
            self.resolve_concatenations(info["content"], url)
            self.extract_routes_ast(info["content"], url)
        self.classify_confidence()

        framework = self.extract_framework()

        # Raw bundles ALWAYS offloaded (large, and needed for later evidence).
        raw_map = {u: {"sha256": i["sha256"], "bytes": i["bytes"], "content": i["content"]}
                   for u, i in self.bundles.items()}
        raw_bundles_spill_id = write_spill(raw_map) if raw_map else None

        endpoints = sorted(self._endpoints.values(), key=lambda e: (not e["is_api"], e["path"]))
        secrets = sorted(self._secrets.values(), key=lambda s: (s["type"], s["value_hash"]))

        # Offload Law: >200 matches (or >50KB) -> spill full set, cap inline.
        endpoints_overflow = None
        if len(endpoints) > MATCH_INLINE_CAP or should_offload(endpoints):
            endpoints_overflow = write_spill(endpoints)
            endpoints_inline = endpoints[:MATCH_INLINE_CAP]
        else:
            endpoints_inline = endpoints
        config = sorted(self._config.values(), key=lambda c: (c["kind"], c["key"]))
        config_overflow = None
        if len(config) > MATCH_INLINE_CAP or should_offload(config):
            config_overflow = write_spill(config)
            config_inline = config[:MATCH_INLINE_CAP]
        else:
            config_inline = config
        secrets_overflow = None
        if len(secrets) > MATCH_INLINE_CAP or should_offload(secrets):
            secrets_overflow = write_spill(secrets)
            secrets_inline = secrets[:MATCH_INLINE_CAP]
        else:
            secrets_inline = secrets

        param_block = offload_list(sorted(self._params_all), always=False)

        status = "ok"
        if not self.bundles and self.errors:
            status = "error"

        return {
            "endpoints": [
                {k: e[k] for k in ("path", "method", "params", "source_js", "confidence", "is_api")}
                for e in endpoints_inline
            ],
            "secrets": [
                {k: s[k] for k in ("type", "value_hash", "context", "source_js", "detector")}
                for s in secrets_inline
            ],
            "config": config_inline,
            "framework": framework,
            "raw_bundles_spill_id": raw_bundles_spill_id,
            # ---- additive, schema-permitted fields ----
            "meta": {
                "skill": "js-spa-reverse",
                "version": "1.0",
                "phase": "1-2",
                "target": self.target,
                "status": status,
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "bundles_analyzed": len(self.bundles),
                "bundles_skipped": self.skipped_urls,
                "endpoint_count": len(endpoints),
                "source_maps": list(self.source_maps.values()),
                "secret_count": len(secrets),
                "endpoints_overflow_spill_id": endpoints_overflow,
                "secrets_overflow_spill_id": secrets_overflow,
                "config_count": len(config),
                "base_paths": sorted(set(self._base_literals.values())),
                "base_url_literals": dict(self._base_url_literals),
                "concat_endpoints_resolved": self._concat_resolved,
                "config_overflow_spill_id": config_overflow,
                "param_inventory": param_block,
                "ast_parsed": self._ast_ok,
                "ast_skipped": self._ast_skipped,
                "esprima_available": esprima is not None,
            },
            "scope_summary": {
                "policy_spill_id": self.scope_id,
                "policy_present": self.scope.have_policy,
                "urls_requested": len(self.js_urls),
                "urls_analyzed": len(self.bundles),
                "urls_skipped": len(self.skipped_urls),
            },
            "errors": self.errors,
        }

    async def run(self) -> dict:
        started = time.time()
        await self.download_bundles()
        return self.offload_and_return(started)


# --- input handling & entry point --------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"js_urls\":[...],\"target\":\"...\"}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str, target: str = "") -> dict:
    return {
        "endpoints": [],
        "secrets": [],
        "config": [],
        "framework": {"name": "unknown", "version": "", "routing_type": "unknown"},
        "raw_bundles_spill_id": None,
        "meta": {"skill": "js-spa-reverse", "version": "1.0", "phase": "1-2",
                 "target": target, "status": "error", "generated_at": _now_iso()},
        "scope_summary": {"policy_spill_id": None, "policy_present": False,
                          "urls_requested": 0, "urls_analyzed": 0, "urls_skipped": 0},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2

    js_urls = payload.get("js_urls") or []
    target = str(payload.get("target", "")).strip()
    if not isinstance(js_urls, list) or not js_urls:
        print(json.dumps(_error_artifact("missing 'js_urls' (non-empty list required)", target)))
        return 2

    skill = JSReverseEngineer(
        js_urls=js_urls,
        target=target,
        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
        config=payload.get("config"),
    )
    artifact = await skill.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
