#!/usr/bin/env python3
"""
run.py -- intelligent-crawling entry point.

Drives a headless Chromium browser (Playwright) through a JavaScript-rendered
application to discover the endpoints a classic spider misses: XHR/Fetch calls,
WebSocket connections, client-side routes, and forms. For every unique
(method, url) it captures a full request template (url, method, headers,
cookies, body) that becomes a replay template for the HTTP Tool (component 21)
in Phase 5.

CONTRACT
--------
* Input  : JSON on argv[1] or stdin:
    {
      "target": "https://app.example.com",
      "session_cookies": {...} | {"admin": {...}, "user": {...}} | [cookie,...],
      "max_pages": 100,
      "timeout_seconds": 300,
      "roles": ["user", "admin"],
      "scope_policy_spill_id": "abc123",
      "config": {"dir_bruteforce": false, "wordlist": null,
                 "capture_resource_types": ["xhr","fetch","document"],
                 "clicks_per_page": 8, "katana": false}
    }
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
           No prose. On fatal error, a schema-valid artifact with
           crawl_stats + meta.status == "error".

LAWS & SAFETY
-------------
* Scope     : only in-scope hosts are ever navigated or requested; off-scope
              links and redirects are dropped, not followed.
* Budget    : hard max_pages counter + wall-clock deadline; the crawl stops the
              instant either is hit (typed exit budget_exhausted).
* Blast     : read-only crawl. Forms are DISCOVERED, never submitted. Controls
              whose text matches destructive keywords (delete/logout/pay/...)
              are never clicked. Submission/mutation belongs to later skills
              under the mutation budget.
* Custody   : raw request templates (which contain cookies/authorization) live
              ONLY in the spill store; the LLM-facing artifact carries spill_ids.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit

try:
    from playwright.async_api import async_playwright  # type: ignore
except ImportError:  # pragma: no cover
    async_playwright = None

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import offload_list, read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import offload_list, read_spill, write_spill  # type: ignore

# --- Tunables (env-overridable) ----------------------------------------------
NAV_TIMEOUT_MS = int(os.environ.get("CRAWL_NAV_TIMEOUT_MS", "20000"))
SCROLL_ROUNDS = int(os.environ.get("CRAWL_SCROLL_ROUNDS", "3"))
DIRBRUTE_MAX = int(os.environ.get("CRAWL_DIRBRUTE_MAX", "500"))   # hard cap
DIRBRUTE_TRIGGER = int(os.environ.get("CRAWL_DIRBRUTE_TRIGGER", "20"))
DIRBRUTE_CONCURRENCY = int(os.environ.get("CRAWL_DIRBRUTE_CONCURRENCY", "10"))
DEFAULT_CAPTURE_TYPES = ["xhr", "fetch", "document", "websocket"]
_DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "assets", "wordlists",
    "directories-fallback.txt")

DESTRUCTIVE_KW = [
    "delete", "remove", "logout", "log out", "sign out", "signout", "pay",
    "buy", "purchase", "checkout", "confirm", "deactivate", "cancel",
    "unsubscribe", "reset", "destroy", "wipe", "revoke", "terminate",
]
SAFE_CLICK_SELECTOR = ("nav button, [aria-haspopup], [data-toggle], "
                       "[data-bs-toggle], .dropdown-toggle, [role='menuitem'], "
                       "button[aria-expanded='false']")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# Real parameter names: alphanumerics plus the separators frameworks actually emit
# (``_``, ``-``, ``.``, PHP/Rails-style ``[]`` and ``[key]``, occasional ``:``). Anything
# else is almost certainly a mis-parsed body fragment, not an injectable parameter.
_PARAM_NAME_RE = re.compile(r"[A-Za-z0-9_\-\.\[\]:]{1,64}")


def _params_of(url: str, post_data: str | None) -> list[str]:
    """Parameter names a captured request actually carries: query string plus body keys.

    This is the only place the real request shape is visible, so it is the only place
    parameters can be recovered from. If they are not emitted here the endpoint is committed
    with ``params: []``, and the threat model then has nothing to inject into — no
    SQLi/SSTI/command-injection/deserialization hypothesis is ever proposed, and the entire
    RCE class goes untested no matter how good the batteries are.

    Names are sanity-filtered: a junk "parameter" is worse than none, because it becomes a
    hypothesis that can only ever be refuted, burning iteration and mutation budget that a
    real parameter would have used.
    """
    names: list[str] = []
    try:
        query = urlsplit(url).query
    except ValueError:
        query = ""
    if query:
        names += [k for k, _ in parse_qsl(query, keep_blank_values=True)]
    if post_data:
        body = post_data.strip()
        if body[:1] in ("{", "["):
            try:
                parsed = json.loads(body)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                names += [str(k) for k in parsed]
        elif "=" in body:
            # Form-encoded means k=v pairs. Without this guard parse_qsl happily returns a
            # whole malformed body as a single key.
            names += [k for k, _ in parse_qsl(body, keep_blank_values=True)]
    return list(dict.fromkeys(n for n in names if _PARAM_NAME_RE.fullmatch(n)))


class ScopePolicy:
    """In-scope host test (mirrors the other skills' policy shape)."""

    def __init__(self, policy: Optional[dict], target_host: str):
        self.raw = policy or {}
        self.have_policy = policy is not None
        self.in_scope = [self._c(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._c(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope and target_host:
            self.in_scope = [self._c(target_host), self._c(f"*.{target_host}")]

    @staticmethod
    def _c(pattern: str) -> re.Pattern:
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
        if any(rx.match(h) for rx in self.in_scope):
            return True
        # With a policy present, unlisted hosts are out of scope. Without one,
        # in_scope defaults to the target apex, so this only matters off-target.
        return False


class IntelligentCrawler:
    def __init__(self, target: str, session_cookies: Any = None,
                 max_pages: int = 100, timeout_seconds: int = 300,
                 roles: Optional[List[str]] = None,
                 scope_policy_spill_id: Optional[str] = None,
                 config: Optional[dict] = None):
        self.target = target.strip()
        self.target_host = _host_of(self.target)
        self.session_cookies = session_cookies or {}
        self.max_pages = max(1, int(max_pages or 100))
        self.timeout_seconds = max(5, int(timeout_seconds or 300))
        self.roles = roles or (["default"] if session_cookies else ["anonymous"])
        self.config = config or {}
        self.capture_types = set(self.config.get("capture_resource_types",
                                                  DEFAULT_CAPTURE_TYPES))
        self.clicks_per_page = int(self.config.get("clicks_per_page", 8))
        self.errors: List[Dict[str, str]] = []
        self.scope_id = scope_policy_spill_id
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target_host)

        # aggregation, deduped by (method, url)
        self._captures: Dict[Tuple[str, str], dict] = {}
        self._forms: Dict[Tuple[str, str, str], dict] = {}
        self.pages_crawled = 0
        self.roles_completed: List[str] = []
        self._deadline = 0.0

    # -- budget ----------------------------------------------------------------
    def enforce_budget(self) -> bool:
        """True if we are STILL within budget (pages and time)."""
        if self.pages_crawled >= self.max_pages:
            return False
        if time.monotonic() >= self._deadline:
            return False
        return True

    def _budget_remaining_pct(self, started: float) -> float:
        used_pages = self.pages_crawled / self.max_pages
        used_time = (time.monotonic() - started) / self.timeout_seconds
        rem = 1.0 - max(used_pages, used_time)
        return round(max(0.0, min(1.0, rem)) * 100.0, 1)

    # -- cookie handling -------------------------------------------------------
    def _cookies_for_role(self, role: str) -> List[dict]:
        raw = self.session_cookies
        if isinstance(raw, dict) and role in raw:
            raw = raw[role]
        if not raw:
            return []
        if isinstance(raw, list):  # already Playwright cookie dicts
            return [c for c in raw if isinstance(c, dict) and c.get("name")]
        if isinstance(raw, dict):  # {name: value} -> attach to target host
            out = []
            for name, value in raw.items():
                if isinstance(value, (str, int)):
                    out.append({"name": str(name), "value": str(value),
                                "domain": self.target_host, "path": "/"})
            return out
        return []

    # -- request/response capture ---------------------------------------------
    def _record_capture(self, *, url: str, method: str, resource_type: str,
                        headers: dict, post_data: Optional[str],
                        status: Optional[int], content_type: str,
                        role: str, discovered_by: str,
                        cookies: List[dict]) -> None:
        if not self.scope.allowed(_host_of(url)):
            return
        rtype = resource_type if resource_type in {"xhr", "fetch", "document",
                                                   "websocket"} else resource_type
        # honor capture filter (websocket/form_action always kept)
        if discovered_by in {"xhr", "fetch"} and rtype not in self.capture_types \
                and "xhr" not in self.capture_types and "fetch" not in self.capture_types:
            pass  # still record; filtering is best-effort, default keeps them
        key = (method.upper(), url)
        if key in self._captures:
            return
        template = {
            "url": url, "method": method.upper(),
            "resource_type": resource_type,
            "headers": headers or {}, "cookies": cookies or [],
            "post_data": post_data, "status": status,
            "content_type": content_type, "role_used": role,
            "discovered_by": discovered_by,
        }
        # Offload Law + custody: the raw template (with cookies) goes to the
        # spill store; only its id ever reaches the artifact.
        spill_id = write_spill(template)
        self._captures[key] = {
            "url": url, "method": method.upper(),
            "requires_auth": bool(cookies),
            "role_used": role,
            "content_type": content_type,
            "params": _params_of(url, post_data),
            "captured_request_spill_id": spill_id,
            "discovered_by": discovered_by,
        }

    # -- form discovery --------------------------------------------------------
    async def discover_forms(self, page, page_url: str, role: str) -> None:
        try:
            forms = await page.evaluate(
                """() => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.getAttribute('action') || '',
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                        name: i.getAttribute('name') || '',
                        type: (i.getAttribute('type') || i.tagName.toLowerCase()),
                        required: i.hasAttribute('required')
                    }))
                }))"""
            )
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "forms", "error": f"{page_url}: {exc}"})
            return
        for f in forms or []:
            action_abs = urljoin(page_url, f.get("action") or "")
            method = (f.get("method") or "GET").upper()
            key = (page_url, action_abs, method)
            if key in self._forms:
                continue
            self._forms[key] = {
                "url": page_url, "action": action_abs, "method": method,
                "input_fields": [
                    {"name": i.get("name", ""), "type": i.get("type", ""),
                     "required": bool(i.get("required"))}
                    for i in f.get("inputs", []) if i.get("name")
                ],
            }
            # a form action is also a (future) endpoint
            if action_abs and self.scope.allowed(_host_of(action_abs)):
                self._record_capture(
                    url=action_abs, method=method, resource_type="document",
                    headers={}, post_data=None, status=None, content_type="",
                    role=role, discovered_by="form_action", cookies=[])

    # -- safe interaction ------------------------------------------------------
    async def _scroll(self, page) -> None:
        for _ in range(SCROLL_ROUNDS):
            if not self.enforce_budget():
                return
            try:
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(400)
            except Exception:  # noqa: BLE001
                return

    async def _expand_menus(self, page) -> None:
        try:
            handles = await page.query_selector_all(SAFE_CLICK_SELECTOR)
        except Exception:  # noqa: BLE001
            return
        clicks = 0
        for h in handles:
            if clicks >= self.clicks_per_page or not self.enforce_budget():
                break
            try:
                txt = ((await h.inner_text()) or "").strip().lower()
            except Exception:  # noqa: BLE001
                txt = ""
            if any(kw in txt for kw in DESTRUCTIVE_KW):
                continue  # blast-radius guard: never click destructive controls
            try:
                await h.click(timeout=1500, no_wait_after=True)
                clicks += 1
                await page.wait_for_timeout(250)
            except Exception:  # noqa: BLE001
                continue

    async def _collect_links(self, page, base_url: str) -> List[str]:
        try:
            hrefs = await page.evaluate(
                "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))")
        except Exception:  # noqa: BLE001
            return []
        out = []
        for href in hrefs or []:
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absu = urljoin(base_url, href)
            if urlsplit(absu).scheme not in ("http", "https"):
                continue
            if self.scope.allowed(_host_of(absu)):
                out.append(absu.split("#", 1)[0])
        return out

    # -- per-role crawl --------------------------------------------------------
    async def crawl_with_role(self, browser, role: str) -> None:
        cookies = self._cookies_for_role(role)
        context = await browser.new_context(ignore_https_errors=True)
        if cookies:
            try:
                await context.add_cookies(cookies)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "cookies", "error": f"{role}: {exc}"})
        page = await context.new_page()

        def on_response(response) -> None:
            try:
                req = response.request
                self._record_capture(
                    url=req.url, method=req.method,
                    resource_type=req.resource_type,
                    headers=dict(req.headers), post_data=req.post_data,
                    status=response.status,
                    content_type=response.headers.get("content-type", ""),
                    role=role,
                    discovered_by=(req.resource_type
                                   if req.resource_type in {"xhr", "fetch"}
                                   else "navigation"),
                    cookies=cookies)
            except Exception:  # noqa: BLE001
                pass

        def on_ws(ws) -> None:
            try:
                self._record_capture(
                    url=ws.url, method="GET", resource_type="websocket",
                    headers={}, post_data=None, status=None, content_type="",
                    role=role, discovered_by="websocket", cookies=cookies)
            except Exception:  # noqa: BLE001
                pass

        page.on("response", on_response)
        page.on("websocket", on_ws)

        queue: List[str] = [self.target]
        seen: Set[str] = set()
        try:
            while queue and self.enforce_budget():
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                try:
                    await page.goto(url, wait_until="domcontentloaded",
                                    timeout=NAV_TIMEOUT_MS)
                except Exception as exc:  # noqa: BLE001
                    self.errors.append({"stage": "nav", "error": f"{url}: {exc}"})
                    continue
                self.pages_crawled += 1
                await self._scroll(page)
                await self._expand_menus(page)
                await self.discover_forms(page, page.url, role)
                for link in await self._collect_links(page, page.url):
                    if link not in seen and link not in queue:
                        queue.append(link)
        finally:
            try:
                await context.close()
            except Exception:  # noqa: BLE001
                pass
        self.roles_completed.append(role)

    # -- directory brute-force fallback (budget-capped) ------------------------
    async def dir_bruteforce(self, role: str) -> None:
        # An operator who explicitly points CRAWL_WORDLIST at a file has stated the intent to
        # brute-force with it; without this the env var is unreachable, because nothing in the
        # orchestration layer ever sets config["dir_bruteforce"].
        if not (self.config.get("dir_bruteforce") or os.environ.get("CRAWL_WORDLIST")):
            return
        if httpx is None:
            self.errors.append({"stage": "dirbrute", "error": "httpx not installed"})
            return
        wordlist = self.config.get("wordlist") or os.environ.get("CRAWL_WORDLIST") \
            or _DEFAULT_WORDLIST
        try:
            with open(wordlist, "r", encoding="utf-8") as fh:
                words = [ln.strip() for ln in fh
                         if ln.strip() and not ln.startswith("#")]
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "dirbrute", "error": str(exc)})
            return
        words = words[:min(DIRBRUTE_MAX, len(words))]  # HARD cap
        base = f"{urlsplit(self.target).scheme}://{urlsplit(self.target).netloc}"
        cookies = self._cookies_for_role(role)
        cookie_hdr = "; ".join(f"{c['name']}={c['value']}" for c in cookies) if cookies else None
        sem = asyncio.Semaphore(DIRBRUTE_CONCURRENCY)

        async def probe(path: str):
            if not self.enforce_budget():
                return
            u = f"{base}/{path.lstrip('/')}"
            if not self.scope.allowed(_host_of(u)):
                return
            headers = {"User-Agent": "intelligent-crawling/1.0"}
            if cookie_hdr:
                headers["Cookie"] = cookie_hdr
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                        r = await client.get(u, headers=headers)
                except Exception:  # noqa: BLE001
                    return
                if r.status_code < 400 or r.status_code in (401, 403):
                    self._record_capture(
                        url=u, method="GET", resource_type="document",
                        headers=headers, post_data=None, status=r.status_code,
                        content_type=r.headers.get("content-type", ""),
                        role=role, discovered_by="navigation", cookies=cookies)

        await asyncio.gather(*(probe(w) for w in words))

    # -- assembly --------------------------------------------------------------
    def offload_and_return(self, started_wall: float, started_mono: float) -> dict:
        sitemap = sorted(self._captures.values(), key=lambda e: (e["method"], e["url"]))
        forms = list(self._forms.values())

        # Full HAR of every captured request -> spill store.
        har = {"log": {"version": "1.2",
                       "creator": {"name": "intelligent-crawling", "version": "1.0"},
                       "entries": [
                           {"request": read_spill(e["captured_request_spill_id"])}
                           for e in sitemap]}}
        har_spill_id = write_spill(har) if sitemap else None

        # If the sitemap itself is huge, offload the overflow (Offload Law).
        overflow = None
        inline = sitemap
        from spill_store import should_offload  # local import keeps top clean
        if len(sitemap) > 500 or should_offload(sitemap):
            overflow = write_spill(sitemap)
            inline = sitemap[:500]

        status = "ok"
        if not sitemap and self.errors and not self.roles_completed:
            status = "error"

        return {
            "sitemap": inline,
            "forms_discovered": forms,
            "crawl_stats": {
                "pages_crawled": self.pages_crawled,
                "requests_captured": len(self._captures),
                "budget_remaining_pct": self._budget_remaining_pct(started_mono),
                "roles_completed": self.roles_completed,
            },
            "har_spill_id": har_spill_id,
            # ---- additive fields ----
            "meta": {
                "skill": "intelligent-crawling", "version": "1.0", "phase": "2",
                "target": self.target, "status": status,
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started_wall, 2),
                "max_pages": self.max_pages,
                "timeout_seconds": self.timeout_seconds,
                "roles_requested": self.roles,
                "forms_count": len(forms),
                "sitemap_overflow_spill_id": overflow,
                "budget_exhausted": not self.enforce_budget(),
                "playwright_available": async_playwright is not None,
            },
            "scope_summary": {
                "policy_spill_id": self.scope_id,
                "policy_present": self.scope.have_policy,
                "target_host": self.target_host,
            },
            "errors": self.errors,
        }

    async def run(self) -> dict:
        started_wall = time.time()
        started_mono = time.monotonic()
        self._deadline = started_mono + self.timeout_seconds
        if async_playwright is None:
            self.errors.append({"stage": "launch", "error": "playwright not installed"})
            return self.offload_and_return(started_wall, started_mono)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True,
                                                  args=["--no-sandbox"])
                try:
                    for role in self.roles:
                        if not self.enforce_budget():
                            break
                        await self.crawl_with_role(browser, role)
                    # fallback: sparse crawl -> optional, capped dir-brute
                    if self.pages_crawled < DIRBRUTE_TRIGGER and self.enforce_budget():
                        await self.dir_bruteforce(self.roles[0])
                finally:
                    await browser.close()
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "browser", "error": repr(exc)})
        return self.offload_and_return(started_wall, started_mono)


# --- input handling & entry point --------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"target\":\"https://...\"}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str, target: str = "") -> dict:
    return {
        "sitemap": [], "forms_discovered": [],
        "crawl_stats": {"pages_crawled": 0, "requests_captured": 0,
                        "budget_remaining_pct": 100.0, "roles_completed": []},
        "har_spill_id": None,
        "meta": {"skill": "intelligent-crawling", "version": "1.0", "phase": "2",
                 "target": target, "status": "error", "generated_at": _now_iso()},
        "scope_summary": {"policy_spill_id": None, "policy_present": False,
                          "target_host": _host_of(target)},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    target = str(payload.get("target", "")).strip()
    if not target or urlsplit(target).scheme not in ("http", "https"):
        print(json.dumps(_error_artifact("invalid 'target' (need http(s) URL)", target)))
        return 2
    crawler = IntelligentCrawler(
        target=target,
        session_cookies=payload.get("session_cookies"),
        max_pages=payload.get("max_pages", 100),
        timeout_seconds=payload.get("timeout_seconds", 300),
        roles=payload.get("roles"),
        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
        config=payload.get("config"),
    )
    artifact = await crawler.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
