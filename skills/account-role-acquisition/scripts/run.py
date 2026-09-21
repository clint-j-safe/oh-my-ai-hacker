#!/usr/bin/env python3
"""
run.py -- account-role-acquisition entry point.

Autonomously creates TEST identities on an in-scope target, walks the
signup/verification/MFA-enrollment flow for each requested role, and captures a
fresh authenticated session per role -- the session pool every access-control
test in Phase 3+ depends on.

HARD BOUNDARIES (non-negotiable)
--------------------------------
* NEW identities only. This skill has no `credentials` input and never logs in
  with supplied or guessed credentials -- no credential stuffing, no brute
  force, no customer accounts. It registers fresh throwaway accounts and logs
  into those.
* In scope only. Registration/verification navigation stays on the in-scope
  target host; off-scope redirects are not followed for account creation.
* MFA = self-enrollment. If the flow enrolls TOTP for the account we just
  created, we read the seed the app shows the account owner (us) and compute
  our own codes. We do NOT attempt to defeat another user's MFA.
* Custody. Full browser state (cookies, localStorage, sessionStorage,
  storage_state) is offloaded to the spill store; the artifact carries the
  session summary and a state_spill_id.

CONTRACT
--------
* Input  : JSON on argv[1] or stdin:
    { "target": "https://app.example.com",
      "roles_to_create": ["standard_user", "tenant_admin"],
      "captcha_api_key": "env:CAPTCHA_API_KEY" | "<key>",
      "signup_path": "/register",            # optional hint
      "scope_policy_spill_id": "abc123",     # optional
      "config": {"captcha_provider": "2captcha", "verify_timeout": 120,
                 "mail_api": "mail.tm", "max_retries": 2} }
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
           No prose. On fatal error, a schema-valid artifact with
           registration_status.success == false.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

try:
    from playwright.async_api import async_playwright  # type: ignore
except ImportError:  # pragma: no cover
    async_playwright = None

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import write_spill, read_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import write_spill, read_spill  # type: ignore

try:
    from browser_agent import BrowserAgent
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from browser_agent import BrowserAgent  # type: ignore

# --- Tunables ----------------------------------------------------------------
NAV_TIMEOUT_MS = int(os.environ.get("ACCT_NAV_TIMEOUT_MS", "25000"))
VERIFY_TIMEOUT = int(os.environ.get("ACCT_VERIFY_TIMEOUT", "120"))
CAPTCHA_POLL_TIMEOUT = int(os.environ.get("ACCT_CAPTCHA_TIMEOUT", "180"))
# Ceiling on a wait the APPLICATION asked for. A target is free to state any cool-down;
# we honour it up to a bound so a hostile or mistaken value cannot stall a whole scan.
MAX_COOLDOWN_SECONDS = int(os.environ.get("ACCT_MAX_COOLDOWN", "600"))
CAPTURED_RESPONSE_CAP = int(os.environ.get("ACCT_CAPTURED_RESPONSES", "40"))
CAPTURED_RESPONSE_CHARS = int(os.environ.get("ACCT_CAPTURED_CHARS", "4000"))
# Per-candidate wait for a login control to render. Short: this runs once per candidate
# route, so a generous value multiplies across the whole candidate list.
LOGIN_FORM_TIMEOUT_MS = int(os.environ.get("ACCT_LOGIN_FORM_TIMEOUT_MS", "4000"))
MAIL_TM = "https://api.mail.tm"
TWOCAPTCHA_IN = "https://2captcha.com/in.php"
TWOCAPTCHA_RES = "https://2captcha.com/res.php"
SIGNUP_CANDIDATES = ["/register", "/signup", "/sign-up", "/users/sign_up",
                     "/account/register", "/auth/register", "/join", "/create-account"]


def _merge_rules(existing: List[str], new: List[str], cap: int = 15) -> List[str]:
    """Return the union of two rule lists, order preserved, bounded.

    Deduplicated on exact text because the rules are the application's own words, and two
    phrasings of the same constraint are two facts worth having. Bounded because they are
    prompt text on every step of every attempt.
    """
    out = list(existing)
    for rule in new or []:
        text = str(rule).strip()
        if text and text not in out:
            out.append(text)
    return out[-cap:]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# --- RFC 4226 HOTP / RFC 6238 TOTP (dependency-free, for OUR test account) ----
def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_now(secret_b32: str, digits: int = 6, period: int = 30,
             at: Optional[float] = None) -> Optional[str]:
    try:
        pad = "=" * ((8 - len(secret_b32) % 8) % 8)
        key = base64.b32decode(secret_b32.strip().replace(" ", "").upper() + pad)
    except Exception:  # noqa: BLE001
        return None
    counter = int((at if at is not None else time.time()) // period)
    return hotp(key, counter, digits)


def _random_msisdn(digits: int = 10) -> str:
    """Return a random subscriber number that will not collide with an earlier run.

    Ten digits with a non-zero lead is the shape most national formats accept and the one
    registration forms most often validate against. It is a generic phone-number shape, not
    a fact about any particular application.
    """
    return secrets.choice("6789") + "".join(secrets.choice(string.digits) for _ in range(digits - 1))


def _strong_password(n: int = 16, *, symbols: bool = False) -> str:
    """Return a random password meeting the complexity rules most applications state.

    Alphanumeric by default, which is a deliberate reversal. The generator used to always
    include a symbol from ``!@#$%^&*-_`` on the reasoning that symbols satisfy complexity
    rules — but a rule that *requires* a symbol is rarer than a validator that *rejects*
    one, and the second failure is silent and total. Measured on a live target: every
    registration was refused with "Parameter passwd is invalid or not set" until the
    symbols were dropped, at which point the identical request succeeded.

    Mixed case plus digits satisfies the common "upper, lower and a number" policy on its
    own. An application that genuinely demands a symbol says so in its rejection, and the
    caller retries with ``symbols=True`` — a rejection that names its rule is recoverable,
    whereas a charset validator that refuses everything looks like a broken signup.
    """
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*-_")
    pw = [secrets.choice(p) for p in pools]
    allc = "".join(pools)
    pw += [secrets.choice(allc) for _ in range(max(0, n - len(pw)))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


class ScopePolicy:
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
        return any(rx.match(h) for rx in self.in_scope)


class AccountAcquisition:
    def __init__(self, target: str, roles_to_create: List[str],
                 captcha_api_key: Optional[str] = None,
                 signup_path: Optional[str] = None,
                 scope_policy_spill_id: Optional[str] = None,
                 config: Optional[dict] = None):
        self.target = target.strip().rstrip("/")
        self.target_host = _host_of(self.target)
        self.roles = roles_to_create or ["standard_user"]
        self.captcha_key = self._resolve_key(captcha_api_key)
        self.signup_path = signup_path
        self.config = config or {}
        self.verify_timeout = int(self.config.get("verify_timeout", VERIFY_TIMEOUT))
        self.max_retries = int(self.config.get("max_retries", 2))
        self.errors: List[Dict[str, str]] = []
        # Per-role agent traces, surfaced in the artifact so a failed registration carries a
        # reason (the durable replacement for the reverted F9 diagnostics).
        self.agent_diagnostics: List[dict] = []
        #: Everything this target has stated about its own input, across every attempt.
        # Seeded from the framework's TargetModel when it has learned anything about this
        # application already, then extended by what this run discovers. A constraint the
        # target stated during an earlier phase is still true here, and rediscovering it
        # costs steps from a budget measured running out.
        self.stated_rules: List[str] = [
            str(r)[:200] for r in (self.config.get("stated_rules") or [])
        ][:15]
        #: Authentication routes the framework's own recon actually observed, ahead of
        #: this module's guesses. Measured on a client-rendered target: eight hardcoded
        #: candidates were tried, a password field was awaited on each, and the route that
        #: worked came last — 270 seconds spent rediscovering what recon already had. The
        #: guess list stays as the fallback for a target whose login page nothing links to.
        self.login_candidates: List[str] = [
            str(c)[:200] for c in (self.config.get("login_candidates") or [])
        ][:10]
        self.captcha_used = False
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target_host)
        self.scope_id = scope_policy_spill_id

    @staticmethod
    def _resolve_key(k: Optional[str]) -> Optional[str]:
        if not k:
            return None
        if k.startswith("env:"):
            return os.environ.get(k[4:])
        return os.environ.get(k) if k.isupper() and os.environ.get(k) else k

    # -- Mail.tm temp email ----------------------------------------------------
    async def generate_temp_email(self) -> Optional[dict]:
        if httpx is None:
            self.errors.append({"stage": "email", "error": "httpx not installed"})
            return None
        try:
            async with httpx.AsyncClient(timeout=30, base_url=MAIL_TM) as c:
                doms = (await c.get("/domains")).json()
                members = doms.get("hydra:member") or doms.get("member") or []
                if not members:
                    raise RuntimeError("no mail.tm domains")
                domain = members[0]["domain"]
                local = "qa." + secrets.token_hex(6)
                address = f"{local}@{domain}"
                pw = _strong_password(14)
                r = await c.post("/accounts", json={"address": address, "password": pw})
                if r.status_code not in (200, 201):
                    raise RuntimeError(f"account create HTTP {r.status_code}")
                tok = await c.post("/token", json={"address": address, "password": pw})
                token = tok.json().get("token")
                return {"address": address, "password": pw, "token": token}
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "email", "error": str(exc)})
            return None

    async def _poll_mail_link(self, token: str) -> Optional[str]:
        """Poll Mail.tm for a verification/confirmation link."""
        if httpx is None or not token:
            return None
        deadline = time.time() + self.verify_timeout
        headers = {"Authorization": f"Bearer {token}"}
        link_re = re.compile(r"https?://[^\s\"'<>]+(?:verify|confirm|activate|token=)[^\s\"'<>]*", re.I)
        async with httpx.AsyncClient(timeout=30, base_url=MAIL_TM, headers=headers) as c:
            while time.time() < deadline:
                try:
                    msgs = (await c.get("/messages")).json()
                    for m in (msgs.get("hydra:member") or msgs.get("member") or []):
                        full = (await c.get(f"/messages/{m['id']}")).json()
                        text = (full.get("html") or [""])
                        text = " ".join(text) if isinstance(text, list) else str(text)
                        text += " " + str(full.get("text", ""))
                        mm = link_re.search(text)
                        if mm:
                            return mm.group(0)
                except Exception as exc:  # noqa: BLE001
                    self.errors.append({"stage": "verify_poll", "error": str(exc)})
                await asyncio.sleep(5)
        return None

    # -- 2Captcha ---------------------------------------------------------------
    async def solve_captcha(self, kind: str, sitekey: str, page_url: str) -> Optional[str]:
        if not self.captcha_key or httpx is None:
            return None
        method = {"recaptcha": "userrecaptcha", "hcaptcha": "hcaptcha",
                  "turnstile": "turnstile"}.get(kind, "userrecaptcha")
        params = {"key": self.captcha_key, "method": method,
                  "googlekey" if method == "userrecaptcha" else "sitekey": sitekey,
                  "pageurl": page_url, "json": 1}
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = (await c.get(TWOCAPTCHA_IN, params=params)).json()
                if str(r.get("status")) != "1":
                    self.errors.append({"stage": "captcha", "error": f"submit: {r.get('request')}"})
                    return None
                cid = r["request"]
                deadline = time.time() + CAPTCHA_POLL_TIMEOUT
                await asyncio.sleep(15)
                while time.time() < deadline:
                    res = (await c.get(TWOCAPTCHA_RES, params={
                        "key": self.captcha_key, "action": "get",
                        "id": cid, "json": 1})).json()
                    if str(res.get("status")) == "1":
                        self.captcha_used = True
                        return res["request"]
                    if res.get("request") != "CAPCHA_NOT_READY":
                        self.errors.append({"stage": "captcha", "error": str(res.get("request"))})
                        return None
                    await asyncio.sleep(5)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "captcha", "error": str(exc)})
        return None

    async def _detect_and_solve_captcha(self, page) -> None:
        specs = [
            ("recaptcha", ".g-recaptcha[data-sitekey], [data-sitekey].g-recaptcha", "g-recaptcha-response"),
            ("hcaptcha", ".h-captcha[data-sitekey], [data-sitekey].h-captcha", "h-captcha-response"),
            ("turnstile", ".cf-turnstile[data-sitekey], [data-sitekey].cf-turnstile", "cf-turnstile-response"),
        ]
        for kind, selector, field in specs:
            try:
                el = await page.query_selector(selector)
                if not el:
                    continue
                sitekey = await el.get_attribute("data-sitekey")
            except Exception:  # noqa: BLE001
                continue
            if not sitekey:
                continue
            token = await self.solve_captcha(kind, sitekey, page.url)
            if token:
                try:
                    await page.evaluate(
                        """([f,t]) => { let e=document.getElementsByName(f)[0];
                           if(!e){e=document.createElement('textarea');e.name=f;
                                   e.style.display='none';document.body.appendChild(e);} e.value=t; }""",
                        [field, token])
                except Exception as exc:  # noqa: BLE001
                    self.errors.append({"stage": "captcha", "error": f"inject: {exc}"})
            return

    # -- registration ----------------------------------------------------------
    async def _find_signup(self, page) -> Optional[str]:
        # The root goes LAST, for the reason LOGIN_CANDIDATES already puts it last: a
        # single-page app commonly renders a LOGIN form on its landing route, and a login
        # form has a password field too. Checking the root second meant the search stopped
        # there and handed the agent a login page to register on. Measured on this target:
        # "/" carries 2 inputs and "/signup" carries 7, and the search returned "/".
        candidates = []
        if self.signup_path:
            candidates.append(urljoin(self.target + "/", self.signup_path.lstrip("/")))
        candidates += [self.target + p for p in SIGNUP_CANDIDATES]
        candidates.append(self.target)
        for url in candidates:
            if not self.scope.allowed(_host_of(url)):
                continue
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except Exception:  # noqa: BLE001
                continue
            # Wait for the control instead of querying for it at DOMContentLoaded. On a
            # client-rendered application the registration form does not exist yet at that
            # moment, so an instant query reports "no signup form here" for every candidate
            # and the search fails in a few seconds against exactly the application class
            # this framework targets. ``_login_account`` already waits, for this reason and
            # with this comment; signup was left querying and so never found a form on a
            # single-page app. Measured: both roles failed in 4.5s with the browser agent
            # never constructed, on a target whose registration page renders fine.
            try:
                await page.wait_for_selector(
                    "input[type=password]", timeout=LOGIN_FORM_TIMEOUT_MS
                )
            except Exception:  # noqa: BLE001 - this candidate simply has no signup form
                continue
            return page.url
        return None

    async def _submit(self, page) -> None:
        """Generic submit, retained only for the TOTP-code step in ``_maybe_totp``.
        Registration form submission is now driven by the LLM agent, not this helper."""
        for sel in ("button[type=submit]", "input[type=submit]",
                    "button:has-text('Sign up')", "button:has-text('Register')",
                    "button:has-text('Create')", "button:has-text('Continue')"):
            try:
                btn = await page.query_selector(sel)
                if btn:
                    await btn.click(timeout=3000)
                    return
            except Exception:  # noqa: BLE001
                continue
        try:  # fallback: submit the first form
            await page.evaluate("() => { const f=document.querySelector('form'); if(f) f.submit(); }")
        except Exception:  # noqa: BLE001
            pass

    async def _maybe_totp(self, page) -> Optional[str]:
        """If the flow enrolls TOTP for OUR account, capture the seed & code."""
        try:
            content = await page.content()
        except Exception:  # noqa: BLE001
            return None
        m = re.search(r"otpauth://totp/[^\s\"'<>]*[?&]secret=([A-Z2-7]{16,})", content, re.I)
        if not m:
            m = re.search(r"\b(?:secret|key)\b[\"'\s:=>]{1,6}([A-Z2-7]{16,52})\b", content)
        if not m:
            return None
        seed = m.group(1)
        code = totp_now(seed)
        if not code:
            return None
        try:  # type the code into any TOTP/OTP input and submit
            for sel in ("input[name*=otp i]", "input[name*=totp i]", "input[name*=code i]",
                        "input[autocomplete=one-time-code]", "input[inputmode=numeric]"):
                el = await page.query_selector(sel)
                if el:
                    await el.fill(code, timeout=2000)
                    await self._submit(page)
                    break
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "totp", "error": str(exc)})
        return seed

    async def register_account(self, context, role: str) -> dict:
        result = {"role": role, "ok": False, "username": None, "email": None,
                  "mfa_enrolled": False}
        email_obj = await self.generate_temp_email()
        if not email_obj:
            result["error"] = "temp email unavailable"
            return result
        password = _strong_password(16)
        # Bound here rather than inline at the agent call, because the number the account was
        # REGISTERED with is a login identifier candidate and was previously thrown away the
        # moment it was generated. An application that authenticates by mobile could then
        # never be logged into: the only value that would have worked no longer existed.
        msisdn = _random_msisdn()
        result["email"] = email_obj["address"]
        result["msisdn"] = msisdn
        result["username"] = email_obj["address"]
        result["_password"] = password  # used only for this registration; discarded, never emitted
        result["_email_token"] = email_obj.get("token")

        page = await context.new_page()
        signup_url = await self._find_signup(page)
        if not signup_url:
            result["error"] = "no signup form found on target"
            await page.close()
            return result

        # The LLM-driven agent reads the page and decides one validated action per step; code
        # permits and executes it (see browser_agent.py). It replaces the old selector
        # heuristics, which could not cope with a required <select>, a type=date input, or a
        # JS-bound <button type="button"> submit control.
        # Capture what the app says back while the agent drives the form. The identifier a
        # signup issues is frequently returned only in an XHR body or shown once on screen,
        # and it is what a later login will demand.
        captured: List[Dict[str, Any]] = []

        async def _on_response(response) -> None:
            try:
                if len(captured) >= CAPTURED_RESPONSE_CAP:
                    return
                ctype = (response.headers or {}).get("content-type", "")
                if "json" in ctype or "text" in ctype:
                    captured.append({
                        "url": response.url,
                        "status": response.status,
                        # Kept because acceptance must distinguish an API reply from the
                        # page you were already looking at; see _signup_accepted.
                        "content_type": ctype,
                        "body": (await response.text())[:CAPTURED_RESPONSE_CHARS],
                    })
            except Exception:  # noqa: BLE001 - diagnostics only; never fail a signup on this
                pass

        page.on("response", _on_response)

        agent_result = None
        for attempt in range(self.max_retries + 1):
            try:
                await page.goto(signup_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except Exception:  # noqa: BLE001
                pass
            # The agent has no captcha action, so solve any captcha (injecting the token into
            # the page) before it drives the form to submission.
            await self._detect_and_solve_captcha(page)
            agent = BrowserAgent(
                page,
                goal="register a new account and confirm the app accepted it",
                # Email is fixed (it is tied to the inbox we poll for verification); the password
                # is only a suggestion the agent may change to satisfy the target's policy.
                #
                # A unique phone number is supplied for the same reason the email is. Left to
                # invent one, a model reaches for a memorable pattern, and registration forms
                # very commonly require the number to be unique — so the same few numbers are
                # tried and rejected on every run. Measured: twenty-five steps spent entirely
                # on "Mobile number already exists", with the budget exhausted before the form
                # was ever accepted. Supplying a random one costs nothing and removes a
                # collision the agent cannot reason its way out of.
                facts={
                    "email": email_obj["address"],
                    "phone or mobile number (already unique, use as-is)": msisdn,
                },
                adaptable={"password": password},
                prior_rules=self.stated_rules,
                in_scope=self.scope.allowed,
                max_steps=int(os.environ.get("BROWSER_AGENT_MAX_STEPS", "25")),
                goal_reached=lambda: _signup_accepted(captured),
            )
            agent_result = await agent.run()
            # Carried across attempts. A constraint the application stated during signup is
            # still true at login, and re-learning it there costs steps from a budget that
            # has already been measured running out: twenty-four calls cycling between
            # "password rejected" and "mobile number already exists", converging on nothing.
            self.stated_rules = _merge_rules(
                self.stated_rules, getattr(agent_result, "stated_rules", [])
            )
            result["agent"] = agent_result.as_dict()  # full per-step trace for diagnostics
            result["captured_sample"] = _captured_sample(captured)
            # Keep whatever password the agent actually used (it may have adapted it).
            password = agent_result.credentials.get("password", password)
            result["_password"] = password
            body = ""
            try:
                body = (await page.content()).lower()
            except Exception:  # noqa: BLE001
                pass
            if re.search(r"already (exists|registered|taken)|email.*in use", body):
                # edge case: account exists -> fresh temp email and retry with new facts
                email_obj = await self.generate_temp_email() or email_obj
                result["email"] = email_obj["address"]
                result["username"] = email_obj["address"]
                result["_email_token"] = email_obj.get("token")
                continue
            # If the app asked us to wait, wait. Retrying into a stated cool-down is how a
            # lockout becomes permanent, and the delay is the app's own number, not a guess.
            cooldown = self._cooldown_seconds(body) or self._cooldown_seconds(
                _captured_text(captured[-3:])
            )
            if cooldown and attempt < self.max_retries:
                self.errors.append(
                    {"stage": f"register:{role}", "error": f"honouring {cooldown}s cool-down"}
                )
                await asyncio.sleep(cooldown)
                continue
            break

        # The identifier the app issued us, which a later login may demand instead of the
        # email we registered with. Searched in what the app returned first, then in what it
        # rendered, because an XHR body is the more reliable of the two.
        result["login_identifier"] = (
            self._identifier_from_text(_captured_text(captured))
            or self._identifier_from_text(await _safe_content_raw(page))
            or ""
        )

        # email verification, if required
        link = await self._poll_mail_link(result.get("_email_token")) if \
            re.search(r"verif|confirm|check your (e-?mail|inbox)", (await _safe_content(page))) else None
        if link and self.scope.allowed(_host_of(link)):
            try:
                await page.goto(link, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "verify_click", "error": str(exc)})

        # MFA self-enrollment for this account, if presented
        seed = await self._maybe_totp(page)
        if seed:
            result["mfa_enrolled"] = True
            result["_totp_seed"] = seed

        # Success requires BOTH signals: the agent reported it registered AND the app
        # actually issued us something to authenticate with. Requiring both stops an
        # over-optimistic model from claiming an identity the app never created.
        #
        # "Something to authenticate with" means a scoped cookie OR a token in web storage.
        # Requiring a cookie alone made success structurally impossible for any app that
        # authenticates by bearer token — and the extraction that finds those tokens used to
        # run only AFTER this verdict, so the evidence that would have proved success was
        # never gathered. State extraction is therefore hoisted above the verdict and its
        # result reused, rather than recomputed later.
        # Registration is not authentication. Plenty of applications create the account and
        # leave you signed out, so a scan that stops at "registered" holds no session and
        # every authenticated test downstream is unreachable. If signup left us without
        # credentials, log in with what the app issued us.
        signup_ok = bool(agent_result and agent_result.success) or _signup_accepted(captured)
        cookies, auth_headers, state_spill_id = await self.offload_state(context, page)
        if signup_ok and not (cookies or auth_headers):
            await self._login_account(
                page,
                identifier=result.get("login_identifier") or result.get("email") or "",
                # Every value this account was actually registered with. Which one the login
                # accepts is the application's business, and it says so plainly when asked
                # with the wrong one -- "Username or Password is incorrect" was the whole of
                # a failed engagement's evidence. Offering a single candidate made that
                # clear answer unactionable: there was nothing else to try.
                alternates={
                    "account identifier issued at signup": result.get("login_identifier") or "",
                    "registration email": result.get("email") or "",
                    "registered mobile number": result.get("msisdn") or "",
                },
                password=password,
                captured=captured,
                role=role,
            )
            # Re-read the identifier: a login screen often states the expected format, and
            # the app may only reveal it after the first failed attempt.
            if not result.get("login_identifier"):
                result["login_identifier"] = (
                    self._identifier_from_text(_captured_text(captured)) or ""
                )
            cookies, auth_headers, state_spill_id = await self.offload_state(context, page)
        session_like = [c for c in cookies
                        if self.target_host.endswith((c.get("domain") or "").lstrip("."))
                        or (c.get("domain") or "").lstrip(".").endswith(self.target_host)]
        agent_ok = bool(agent_result and agent_result.success)
        # The wire, not the narrator. ``_signup_accepted`` and ``_login_accepted`` already
        # judge acceptance from what the server returned, and their own docstrings say the
        # agent's report is not sufficient evidence — but the verdict then asked the agent
        # anyway, so a run that registered, logged in and was holding real credentials was
        # discarded because the model had not said the word "success". The same obstruction
        # those functions exist to see past (a success dialog covering the submit control,
        # after which every click times out) is exactly what stops the agent reporting it.
        #
        # Evidence of acceptance is therefore any of the three, and a credential we can
        # actually present is still required on top: acceptance without a cookie or token
        # is an account, not a session, and every authenticated test downstream needs the
        # session. A claim alone can no longer create one, and neither can a stray cookie.
        wire_ok = signup_ok or _login_accepted(captured)
        holds_credential = bool(session_like) or bool(auth_headers)
        result["ok"] = (agent_ok or wire_ok) and holds_credential
        if not result["ok"]:
            if agent_ok or wire_ok:
                reason = "account accepted but no session cookie or bearer token was issued"
            elif agent_result is not None:
                reason = (
                    agent_result.stopped_reason
                    or agent_result.note
                    or "agent did not confirm and the wire showed no acceptance"
                )
            else:
                reason = "agent did not run"
            # Carried on the result too, not only in the error list: the per-role
            # diagnostic reads result["error"], and without this every failure was
            # reported as `err=None`, which says nothing to whoever reads the artifact.
            result["error"] = reason
            self.errors.append({"stage": f"register:{role}", "error": reason})
        result["_state"] = (cookies, auth_headers, state_spill_id)
        result["_page"] = page
        return result

    # -- login (turning a registration into a session) --------------------------
    # "/" is included deliberately and last: single-page applications frequently present
    # the login form on the landing route rather than at a dedicated path.
    LOGIN_CANDIDATES = ["/login", "/signin", "/sign-in", "/auth/login", "/users/sign_in",
                        "/account/login", "/session/new", "/"]

    async def _login_account(
        self, page, *, identifier: str, password: str,
        captured: List[Dict[str, Any]], role: str,
        alternates: dict[str, str] | None = None,
    ) -> bool:
        """Authenticate the account we just created, honouring any stated cool-down.

        ``identifier`` is the best guess — whatever the application issued at signup,
        falling back to the registration email. ``alternates`` carries every OTHER value the
        account was registered with, each under a label saying what it is.

        This docstring used to claim the agent "is told both facts and reads the error if it
        picks wrong". It was not: exactly one identifier reached the agent, and the mobile
        number was discarded at the moment it was generated. An application authenticating by
        any other value answered "Username or Password is incorrect" — correctly,
        unambiguously, and with nothing the agent could do about it.
        """
        ordered = self.login_candidates + [
            p for p in self.LOGIN_CANDIDATES if p not in self.login_candidates
        ]
        for path in ordered:
            url = urljoin(self.target + "/", path.lstrip("/"))
            if not self.scope.allowed(_host_of(url)):
                continue
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except Exception:  # noqa: BLE001
                continue
            # Wait for the control rather than querying for it immediately. On a
            # client-rendered application the form does not exist at DOMContentLoaded, so an
            # instant query reports "no login form here" for every route and the search
            # fails against precisely the app class this framework targets.
            try:
                await page.wait_for_selector(
                    "input[type=password]", timeout=LOGIN_FORM_TIMEOUT_MS
                )
            except Exception:  # noqa: BLE001 - this route simply has no login form
                continue

            facts: Dict[str, str] = {"password": password}
            if identifier:
                facts["account identifier issued at signup"] = identifier
            # Every other value this account was registered with, each labelled. Blank
            # entries and the one already named above are skipped so the prompt never
            # carries an empty fact or the same value twice.
            for label, value in (alternates or {}).items():
                if value and value != identifier and label not in facts:
                    facts[label] = value
            agent = BrowserAgent(
                page,
                goal=(
                    "log in to the account that was just created. The facts list every "
                    "value this account was registered with; exactly one of them is the "
                    "login identifier this application accepts, and which one is its own "
                    "business. Start with the account identifier issued at signup if there "
                    "is one, since an application that issues an identifier usually expects "
                    "it. If the app rejects the credentials, READ what it said and try the "
                    "next value from the facts rather than retrying the same one — a "
                    "rejection naming the username is evidence about the identifier, not "
                    "about the password. Confirm the app accepted the credentials."
                ),
                facts=facts,
                adaptable={},
                prior_rules=self.stated_rules,
                in_scope=self.scope.allowed,
                max_steps=int(os.environ.get("BROWSER_AGENT_LOGIN_STEPS", "20")),
                goal_reached=lambda: _login_accepted(captured),
            )
            outcome = await agent.run()
            self.stated_rules = _merge_rules(
                self.stated_rules, getattr(outcome, "stated_rules", [])
            )
            self.agent_diagnostics.append({
                "role": role, "phase": "login", "path": path,
                "identifier_used": identifier,
                # Everything that COULD have been the identifier, not just the one used:
                # a diagnostic listing a single candidate cannot show whether the login
                # failed for want of alternatives or because none of them was right.
                "identifier_candidates": sorted(
                    {
                        c
                        for c in (
                            self._identifier_from_text(_captured_text(captured)),
                            identifier,
                            *(alternates or {}).values(),
                        )
                        if c
                    }
                ),
                "captured_sample": _captured_sample(captured),
                "ok": bool(outcome and outcome.success),
                "stopped": getattr(outcome, "stopped_reason", ""),
                "note": str(getattr(outcome, "note", ""))[:300],
            })
            cooldown = self._cooldown_seconds(_captured_text(captured[-5:]))
            if cooldown:
                self.errors.append(
                    {"stage": f"login:{role}", "error": f"honouring {cooldown}s cool-down"}
                )
                await asyncio.sleep(cooldown)
                outcome = await agent.run()
            return bool(outcome and outcome.success)
        self.errors.append({"stage": f"login:{role}", "error": "no login form found"})
        return False

    # -- login-identifier discovery --------------------------------------------
    # The credential a signup ISSUES is not always the one a login ACCEPTS. Plenty of
    # applications register you by email and then authenticate you by an account number
    # they generate and show you once. Assuming the email is the identifier makes every
    # subsequent login fail with a message that reads like bad credentials.
    #
    # These patterns look for a labelled identifier in whatever the app said after signup —
    # a general convention (a label, then a code), not knowledge of any one app's format.
    # The LABEL is matched case-insensitively — an application may write "User ID",
    # "user id" or "USERID" — but the CODE is not, and that distinction is load-bearing.
    # Under a blanket (?i) the code class [A-Z0-9][A-Z0-9_-]{3,23} matches ordinary
    # lowercase English, so "user id format is invalid" yielded the identifier "format".
    # That was observed live: the skill then attempted to log in as "format", failed, and
    # reported an identifier problem that did not exist.
    _LABELLED_ID = re.compile(
        r"""(?x)
        (?i:\b(?:user\s*id|userid|customer\s*(?:id|number|no)|account\s*(?:id|number|no)
           |client\s*id|member\s*(?:id|no)|reference\s*(?:id|no)|login\s*id)\b)
        \W{0,24}?
        ([A-Z0-9][A-Z0-9_-]{3,23})
        """
    )
    #: A bare code shaped like an issued identifier, used only when no label is found.
    _BARE_ID = re.compile(r"\b([A-Z]{2,5}\d{4,12})\b")

    @classmethod
    def _identifier_from_text(cls, text: str) -> Optional[str]:
        """Return an issued login identifier found in ``text``, or None.

        A candidate must contain a digit. Issued identifiers essentially always do, and the
        requirement is what separates a real code from the next English word after a label
        — "format", "required", "invalid" and "mandatory" all fit the character class
        otherwise. Being wrong here is expensive in a way that being conservative is not: a
        bad candidate is *used*, the login fails, and the failure is misread as the
        application rejecting a correct credential.
        """
        if not text:
            return None
        labelled = cls._LABELLED_ID.search(text)
        if labelled and any(ch.isdigit() for ch in labelled.group(1)):
            return labelled.group(1)
        bare = cls._BARE_ID.search(text)
        return bare.group(1) if bare else None

    #: A wait the application itself asks for, in seconds or minutes. Respecting a stated
    #: cool-down is both politer and more effective than retrying into a lockout.
    _COOLDOWN = re.compile(
        r"(?i)\b(?:wait|retry|try\s+again|locked?|cool\s*down)\b[^.\n]{0,40}?"
        r"(\d{1,5})\s*(seconds?|secs?|s|minutes?|mins?|m)\b"
    )

    @classmethod
    def _cooldown_seconds(cls, text: str) -> Optional[int]:
        """Return a cool-down the application asked for, in seconds, if it stated one."""
        m = cls._COOLDOWN.search(text or "")
        if not m:
            return None
        value = int(m.group(1))
        unit = m.group(2).lower()
        seconds = value * 60 if unit.startswith("m") and not unit.startswith("s") else value
        return min(seconds, MAX_COOLDOWN_SECONDS)

    # -- auth material detection -----------------------------------------------
    # A JWT anywhere inside a stored value, not only as the whole value. Applications
    # routinely stash the token inside a JSON blob (``userData = {"token":"eyJ..."}``), and
    # an anchored match misses every one of those — which reads as "this app issued no
    # token" when it plainly did.
    _JWT_ANYWHERE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")

    #: Storage keys whose names conventionally hold an opaque session credential. Used only
    #: when no JWT is found, since an opaque token is indistinguishable from any other
    #: string without a naming hint.
    _TOKEN_KEY_HINT = re.compile(r"(?i)\b(?:auth|access|id|session|bearer|api)?[_-]?token\b|\bjwt\b")
    _MIN_OPAQUE_TOKEN = 20

    @classmethod
    def _auth_headers_from_storage(
        cls, storage_state: dict, session_storage: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Return Authorization headers derived from local/session storage, if any.

        Searches every stored value rather than testing it whole, so a token nested in JSON
        is found. Falls back to a conventionally-named opaque credential when no JWT is
        present, because plenty of applications do not use JWTs at all.
        """
        pairs: List[Tuple[str, str]] = []
        for origin in storage_state.get("origins", []):
            for kv in origin.get("localStorage", []):
                pairs.append((str(kv.get("name", "")), str(kv.get("value", ""))))
        for name, value in (session_storage or {}).items():
            pairs.append((str(name), str(value)))

        for _name, value in pairs:
            found = cls._JWT_ANYWHERE.search(value)
            if found:
                return {"Authorization": f"Bearer {found.group(0)}"}
        for name, value in pairs:
            if cls._TOKEN_KEY_HINT.search(name) and len(value) >= cls._MIN_OPAQUE_TOKEN:
                return {"Authorization": f"Bearer {value}"}
        return {}

    # -- session extraction & offload ------------------------------------------
    async def offload_state(self, context, page) -> Tuple[List[dict], Dict[str, str], str]:
        try:
            storage_state = await context.storage_state()
        except Exception:  # noqa: BLE001
            storage_state = {"cookies": [], "origins": []}
        cookies = storage_state.get("cookies", [])
        # sessionStorage (not in storage_state) captured per page
        session_storage = {}
        try:
            session_storage = await page.evaluate(
                "() => { const o={}; for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k);} return o; }")
        except Exception:  # noqa: BLE001
            pass
        # derive auth headers from a bearer/JWT-looking token in web storage
        auth_headers = self._auth_headers_from_storage(storage_state, session_storage)
        state = {"storage_state": storage_state, "session_storage": session_storage,
                 "captured_at": _now_iso()}
        state_spill_id = write_spill(state)
        # normalize cookies to the artifact shape
        norm = [{"name": c.get("name"), "value": c.get("value"),
                 "domain": c.get("domain"), "httpOnly": c.get("httpOnly", False),
                 "secure": c.get("secure", False),
                 "sameSite": c.get("sameSite", "Lax")} for c in cookies]
        return norm, auth_headers, state_spill_id

    # -- orchestration ---------------------------------------------------------
    async def run(self) -> dict:
        started = time.time()
        session_pool: List[dict] = []
        failed: List[str] = []
        if async_playwright is None:
            self.errors.append({"stage": "launch", "error": "playwright not installed"})
            return self._artifact(session_pool, failed, started, fatal=True)
        if not self.scope.allowed(self.target_host):
            self.errors.append({"stage": "scope", "error": f"{self.target_host} not in scope"})
            return self._artifact(session_pool, failed, started, fatal=True)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    for role in self.roles:
                        context = await browser.new_context(ignore_https_errors=True)
                        try:
                            res = await self.register_account(context, role)
                            self.agent_diagnostics.append({
                                "role": role, "ok": bool(res.get("ok")),
                                "agent": res.get("agent"), "error": res.get("error"),
                            })
                            if res.get("ok") and res.get("_state") is not None:
                                # Reuse the state captured at verdict time. Re-extracting
                                # here would re-read storage after the page may have moved
                                # on, and could disagree with the verdict just made.
                                cookies, auth, sid = res["_state"]
                                session_pool.append({
                                    "role": role, "username": res.get("username") or "",
                                    "login_identifier": res.get("login_identifier") or "",
                                    "cookies": cookies, "auth_headers": auth,
                                    "state_spill_id": sid,
                                    "mfa_enrolled": res.get("mfa_enrolled", False),
                                    "agent": res.get("agent"),
                                })
                            else:
                                failed.append(role)
                                if res.get("error"):
                                    self.errors.append({"stage": f"register:{role}",
                                                        "error": res["error"]})
                        finally:
                            await context.close()
                finally:
                    await browser.close()
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "browser", "error": repr(exc)})
        return self._artifact(session_pool, failed, started)

    def _artifact(self, session_pool, failed, started, fatal=False) -> dict:
        success = (not fatal) and len(session_pool) > 0 and not failed \
            if session_pool or failed else not fatal
        return {
            "session_pool": session_pool,
            "registration_status": {
                "success": bool(session_pool) and not fatal,
                "failed_roles": failed,
                "captcha_bypass_used": self.captcha_used,
            },
            "meta": {
                "skill": "account-role-acquisition", "version": "1.0", "phase": "3",
                "target": self.target,
                "status": "ok" if (session_pool and not fatal) else "error",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "roles_requested": self.roles,
                "roles_acquired": [s["role"] for s in session_pool],
                "new_identities_only": True,
                "credential_reuse": False,
                # What this application said about its own inputs, verbatim, across every
                # attempt. Accumulated all along and then dropped on the floor: the skill
                # learned the contract and kept it to itself, so the next phase — and the
                # next run — rediscovered it from scratch at the cost of the attempts that
                # taught it. The target's own words about its own validation are the most
                # reliable sentences in an engagement; they are worth carrying out.
                "stated_rules": list(self.stated_rules),
            },
            "scope_summary": {"policy_spill_id": self.scope_id,
                              "policy_present": self.scope.have_policy,
                              "target_host": self.target_host},
            "registration_diagnostics": self.agent_diagnostics,
            "errors": self.errors,
        }


def _captured_sample(entries: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    """Return a bounded, readable sample of what the application actually answered.

    Emitted in the artifact so a failed acquisition is legible from its output alone.
    Without it the artifact says ok=false and nothing else, and every diagnosis of why
    sessions were not acquired has required re-running the skill by hand with print
    statements — three times so far this milestone.

    Bodies are truncated and only auth-relevant URLs are kept, so this stays a diagnostic
    rather than a transcript. Password values never appear here: the skill sends them, the
    server does not echo them, and nothing in this function reads the request side.
    """
    out: List[Dict[str, Any]] = []
    for entry in entries or []:
        url = str(entry.get("url") or "")
        if not _AUTH_ENDPOINT.search(url):
            continue
        out.append({
            "url": url[:200],
            "status": entry.get("status"),
            "body": str(entry.get("body") or "")[:400],
        })
    return out[-limit:]


def _captured_text(entries: List[Dict[str, Any]]) -> str:
    """Return the concatenated bodies of captured responses."""
    return "\n".join(str(e.get("body", "")) for e in entries or [])


#: URL shapes that carry an account-creation or authentication result. Broad web
#: convention, not one application's routing.
_AUTH_ENDPOINT = re.compile(r"(?i)/(?:sign[_-]?up|register|account|users?|auth|login|session)")
#: Wire-level markers that an account-creation request was accepted.
_ACCEPTED = re.compile(r"(?i)\b(?:success|created|registered|accepted)\b|\"status\"\s*:\s*(?:true|200|201)")


def _signup_accepted(entries: List[Dict[str, Any]]) -> bool:
    """Return True when the wire shows an account-creation request was accepted.

    The agent's own report is not sufficient evidence. Once a success dialog covers the
    submit control, every further click times out and the agent cannot tell whether it
    succeeded and is being obstructed, or never succeeded at all — it burns its whole step
    budget on an element it can no longer reach. What the server returned does not have
    that ambiguity, so acceptance is judged from the response, not from the model.
    """
    for entry in entries or []:
        status = int(entry.get("status") or 0)
        if not (200 <= status < 300):
            continue
        if not _AUTH_ENDPOINT.search(str(entry.get("url") or "")):
            continue
        # An acceptance is an API reply, not a document. Navigating to /signup returns the
        # application shell, whose URL matches the auth pattern and whose body routinely
        # contains an acceptance word for reasons that have nothing to do with an account:
        # Create React App ships `content="Web site created using create-react-app"`, and
        # "created" alone was enough. Measured on this target — the goal fired on page
        # load, the agent stopped having made zero model calls without filling the form,
        # and the verdict believed a registration had been accepted.
        #
        # The separator is that the body PARSES as JSON, not that a header claims it does.
        # Measured on a live target: /api/signup answers
        # {"status":"Success","status_code":"SNUP02",...} under
        # `content-type: text/html; charset=UTF-8`, so trusting the header would refuse a
        # genuine acceptance — the mirror of the bug this check exists to prevent. A
        # structured reply is still required, because the shell served at /signup is HTML
        # that happens to contain an acceptance word and must never count.
        body = str(entry.get("body") or "")
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            continue
        if not isinstance(parsed, dict):
            continue
        if _ACCEPTED.search(body):
            return True
    return False


#: A login response that issued a credential. The presence of a token on the wire is a
#: stronger signal than anything the page renders.
_TOKEN_IN_BODY = re.compile(
    r"(?i)\b(?:access[_-]?token|id[_-]?token|jwt|bearer)\b|eyJ[A-Za-z0-9_-]{8,}\.eyJ"
)


def _login_accepted(entries: List[Dict[str, Any]]) -> bool:
    """Return True when the wire shows an authentication request issued a credential."""
    for entry in entries or []:
        status = int(entry.get("status") or 0)
        if 200 <= status < 300 and _TOKEN_IN_BODY.search(str(entry.get("body") or "")):
            return True
    return False


async def _safe_content(page) -> str:
    """Return the page's text lowercased, for case-insensitive presence checks."""
    return (await _safe_content_raw(page)).lower()


async def _safe_content_raw(page) -> str:
    """Return the page's text with its original casing.

    Issued identifiers are conventionally upper-case, so the lowercased variant above
    destroys the very signal an identifier search depends on.
    """
    try:
        return await page.content()
    except Exception:  # noqa: BLE001
        return ""


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"target\":\"https://...\",\"roles_to_create\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str, target: str = "") -> dict:
    return {
        "session_pool": [],
        "registration_status": {"success": False, "failed_roles": [],
                                "captcha_bypass_used": False},
        "meta": {"skill": "account-role-acquisition", "version": "1.0", "phase": "3",
                 "target": target, "status": "error", "generated_at": _now_iso(),
                 "new_identities_only": True, "credential_reuse": False},
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
    acq = AccountAcquisition(
        target=target,
        roles_to_create=payload.get("roles_to_create") or ["standard_user"],
        captcha_api_key=payload.get("captcha_api_key"),
        signup_path=payload.get("signup_path"),
        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
        config=payload.get("config"),
    )
    artifact = await acq.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
