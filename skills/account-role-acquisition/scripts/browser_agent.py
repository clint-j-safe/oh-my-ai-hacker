#!/usr/bin/env python3
"""
browser_agent.py -- LLM-driven Playwright agent for interacting with ANY web form.

WHY THIS EXISTS
---------------
The previous approach enumerated selectors: ``button[type=submit]``, then
``button:has-text('Sign up')``, then ``button[id*=submit i]``, and keyword-matched field names
("email", "dob", "company"). Every unfamiliar app needed another entry. On the live target that
chain failed three separate ways in a row — a required ``<select>`` that ``fill()`` cannot set, a
``<input type="date">`` that rejected free text, and a submit control that was
``<button type="button" id="submitButtonDiv">`` with the handler bound in JavaScript, so no
``[type=submit]`` selector matched and the form was never posted at all.

Adding a fourth selector would have found a fourth failure. Instead the LLM looks at the page and
decides what to do, which is what "works regardless of tech stack" actually requires.

DIVISION OF LABOUR (this is the important part)
-----------------------------------------------
The LLM only ever PROPOSES one action per step, as JSON. Everything else is deterministic code:

* the page snapshot the LLM sees is built by code, and only from elements code found visible;
* every proposed action is checked against a fixed allowlist before it runs;
* ``index`` must refer to an element that exists and is not disabled;
* ``goto`` is refused unless the host passes the caller's scope predicate;
* the step budget, the values used for email/password, and the stop condition are all code;
* the LLM cannot execute JavaScript, cannot touch the network directly, and cannot invent an
  action verb — an unrecognised proposal is rejected and reported back to it as an error.

So the model chooses *what* to do; this module decides whether it is permitted and *how* it runs.

LLM ACCESS
----------
Prefers the framework's ``ModelRouter`` (tier config, provider abstraction, cost accounting) when
importable, and falls back to a direct OpenRouter chat call so the skill still runs standalone.
Both read the same environment.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

# The agent is a leaf module inside a skill bundle; the framework root is two levels above
# skills/<name>/scripts, which is where core/ lives when running inside the repo or the image.
_FRAMEWORK_ROOT = os.environ.get("SAHW_ROOT", "")
if not _FRAMEWORK_ROOT:
    _here = os.path.dirname(os.path.abspath(__file__))
    for _candidate in (os.path.abspath(os.path.join(_here, "..", "..", "..")), "/app"):
        if os.path.isdir(os.path.join(_candidate, "core")):
            _FRAMEWORK_ROOT = _candidate
            break

# Actions the LLM may propose. Anything outside this list is rejected outright.
ALLOWED_ACTIONS = frozenset({"fill", "click", "select", "check", "uncheck", "goto", "press", "done"})
# Keys permitted for the "press" action, so the model cannot send arbitrary input sequences.
ALLOWED_KEYS = frozenset({"Enter", "Tab", "Escape", "ArrowDown", "ArrowUp", "Space"})

#: Distinct application statements carried in the prompt. Bounded because they are
#: prompt text on every step of every attempt.
_MAX_STATED_RULES = 15

DEFAULT_MAX_STEPS = int(os.environ.get("BROWSER_AGENT_MAX_STEPS", "25"))
LLM_TIMEOUT = float(os.environ.get("BROWSER_AGENT_LLM_TIMEOUT", "90"))

#: Attempts per proposal before the transport is declared unusable. The model returning
#: nothing is a transient event, not a verdict on the run: measured over one engagement,
#: 13 of 966 completions came back empty. Without a retry each one ended a 25-step agent
#: that was mid-form, discarding an account the signup had already created.
_LLM_ATTEMPTS = int(os.environ.get("BROWSER_AGENT_LLM_ATTEMPTS", "3"))
#: Consecutive step failures tolerated before the agent gives up. A single failure is now a
#: step error like any other -- the loop already treats unparseable JSON that way, and an
#: unparseable reply is the WORSE signal of the two -- but a persistent outage must still
#: end the run rather than burn the whole step budget against a dead provider.
_MAX_CONSECUTIVE_LLM_FAILURES = 3

#: LiteLLM addresses OpenRouter as ``openrouter/<author>/<model>``; OpenRouter's own REST API
#: wants the ``<author>/<model>`` slug and rejects the prefixed form with 400 Bad Request.
#: MODEL_TIER_FRONTIER is written in LiteLLM's dialect because the framework router speaks it,
#: so the direct path -- and only the direct path -- has to translate.
_LITELLM_OPENROUTER_PREFIX = "openrouter/"


def openrouter_slug(model: str) -> str:
    """Return ``model`` as OpenRouter's REST API names it.

    Posting the LiteLLM-prefixed name verbatim is a guaranteed 400, and the 400 surfaced as
    ``llm_error`` on the agent -- indistinguishable from the provider being down, which is
    why it survived a full engagement. Verified against OpenRouter's API reference: slugs are
    ``author/model`` (``openai/gpt-4o-mini``, ``deepseek/deepseek-v3.2``).
    """
    if not model.startswith(_LITELLM_OPENROUTER_PREFIX):
        return model
    remainder = model[len(_LITELLM_OPENROUTER_PREFIX):]
    # Strip only when what is left is still an ``author/model`` slug. "openrouter/auto" is
    # OpenRouter's OWN two-part slug for the auto-router -- verified in its API reference,
    # which posts `"model": "openrouter/auto"` directly -- and it is this module's default,
    # so a blanket strip would send "auto" and break the standalone path it exists to serve.
    # LiteLLM's form of that same model is "openrouter/openrouter/auto", which still has a
    # slash after one strip and so reduces correctly.
    return remainder if "/" in remainder else model

# Snapshot JS: enumerate visible interactive elements with a stable index. The LLM refers to
# elements ONLY by this index, which is what makes its proposals checkable before execution.
_SNAPSHOT_JS = """
() => {
  const sel = 'a[href], button, input, select, textarea, [role=button], [role=combobox],'
            + ' [role=checkbox], [role=link], [role=tab], [onclick]';
  const out = [];
  const nodes = document.querySelectorAll(sel);
  for (const e of nodes) {
    const r = e.getBoundingClientRect();
    const cs = getComputedStyle(e);
    if (r.width <= 0 || r.height <= 0 || cs.visibility === 'hidden' || cs.display === 'none') continue;
    const tag = e.tagName.toLowerCase();
    const label = (e.innerText || e.getAttribute('aria-label') || e.getAttribute('placeholder')
                   || e.value || '').trim().replace(/\\s+/g, ' ').slice(0, 70);
    const rec = {
      i: out.length, tag: tag,
      type: (e.getAttribute('type') || '').toLowerCase(),
      id: e.id || '', name: e.getAttribute('name') || '',
      role: e.getAttribute('role') || '',
      label: label,
      value: String(e.value || '').slice(0, 40),
      required: e.required === true,
      disabled: e.disabled === true || e.getAttribute('aria-disabled') === 'true',
      href: tag === 'a' ? (e.getAttribute('href') || '').slice(0, 120) : undefined
    };
    if (tag === 'select') {
      rec.options = Array.from(e.options).slice(0, 15)
        .map(o => ({v: String(o.value), t: (o.textContent || '').trim().slice(0, 40)}));
    }
    out.push(rec);
  }
  return {url: location.href, title: document.title.slice(0, 120), elements: out};
}
"""

# Text that indicates the page is reporting an error, surfaced to the LLM as feedback so it can
# correct itself instead of repeating a rejected submission.
_ERROR_TEXT_JS = """
() => {
  const sel = '[role=alert], mat-error, .mat-error, .error, .error-message, .alert-danger,'
            + ' .invalid-feedback, .form-error, .field-error, .validation-error, .toast-error,'
            + ' .help-block, simple-snack-bar, .mat-mdc-snack-bar-container';
  const out = [];
  for (const e of document.querySelectorAll(sel)) {
    const t = (e.innerText || '').trim();
    if (t) out.push(t.slice(0, 160));
  }
  return out.slice(0, 8);
}
"""

_SYSTEM_PROMPT = """You drive a web browser to complete ONE goal on a page you cannot see directly.
Each turn you receive a JSON snapshot: the current URL, the page title, and a list of interactive
elements, each with an index "i". You may only refer to elements by that index.

Reply with EXACTLY one JSON object and no other text:
  {"thought": "<= 20 words", "action": "<verb>", ...}

Allowed actions:
  {"action":"fill","index":N,"value":"..."}      set a text-like input
  {"action":"select","index":N,"value":"..."}    choose a <select> option (use its "v")
  {"action":"click","index":N}                   click a button/link
  {"action":"check","index":N}                   tick a checkbox/radio
  {"action":"uncheck","index":N}
  {"action":"press","key":"Enter|Tab|Escape|ArrowDown|ArrowUp|Space"}
  {"action":"goto","url":"..."}                  same-host navigation only
  {"action":"done","success":true|false,"note":"..."}

Rules:
- One action per turn. Never emit a list of actions.
- A <select> MUST use "select", never "fill" — filling a select does nothing.
- Typed inputs need type-appropriate values: type=date wants YYYY-MM-DD, type=number wants digits,
  type=tel wants a phone number, type=email wants an email address.
- Fill EVERY field marked required before submitting. A form submitted with a required field empty
  will be rejected by the page and you will be told so.
- The submit control is often a plain <button type="button"> with the handler bound in JavaScript.
  Do not assume type=submit; click whatever element is labelled as submit.
- If the page reports an error, read it and fix the cause rather than resubmitting unchanged.
- Some values are FIXED (use them exactly). Others are ADAPTABLE suggestions you MAY change.
  If the app rejects an adaptable value (e.g. "password is not a valid input"), do NOT resubmit
  the same value — fill that field with a DIFFERENT value likely to satisfy the app, and vary it
  across attempts (try 12-16 chars mixing upper/lower/digits/symbols; if still rejected, try a
  longer value, then one without special symbols). Never retype a value the app just rejected.
- Placeholder dots like "●●●●●●●●" are a hint, not the field's current value.
- Call "done" as soon as the goal is achieved or is clearly impossible. Do not loop.
"""


@dataclass
class AgentStep:
    """One proposal/execution pair, kept so a failed run is diagnosable."""

    index: int
    thought: str = ""
    action: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    ok: bool = False
    error: str = ""
    url_before: str = ""
    url_after: str = ""
    redact: bool = False  # True when params carry a secret (e.g. a password fill) to redact


@dataclass
class AgentResult:
    """Outcome of an agent run."""

    success: bool = False
    note: str = ""
    steps: List[AgentStep] = field(default_factory=list)
    final_url: str = ""
    stopped_reason: str = ""
    llm_calls: int = 0
    # Values the agent settled on for adaptable fields (e.g. a password it had to change to
    # satisfy the app). Kept OFF as_dict() so the secret never reaches the emitted artifact.
    credentials: Dict[str, str] = field(default_factory=dict)
    #: Everything the application stated about its own input during this run. Carried out
    #: so a later attempt starts where this one finished rather than from nothing.
    stated_rules: List[str] = field(default_factory=list)

    @staticmethod
    def _safe_params(step: "AgentStep") -> Dict[str, Any]:
        if step.redact and "value" in step.params:
            return {**step.params, "value": "***"}
        return step.params

    def as_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "note": self.note,
            "final_url": self.final_url,
            "stopped_reason": self.stopped_reason,
            "llm_calls": self.llm_calls,
            "steps": [
                {"i": s.index, "action": s.action, "params": self._safe_params(s), "ok": s.ok,
                 "error": s.error, "thought": s.thought}
                for s in self.steps
            ],
        }


# --------------------------------------------------------------------- LLM plumbing
class LLM:
    """Minimal chat access: framework ModelRouter when importable, else direct OpenRouter."""

    def __init__(self, model: Optional[str] = None) -> None:
        self.model = model or os.environ.get("BROWSER_AGENT_MODEL") \
            or os.environ.get("MODEL_TIER_FRONTIER") or "openrouter/auto"
        self.backend = "direct-openrouter"
        self._router: Any = None
        self._api_key = os.environ.get("OPENROUTER_API_KEY", "")
        try:
            import sys
            if _FRAMEWORK_ROOT and _FRAMEWORK_ROOT not in sys.path:
                sys.path.insert(0, _FRAMEWORK_ROOT)
            from config.settings import get_settings       # type: ignore
            from core.context.model_router import ModelRouter  # type: ignore
            self._router = ModelRouter(get_settings().llm)
            self.backend = "framework-router"
        except Exception:  # noqa: BLE001 - standalone skill use is supported
            self._router = None

    async def ask(self, system: str, user: str) -> str:
        """Return the model's text reply, or raise RuntimeError naming every transport tried.

        An empty completion is retried on the SAME transport rather than answered by
        switching to another one. Silently changing provider path mid-run cost this skill an
        engagement: the router returned empty content, control fell through to the direct
        call, and the direct call had been posting a model name the API rejects -- so an
        ordinary empty completion presented as a hard provider failure, and the agent died
        holding an account it had already created.

        The direct path stays, because the skill is supported standalone without the
        framework, but it is now the last resort it was documented to be rather than the
        first thing an empty string reaches.
        """
        attempts: list[str] = []
        if self._router is not None:
            for attempt in range(1, _LLM_ATTEMPTS + 1):
                try:
                    resp = await self._router.route_call(
                        tier="frontier", task_type="browser_agent", prompt=user, system=system)
                    # ModelRouter.route_call returns the model text under "content"; the
                    # other keys are kept for the direct-call/standalone shapes.
                    text = resp.get("content") or resp.get("completion") or resp.get("text")
                    if text:
                        return str(text)
                    attempts.append(f"router attempt {attempt}: empty completion")
                except Exception as exc:  # noqa: BLE001 - recorded, then retried
                    attempts.append(f"router attempt {attempt}: {type(exc).__name__}: {exc}")
                if attempt < _LLM_ATTEMPTS:
                    await asyncio.sleep(min(2.0 * attempt, 5.0))
        if not self._api_key or httpx is None:
            raise RuntimeError(
                "no LLM available: framework router unusable and OPENROUTER_API_KEY unset"
                + (f" [{'; '.join(attempts)}]" if attempts else ""))
        try:
            async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
                response = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    # Translated, not passed through: see openrouter_slug.
                    json={"model": openrouter_slug(self.model),
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user}]},
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001 - re-raised with what the router also said
            attempts.append(f"direct openrouter: {type(exc).__name__}: {exc}")
            raise RuntimeError("; ".join(attempts)) from exc
        return str(payload["choices"][0]["message"]["content"])


def _parse_proposal(text: str) -> Dict[str, Any]:
    """Extract the single JSON object the model returned, tolerating prose and code fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else {}
    except ValueError:
        pass
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group(0))
            return obj if isinstance(obj, dict) else {}
        except ValueError:
            return {}
    return {}


# --------------------------------------------------------------------- the agent
class BrowserAgent:
    """Drives one Playwright page toward a goal, with the LLM proposing and code permitting."""

    def __init__(
        self,
        page: Any,
        goal: str,
        *,
        facts: Optional[Dict[str, str]] = None,
        adaptable: Optional[Dict[str, str]] = None,
        prior_rules: Optional[List[str]] = None,
        in_scope: Optional[Callable[[str], bool]] = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        llm: Optional[LLM] = None,
        goal_reached: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.page = page
        self.goal = goal
        # Values the LLM MUST use verbatim (e.g. the email, which is tied to the inbox we poll
        # for verification). Kept under code control so the account is one the caller can use.
        self.facts = dict(facts or {})
        # Suggested starting values the LLM MAY change to satisfy the app (e.g. a password when
        # the app's policy rejects the suggestion). The value the agent settles on is captured in
        # ``result.credentials`` for downstream use.
        self.adaptable = dict(adaptable or {})
        # Every distinct thing the application has said about its own input, across
        # the whole run. Without this the agent reads one rejection, reacts, and
        # forgets: measured live, twenty-four LLM calls cycling between "password
        # rejected" and "mobile number already exists", re-learning each constraint
        # every time it reappeared and converging on nothing.
        # Seeded from earlier attempts. A constraint the application stated during
        # signup is still true at login, and this agent would otherwise rediscover it.
        self.stated_rules: List[str] = list(prior_rules or [])
        self.in_scope = in_scope or (lambda host: True)
        self.max_steps = max(1, max_steps)
        self.llm = llm or LLM()
        # An OUT-OF-BAND check that the goal is already met — typically the network
        # saying the request succeeded. Without it the agent can only judge success from
        # what it can see, and once a confirmation dialog covers the control it was
        # clicking, every further click times out: it cannot distinguish 'succeeded and
        # now obstructed' from 'never succeeded', and spends its entire budget finding
        # out. Consulted before each step so the loop stops as soon as the goal is met.
        self.goal_reached = goal_reached
        self.result = AgentResult()

    def _goal_already_reached(self) -> bool:
        """Return True when an out-of-band signal says the goal is met. Never raises."""
        if self.goal_reached is None:
            return False
        try:
            return bool(self.goal_reached())
        except Exception:  # noqa: BLE001 - a broken probe must not end a run
            return False

    # -- snapshot ------------------------------------------------------------
    async def snapshot(self) -> Dict[str, Any]:
        """Build the element index the LLM is allowed to refer to."""
        try:
            data = await self.page.evaluate(_SNAPSHOT_JS)
        except Exception as exc:  # noqa: BLE001
            return {"url": getattr(self.page, "url", ""), "title": "",
                    "elements": [], "snapshot_error": repr(exc)}
        if not isinstance(data, dict):
            return {"url": "", "title": "", "elements": []}
        data.setdefault("elements", [])
        return data

    async def _page_errors(self) -> List[str]:
        try:
            found = await self.page.evaluate(_ERROR_TEXT_JS)
        except Exception:  # noqa: BLE001
            return []
        return [str(f) for f in found] if isinstance(found, list) else []

    def _remember(self, errors: List[str]) -> None:
        """Accumulate distinct statements the application has made about its input.

        Kept verbatim and deduplicated. The application's own words about its own rules
        are the most reliable sentences available, and a paraphrase loses exactly the
        detail that makes one actionable.
        """
        for error in errors:
            text = str(error).strip()
            if 3 <= len(text) <= 200 and text not in self.stated_rules:
                self.stated_rules.append(text)
        del self.stated_rules[:-_MAX_STATED_RULES]

    def _prompt(self, snap: Dict[str, Any], errors: List[str], last: Optional[AgentStep]) -> str:
        parts = [f"GOAL: {self.goal}"]
        if self.facts:
            parts.append("FIXED VALUES — use these EXACTLY where the corresponding field appears: "
                         + json.dumps(self.facts))
        if self.adaptable:
            parts.append("ADAPTABLE VALUES — start with these, but change any the app rejects to "
                         "meet its rules: " + json.dumps(self.adaptable))
        parts.append(f"CURRENT URL: {snap.get('url')}")
        parts.append(f"PAGE TITLE: {snap.get('title')}")
        if errors:
            parts.append("THE PAGE IS CURRENTLY REPORTING: " + json.dumps(errors))
        history = [r for r in self.stated_rules if r not in errors]
        if history:
            # What the app has already told us, so a constraint is learned once rather
            # than rediscovered every time it fires.
            parts.append(
                "CONSTRAINTS THIS APPLICATION HAS ALREADY STATED (do not violate these "
                "again; a value it rejected once will be rejected again): "
                + json.dumps(history)
            )
        if last is not None and not last.ok:
            parts.append(f"YOUR LAST ACTION WAS REJECTED: {last.action} "
                         f"{json.dumps(last.params)} -> {last.error}. Do something different.")
        elif last is not None:
            parts.append(f"YOUR LAST ACTION SUCCEEDED: {last.action} {json.dumps(last.params)}")
        elements = snap.get("elements") or []
        parts.append(f"INTERACTIVE ELEMENTS ({len(elements)}):")
        parts.append(json.dumps(elements)[:14000])
        parts.append("Reply with exactly one JSON action object.")
        return "\n".join(parts)

    # -- validation (deterministic) ------------------------------------------
    def _validate(self, proposal: Dict[str, Any], snap: Dict[str, Any]) -> str:
        """Return '' if the proposal may run, else the reason it is refused."""
        action = str(proposal.get("action") or "").strip().lower()
        if action not in ALLOWED_ACTIONS:
            return f"action {action!r} is not in the allowlist {sorted(ALLOWED_ACTIONS)}"
        elements = snap.get("elements") or []
        if action == "done":
            return ""
        if action == "goto":
            url = str(proposal.get("url") or "").strip()
            if not url:
                return "goto requires a url"
            host = _host_of(url)
            if not self.in_scope(host):
                return f"navigation to host {host!r} is out of scope"
            return ""
        if action == "press":
            key = str(proposal.get("key") or "")
            if key not in ALLOWED_KEYS:
                return f"key {key!r} is not permitted"
            return ""
        # index-addressed actions
        raw = proposal.get("index")
        try:
            index = int(raw)
        except (TypeError, ValueError):
            return f"{action} requires an integer index, got {raw!r}"
        if not 0 <= index < len(elements):
            return f"index {index} is out of range (0..{len(elements) - 1})"
        element = elements[index]
        if element.get("disabled"):
            return f"element {index} is disabled"
        if action == "fill" and not isinstance(proposal.get("value"), str):
            return "fill requires a string value"
        if action in ("fill", "select") and element.get("tag") == "select" and action == "fill":
            return "element is a <select>; use action=select with an option value"
        if action in ("check", "uncheck") and element.get("tag") not in (
                "input", "button") and not element.get("role"):
            return f"element {index} is not checkable"
        return ""

    # -- execution -----------------------------------------------------------
    async def _execute(self, proposal: Dict[str, Any], snap: Dict[str, Any]) -> None:
        """Run a validated action. Raises on failure; the caller records it."""
        action = str(proposal["action"]).lower()
        elements = snap.get("elements") or []
        if action == "done":
            return
        if action == "goto":
            await self.page.goto(str(proposal["url"]), wait_until="domcontentloaded",
                                 timeout=45000)
            return
        if action == "press":
            await self.page.keyboard.press(str(proposal["key"]))
            return
        index = int(proposal["index"])
        # Re-resolve by position among currently-visible interactive elements. The snapshot index
        # is only valid for this step; a stale index is refused rather than guessed at.
        handle = await self._resolve(index)
        if handle is None:
            raise RuntimeError(f"element {index} is no longer present on the page")
        if action == "fill":
            await handle.fill(str(proposal["value"]), timeout=8000)
        elif action == "select":
            await handle.select_option(value=str(proposal["value"]), timeout=8000)
        elif action == "check":
            await handle.check(timeout=8000)
        elif action == "uncheck":
            await handle.uncheck(timeout=8000)
        elif action == "click":
            await handle.click(timeout=8000)
        else:  # pragma: no cover - guarded by the allowlist
            raise RuntimeError(f"unhandled action {action!r}")

    async def _resolve(self, index: int) -> Any:
        """Return an ElementHandle for snapshot index ``index``, or None if it moved away."""
        js = """
        (target) => {
          const sel = 'a[href], button, input, select, textarea, [role=button], [role=combobox],'
                    + ' [role=checkbox], [role=link], [role=tab], [onclick]';
          let n = 0;
          for (const e of document.querySelectorAll(sel)) {
            const r = e.getBoundingClientRect();
            const cs = getComputedStyle(e);
            if (r.width <= 0 || r.height <= 0 || cs.visibility === 'hidden'
                || cs.display === 'none') continue;
            if (n === target) return e;
            n += 1;
          }
          return null;
        }
        """
        return await self.page.evaluate_handle(js, index)

    # -- main loop -----------------------------------------------------------
    async def run(self) -> AgentResult:
        """Snapshot -> propose -> validate -> execute, until done or the step budget runs out."""
        last: Optional[AgentStep] = None
        consecutive_llm_failures = 0
        for step_no in range(self.max_steps):
            if self._goal_already_reached():
                self.result.success = True
                self.result.stopped_reason = "goal_confirmed_out_of_band"
                return self._finish(await self.snapshot())
            snap = await self.snapshot()
            errors = await self._page_errors()
            self._remember(errors)
            prompt = self._prompt(snap, errors, last)
            try:
                reply = await self.llm.ask(_SYSTEM_PROMPT, prompt)
            except Exception as exc:  # noqa: BLE001
                # A step error, not the end of the run. The loop below already treats an
                # unparseable reply this way, and an unparseable reply is the worse signal
                # of the two -- there the model answered and answered wrongly. Ending the
                # whole agent on one transport hiccup threw away a created account at step
                # 9 of 25. A sustained outage still stops it, a few lines down.
                consecutive_llm_failures += 1
                step = AgentStep(index=step_no, thought="", action="",
                                 url_before=str(snap.get("url") or ""))
                step.error = f"llm_error: {exc}"
                self.result.steps.append(step)
                last = step
                if consecutive_llm_failures >= _MAX_CONSECUTIVE_LLM_FAILURES:
                    self.result.stopped_reason = (
                        f"llm_unavailable after {consecutive_llm_failures} "
                        f"consecutive failures: {exc}"
                    )
                    return self._finish(snap)
                continue
            consecutive_llm_failures = 0
            self.result.llm_calls += 1
            proposal = _parse_proposal(reply)
            step = AgentStep(index=step_no,
                             thought=str(proposal.get("thought") or "")[:200],
                             action=str(proposal.get("action") or "").lower(),
                             url_before=str(snap.get("url") or ""))
            if not proposal:
                step.error = f"model returned no parseable JSON action: {reply[:200]!r}"
                self.result.steps.append(step)
                last = step
                continue
            step.params = {k: v for k, v in proposal.items()
                           if k not in ("thought", "action")}
            reason = self._validate(proposal, snap)
            if reason:
                step.error = reason          # refused by code, not by the model
                self.result.steps.append(step)
                last = step
                continue
            if step.action == "done":
                step.ok = True
                self.result.success = bool(proposal.get("success"))
                self.result.note = str(proposal.get("note") or "")[:400]
                self.result.stopped_reason = "model_called_done"
                self.result.steps.append(step)
                return self._finish(snap)
            try:
                await self._execute(proposal, snap)
                step.ok = True
                # Capture the value the agent settled on for an adaptable password field, and
                # mark the step so the secret is redacted from the emitted trace.
                if step.action == "fill":
                    element = (snap.get("elements") or [])[int(proposal["index"])]
                    if element.get("type") == "password":
                        self.result.credentials["password"] = str(proposal.get("value") or "")
                        step.redact = True
            except Exception as exc:  # noqa: BLE001
                step.error = f"{type(exc).__name__}: {str(exc)[:200]}"
            try:
                await self.page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:  # noqa: BLE001
                pass
            step.url_after = str(getattr(self.page, "url", "") or "")
            self.result.steps.append(step)
            last = step
        if self._goal_already_reached():
            self.result.success = True
            self.result.stopped_reason = "goal_confirmed_out_of_band"
            return self._finish(await self.snapshot())
        self.result.stopped_reason = f"step_budget_exhausted({self.max_steps})"
        return self._finish(await self.snapshot())

    def _finish(self, snap: Dict[str, Any]) -> AgentResult:
        self.result.final_url = str(snap.get("url") or getattr(self.page, "url", "") or "")
        self.result.stated_rules = list(self.stated_rules)
        return self.result


def _host_of(url: str) -> str:
    """Lowercase host of a URL, or '' if it does not parse."""
    try:
        from urllib.parse import urlsplit
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
