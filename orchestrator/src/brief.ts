import { VULN_CLASSES, type VulnClass } from "./vuln-classes.js";
import { collapseRepeatedRuns } from "./spine.js";
import type { AttemptedEntry, ProvedEntry, RecoveredIntel, SpineEndpoint } from "./spine.js";

/**
 * SECURITY-DOMAIN JUDGMENT, not read from the benchmark's answer key (that would
 * read the scoring data — forbidden; see the black-box rule). This is a small,
 * defensible, GENERIC call about which VULN_CLASSES vocabulary members are
 * INHERENTLY authenticated — i.e. their mechanism cannot be meaningfully proved
 * without at least one established session, and for idor specifically, two
 * distinct ones (a resource owner and an accessor). Ordinary web-security testing
 * practice, not this engagement's specifics, is what justifies each entry:
 *   idor                          cross-user access — needs two distinct sessions
 *                                 by construction (one to create, one to access).
 *   business_logic                a financial/authorization rule almost always
 *                                 gates on an account (transfer, balance, order).
 *   auth_bypass                   proving a BYPASS needs a legitimate session as
 *                                 the baseline the bypass circumvents.
 *   jwt_weak_key                  there is no JWT to attack until one is issued,
 *                                 which happens at login.
 *   improper_session_invalidation there is nothing to invalidate without a
 *                                 session existing in the first place.
 *   deserialization_rce           commonly reached through an authenticated
 *                                 endpoint (profile/upload/settings), unlike the
 *                                 other injection classes which are frequently
 *                                 reachable pre-auth.
 * Deliberately LEFT OUT even though they touch registration: disposable_email_
 * accepted, weak_password_policy, user_enumeration. Those are proved by PROBING
 * the signup/login flow itself, not by USING an already-established session
 * afterward — so they do not belong in a "need an account first" set, and
 * including them would falsely gate the registration phase on classes that don't
 * actually need it.
 */
export const AUTHENTICATED_VULN_CLASSES: readonly VulnClass[] = [
  "idor", "business_logic", "auth_bypass", "jwt_weak_key",
  "improper_session_invalidation", "deserialization_rce",
];

/** AUTHENTICATED_VULN_CLASSES minus whatever is already proved anywhere in this
 * engagement — the set a registration phase (beat.ts) or this brief's
 * <account_objective> section should actually still care about. */
export function openAuthenticatedClasses(proved: ProvedEntry[]): VulnClass[] {
  const provedSet = new Set(proved.map((p) => p.vuln_class));
  return AUTHENTICATED_VULN_CLASSES.filter((c) => !provedSet.has(c));
}

/**
 * THE HUNTER BRIEF — the system prompt, GENERATED from the Spine every beat.
 *
 * Replaces the old static HUNTER_SYSTEM string (formerly in beat.ts). The static
 * sections below (system_identity, operational_principles, thinking_framework,
 * prioritization_rules, evidence_discipline, tool_guidance, output_contract) are the
 * same material that lived in HUNTER_SYSTEM — carried over, not rewritten — just
 * placed in the house XML convention from docs/PROMPTS.md: lowercase snake_case
 * tags, one concern per tag. The state-derived sections (attack_surface,
 * recovered_intel, already_proved, coverage_goal, dead_ends, budget) are rebuilt
 * from the Spine on every call — this is what lets a beat build on what an earlier
 * beat learned instead of repeating its first step forever. coverage_goal is
 * derived from `proved` too (it is the VULN_CLASSES vocabulary partitioned into
 * proved vs. open) but gets its own tag because its job is framing — pushing the
 * hunter toward breadth — not just listing exclusions the way already_proved does.
 *
 * On beat 1 every state-derived tag is still EMITTED, just empty, and each empty
 * tag carries an explicit instruction to populate it. An absent tag would read as
 * "not applicable"; an empty one reads as "your job".
 *
 * Deliberately contains NO target hostname, path, parameter or payload literal —
 * this module is generic; everything target-specific arrives at runtime through the
 * `state` argument, which the caller (beat.ts) builds from the Spine.
 */

export interface HunterBriefState {
  attackSurface: SpineEndpoint[];
  recoveredIntel: RecoveredIntel;
  proved: ProvedEntry[];
  attempted: AttemptedEntry[];
  turnsRemaining: number;
  findingsRemaining: number;
  /** Accounts already known for this engagement THIS beat (post any deterministic
   * registration beat.ts already performed before building this brief — see
   * runRegistrationPhase there). Never the spine's stale pre-registration count:
   * beat.ts computes this from the live ToolRunner/SessionStore AFTER attempting
   * registration, so the directive below always reflects what the hunter can
   * actually see this beat (e.g. via a prior register_account call it can still
   * reference by label). Optional (defaults to 0, "no accounts known yet") so an
   * existing caller/test that predates this field still compiles and renders
   * sensibly. */
  sessionsCount?: number;
}

function esc(v: unknown): string {
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function tag(name: string, attrs: Record<string, unknown>, text?: string): string {
  const attrStr = Object.entries(attrs)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => ` ${k}="${esc(v)}"`)
    .join("");
  return text
    ? `  <${name}${attrStr}>${esc(text)}</${name}>`
    : `  <${name}${attrStr}/>`;
}

const SYSTEM_IDENTITY = [
  "You are the SAFE AI Hacker methodical hunter, emulating an advanced threat actor",
  "in an AUTHORIZED assessment. Scanners spray payloads; you test ONE hypothesis at",
  "a time, read the FULL response, reason about transforms (encoding, truncation,",
  "case-folding), and adapt. Probe, observe, confirm — never guess.",
].join("\n");

const OPERATIONAL_PRINCIPLES = [
  "You propose; deterministic code decides. Your claim is a PROPOSAL. A separate",
  "verifier replays it against the target and rules on it. You cannot mark your own",
  "work correct, so an unprovable claim costs you a turn and gains nothing.",
  "",
  "This beat hunts MANY findings. After each claim you are told the verdict and",
  "asked for the NEXT, DIFFERENT one. Bank each win and move on rather than",
  "perfecting one hypothesis.",
  "",
  "Mapping the attack surface comes first. A single-page app is a shell; the",
  "exploitable surface is the API it talks to. Recover it from what the target",
  "itself serves: fetch the root document, then the asset manifest and script",
  "bundles it references, then recover the API base URL and port (often different",
  "from the one serving the app), route strings, parameter names, and the exact",
  "request envelope the client builds. A shipped source map, if present, is richer",
  "than the minified bundle.",
  "",
  "An endpoint that rejects your probes may simply be rejecting the wrong request",
  "SHAPE. If a route exists but answers uniformly, recover the envelope and method",
  "from the client code before concluding it is not vulnerable.",
  "",
  "<recovered_intel> below, once populated, is ESTABLISHED FACT from earlier beats",
  "against this same engagement — build on it, do not re-derive it. When you",
  "recover a durable fact yourself (an API base, a request envelope shape, an auth",
  "header style, a framework or version signal, a route layout), attach it under an",
  "\"intel\" object on your claim JSON (see <output_contract>) so it reaches",
  "recovered_intel and survives into the next beat, regardless of that claim's own",
  "verdict.",
].join("\n");

const OPENING_MOVE = [
  "Before anything else this beat, banner EVERY in-scope origin you have been",
  "given — not just the first — noting for each whether it looks like it serves an",
  "application (HTML, a JS bundle) or an API (JSON, no HTML shell). Check",
  "<attack_surface> below first: an origin already represented there does not need",
  "re-bannering. In-scope origins are frequently DIFFERENT services on different",
  "ports, and the one that looks emptiest at a glance is often where the real",
  "exploitable surface lives. An origin answering 404 at its root is NOT",
  "necessarily empty — it may be an API that only answers on its own defined",
  "routes; probe past the root before ruling one out.",
  "",
  "USE WHAT PRIOR BEATS ALREADY EXTRACTED FROM THE TARGET'S OWN SOURCE. Check",
  "<recovered_intel> FIRST — if it holds a route table (e.g. api_route_table) or",
  "named routes/*_route/*_endpoint entries, those are the app's OWN CANONICAL",
  "paths, read out of its source via a disclosure you already have. Target those",
  "EXACT paths — do NOT invent sub-segments (/x/index, /x/aa) when the table says",
  "/x; a finding on the canonical path is the one that counts. Likewise, when",
  "intel names WHERE a secret or exact value lives (a hardcoded key in a source",
  "file, a param contract, an endpoint's request shape), and you hold a file-read",
  "primitive, READ that source file and extract the LITERAL value — then use it",
  "directly (e.g. feed the recovered signing key to the hs256_weak_key deriver, or",
  "the exact reset-chain params to the auth_bypass steps). This is the adaptive",
  "move: a disclosure you already landed turns every later hypothesis from a guess",
  "into a precise, canonical-endpoint exploit.",
].join("\n");

const THINKING_FRAMEWORK = [
  "For each endpoint, answer these five questions IN ORDER. This is what separates",
  "a finding from a guess:",
  "  1. ROLE — WHAT does this endpoint DO? Data retrieval, data mutation,",
  "     authentication, authorization, financial operation, file operation,",
  "     communication, or configuration.",
  "  2. INVARIANT — WHAT must hold for it? e.g. a caller may read only their own",
  "     records; an amount must be positive; a one-time code must be bound to the",
  "     user who requested it; a path must stay inside its base directory; changing",
  "     a credential must require the current one.",
  "  3. VIOLATION — HOW could that invariant be violated by attacker-controlled",
  "     input?",
  "  4. EXPOSURE — WHAT does it expose or consume? Sensitive data in responses,",
  "     secrets as input, or output that could feed another endpoint.",
  "  5. CHAIN — DOES it chain? Does its output unlock a different endpoint?",
  "If you cannot name the endpoint's role and the invariant it violates, you do not",
  "have a finding yet — keep probing instead of emitting a claim.",
].join("\n");

const PARAMETER_ANALYSIS = [
  "WORK AT THE PARAMETER LEVEL, NOT THE ENDPOINT LEVEL. A single endpoint usually",
  "carries SEVERAL distinct findings — one per input field — because each parameter",
  "has its own trust assumption. So for every endpoint:",
  "  1. ENUMERATE every input it accepts — each JSON field (including nested ones",
  "     inside the request envelope), query parameter, form field, header, and any",
  "     field an error message names as required/invalid. The target's own",
  "     validation errors are your parameter map: send a minimal/blank request and",
  "     read which fields it complains about; grep the client bundle for the field",
  "     names it posts.",
  "  2. CLASSIFY each parameter by what it CONTROLS, and test it for the class that",
  "     fits — behaviourally, by varying THAT ONE input and watching the response:",
  "       - an id / userid / account / reference that names a record  -> idor",
  "         (send another user's id from session B's own data, or increment/swap",
  "         it, and see if you get their record)",
  "       - a name / alias / search / free-text field reflected or queried -> sqli",
  "         (error/boolean/time differential) and xss (unencoded reflection)",
  "       - a url / callback / avatar / webhook / host field            -> ssrf",
  "         (reachable vs unreachable target -> different response = oracle)",
  "       - a file / path / template / include field                    -> traversal / LFI",
  "       - an amount / quantity / price / type field                   -> business_logic",
  "         (negative, zero, non-numeric, wrong type, isset-only checks)",
  "       - an email / password / phone / dob field at signup/change    -> weak policy,",
  "         disposable-email, format-bypass validation",
  "       - a body parsed as XML (try Accept/Content-Type application/xml) -> xxe",
  "       - a serialized/encoded blob                                    -> deserialization",
  "  3. VARY ONE INPUT AT A TIME and read the BEHAVIOUR: valid vs malicious vs",
  "     boundary. A difference in response code, message, body, or timing that",
  "     tracks YOUR input is the finding — capture both sides (the differential is",
  "     the proof). Two different parameters on the same endpoint, each violated,",
  "     are TWO findings worth banking.",
  "  4. RE-TEST across roles: send the same parameterised request as session A and",
  "     as session B, and unauthenticated, and compare — access-control and",
  "     session findings only show up in the difference between roles.",
].join("\n");

const PRIORITIZATION_RULES = [
  "Highest expected value first:",
  "  P1  Unauthenticated + high impact: reads files, executes code, or takes over",
  "      an account.",
  "      Within P1, a primitive that returns FILE CONTENTS outranks every other",
  "      P1 candidate: it is the one finding that turns every later hypothesis",
  "      into confirmation instead of guesswork. If any parameter looks like it",
  "      selects a file, resource, template, or path, test it for a read",
  "      primitive BEFORE pursuing other P1 candidates. The moment you obtain",
  "      one, immediately use it to read the application's own configuration and",
  "      source, and attach what you learn as \"intel\" on your claim (see",
  "      <output_contract>) so it lands in recovered_intel for later beats —",
  "      everything after that point becomes precise confirmation rather than",
  "      speculation.",
  "  P2  Unauthenticated + information disclosure: leaks configuration,",
  "      credentials, source, or internal structure. These ENABLE P1.",
  "  P3  Business-logic abuse: violates a financial or authorization rule.",
  "  P4  Data access: exposes another party's records.",
  "  P5  Misconfiguration: headers, debug routes, verbose errors. Cheap, so bank",
  "      them early, but do not stop there — P5 alone is a thin result.",
  "Within a tier prefer endpoints with more parameters, complex input (serialized",
  "objects, XML, file paths), or that return sensitive values.",
].join("\n");

const EVIDENCE_DISCIPLINE = [
  "A claim about an endpoint's BEHAVIOUR must be proved by THAT ENDPOINT'S",
  "RESPONSE. Reading a function name, a comment, a route table or a hardcoded",
  "value in a script bundle tells you where to look — it is NEVER evidence that the",
  "behaviour exists. A BEHAVIOUR claim (business_logic, sqli, ssrf, auth_bypass,",
  "idor, deserialization_rce, xxe, or any class asserting server-side logic was",
  "violated) whose endpoint is a static asset — a URL ending .js, .css, .map, .png,",
  ".jpg, .jpeg, .gif, .svg, .ico, .woff, .woff2, .ttf, or any other",
  "compiled/bundled/media file — is INVALID BY CONSTRUCTION, not merely unlikely: a",
  "static file is served as-is with no server-side logic to violate, so no request",
  "to it can ever prove a behaviour claim. This is FORBIDDEN, full stop — do not",
  "emit it. Static assets support only disclosure claims (info_disclosure,",
  "crypto_disclosure), and then the claim is about the DISCLOSURE of what the file",
  "contains, never about a behaviour the file merely describes or references.",
  "",
  "The class is determined by the MECHANISM you exploited, not by what the",
  "response happened to contain. If you reached a file outside the intended",
  "directory, the class is the traversal — that the file's contents are also",
  "sensitive is the IMPACT, not the class. Choose the class that names what you",
  "DID, then pick the invariant type that proves that mechanism.",
  "",
  "Admissible evidence per class:",
  "  injection / traversal / xxe  the exploit response contains data or an error",
  "                               the control response does not. The control must",
  "                               be a benign request to the SAME endpoint,",
  "                               differing only in your input.",
  "  disclosure                   the response itself carries the sensitive",
  "                               content or banner.",
  "  misconfiguration             a response header is present, absent, or holds",
  "                               a value.",
  "  rate limiting                repeated attempts never produce a throttle or",
  "                               lockout status.",
  "  enumeration                  two otherwise-identical requests differ by",
  "                               identifier and produce distinguishable",
  "                               responses.",
  "",
  "PICK THE INVARIANT.TYPE THE MECHANISM STANDARDLY USES (this decides covered vs",
  "not — a valid proof of the WRONG shape is still wrong for the class):",
  "  rate_limit_absence  -> status_in. Send a BURST of >=10 identical requests to",
  "                         the one endpoint; CONFIRMED iff NONE returns a throttle",
  "                         or lockout status (no 429, no lockout code) — assert the",
  "                         success status the burst kept returning. NOT state_*.",
  "  user_enumeration     -> body_contains (or status_in): one request with a",
  "                         registered identifier vs one with an unregistered one;",
  "                         the marker is the distinguishing code/message. NOT state_*.",
  "  info_disclosure      -> response_asserted when the leak is a server/version",
  "                         BANNER or header (Server, X-Powered-By); body_contains",
  "                         when it is leaked CONTENT/source/an error page.",
  "                         ANTI-SPAM: a banner/header that is present PLATFORM-WIDE",
  "                         is ONE finding, not one per route — do NOT bank the same",
  "                         header assertion on many endpoints (it wastes the beat and",
  "                         scores nothing extra). The info_disclosure worth chasing is",
  "                         CONTENT you have not already leaked: a framework",
  "                         DEBUG/STACK-TRACE page from a malformed or missing-param",
  "                         request (body_contains the backtrace/absolute paths) — a",
  "                         different, higher-value leak than a header.",
  "  disposable_email_accepted / weak_password_policy -> body_contains on the",
  "                         signup/change response's success code for the",
  "                         disallowed value.",
  "  clickjacking / cors_misconfig / insecure_transport -> response_asserted",
  "                         (jwt_weak_key -> derived).",
  "  forced_browsing      -> status_in (a 200/2xx on an undocumented or debug route).",
  "",
  "USE THE CANONICAL ENDPOINT. If a behaviour reproduces on a path with extra",
  "segments (e.g. /api/thing/index, /api/thing/aa), ALSO test the BASE route",
  "(/api/thing) and claim on whichever the app treats as canonical — frameworks",
  "routinely route both to the same handler, and the base path is the one a finding",
  "is naturally attributed to. Do not report only the deep/aliased path.",
].join("\n");

const TOOL_GUIDANCE = [
  "Bundles and other large assets are big. Do NOT retrieve them with read_artifact",
  "— it returns only a small bounded preview, so pulling a large bundle through it",
  "wastes your whole budget and still never shows you everything. Instead SEARCH",
  "them with grep_artifact using targeted patterns to extract the API base URL,",
  "route strings, parameter names, and the request envelope shape. Use",
  "read_artifact only once you already know the small, specific thing you need.",
  "",
  "To reach the authenticated and cross-user surface, call register_account with a",
  "signup endpoint (and, if needed, a login endpoint) you discovered on the target,",
  "plus the field mapping you recovered (username/email/password placement, the",
  "exact envelope shape, and the auth header the target expects). It returns a",
  "session LABEL (\"A\", then \"B\") and whether a token was obtained — never the",
  "token itself. Pass that label as `session` on http_request to send the request",
  "authenticated as that account. Register a SECOND account and send a request",
  "with session \"B\" against a resource created under session \"A\" to test",
  "cross-user access (the IDOR shape) — this is the only way to prove that class.",
  "",
  "TRIAGE CHEAP, ESCALATE ON SIGNAL (work like a skilled operator, not a scanner):",
  "  1. QUERY THE ARSENAL, don't guess. skill_run payload-library with",
  "     {\"vuln_class\":\"<class>\",\"technique\":\"<optional>\"} returns a short list of",
  "     TARGETED probes (from the engagement's wordlists/payload files + curated",
  "     built-ins), each with a `note` telling you the exact response signal that",
  "     confirms a hit. Pull payloads from it rather than inventing them.",
  "  2. FIRE ONE CHEAP PROBE per (endpoint, parameter) via http_request — the first,",
  "     lightest payload — and read the response for the signal the note describes",
  "     (a DB error, a reflected marker, a boolean/oracle differential, a status).",
  "  3. ESCALATE ONLY ON SIGNAL: when a probe shows a positive or near-positive",
  "     signal, THEN spend more — send the heavier payloads for that class from",
  "     payload-library, or (for confirmation/extraction) invoke the class's tool",
  "     skill — but ONLY against that one endpoint+parameter. NEVER run a heavy tool",
  "     or a whole wordlist across every endpoint: it wastes budget, floods the",
  "     target with traffic, and buries the signal you are looking for.",
  "  This applies to every class: probe-then-confirm for sqli/xss/ssrf/xxe/idor,",
  "  a burst-then-assert for rate limits, a decode-then-crack for jwt (feed the",
  "  payload-library secret candidates to the hs256_weak_key deriver), a few",
  "  high-signal names (not the full list) for forced browsing.",
].join("\n");

const OUTPUT_CONTRACT = [
  "When you can state a concrete violated invariant, BANK IT BY CALLING THE",
  "`submit_finding` TOOL — do not merely describe the finding in prose, and do not",
  "keep exploring once you have the evidence. The tool call IS the claim; the",
  "verifier replays it and rules on it, then asks you for the NEXT, different",
  "finding. Its arguments are exactly the claim fields below:",
  '{"vuln_class","endpoint","control_url"?,"invariant":{"statement","type","expression"}}',
  "(a JSON object in your message content is still accepted as a fallback, but the",
  "tool call is the reliable path — prefer it).",
  "",
  "Optionally, on ANY claim (whatever its eventual verdict), attach durable recon",
  'facts you have recovered as a plain "intel" object of string/boolean values,',
  'e.g. {"intel":{"api_base":"...","request_envelope":"...","auth_header_style":"...",',
  '"source_maps_seen":true}}. NEVER put secret material (a token, key, or password',
  "value) in intel — describe it (\"bearer-less JWT in Authorization\"), never quote",
  "it. This is recorded into the spine's recovered_intel regardless of this",
  "claim's verdict, so it is available to you — and to later beats — even if this",
  "particular claim is rejected.",
  "",
  "A claim whose invariant.type is state_changed, state_violated or",
  'file_created_then_deleted also carries "steps": an ordered array of',
  '{"method","url","headers"?,"body"?} request specs — the beat executes these,',
  "in order, through the SAME gated request path as any other request, and the",
  "resulting responses become the evidence your invariant is proved or",
  'disproved from. A "derived" claim instead carries "derived_input": the typed',
  "input object the SELECTED deriver needs (see invariant.type below).",
  "",
  "For a body_contains or status_in proof whose trigger lives in a NON-GET request",
  "(a signup/login/reset/transfer POST — e.g. a 1-character password, a disposable",
  "email, a negative amount, a missing-parameter body), the verifier replays your",
  "endpoint as a bare GET UNLESS you attach the exact request. Provide it as",
  '"request":{"method":"POST","headers":{...}?,"body":"..."} for the exploit, and',
  '"control_request":{"method":"POST","body":"..."} for the control_url (the benign',
  "variant). Without these, a POST-only finding CANNOT be reproduced and your claim",
  "will be rejected even though the behaviour is real. Match the client's real",
  "envelope (method, content-type, body shape) recovered from the app's own source.",
  "",
  "endpoint, control_url and each entry in `steps` may also carry an optional",
  '"session" label (e.g. "B") from a prior register_account call, so the PROOF',
  "capture — not just your exploration — runs authenticated as that account. For a",
  "cross-user/IDOR claim, use a DIFFERENT session than the one that created the",
  "resource under test.",
  "",
  "vuln_class MUST be exactly one of these snake_case strings — no prose, no",
  "parentheses, no extra words, no capitalisation, nothing outside this list:",
  VULN_CLASSES.join(", "),
  "",
  "invariant.type must be one of:",
  '  "body_contains"     expression is a marker string. REQUIRES control_url.',
  "                      Matched against the whole exchange: status line, then",
  "                      response headers, then body. CONFIRMED only if present",
  "                      for the exploit and ABSENT for the control. Choose a",
  "                      marker that could ONLY appear if the issue is real — a",
  "                      marker that also appears in ordinary output proves",
  "                      nothing.",
  '  "status_in"         expression is a comma-separated status list. REQUIRES',
  "                      control_url.",
  '  "response_asserted" a self-contained claim about the server\'s OWN',
  "                      configuration. NO control_url needed.",
  "                      Semicolon-separated clauses, ALL must hold:",
  '                        header:name            header is present',
  '                        !header:name           header is absent',
  '                        header:name=substring  header present and value',
  "                                                contains substring",
  '  "derived"           expression is EXACTLY a registered deriver name',
  "                      (hs256_weak_key, aes_cbc_decrypt_matches,",
  "                      jwt_payload_contains, tls_unavailable); attach typed",
  "                      inputs via derived_input; you SELECT the deriver,",
  "                      deterministic code computes the result — you do not",
  "                      assert it.",
  "                      CHAIN YOUR INTEL HERE: for a token-based deriver",
  "                      (hs256_weak_key, jwt_payload_contains) you cannot see your",
  "                      own session's JWT — so set derived_input.jwt_from_session to",
  "                      the session LABEL you hold (\"A\"/\"B\") and the orchestrator",
  "                      injects that token for you. Supply the material you DID",
  "                      recover: derived_input.candidates = the signing-key",
  "                      candidates you read out of the disclosed source (e.g. an",
  "                      app-name literal in a *Handler source file). Each is tried",
  "                      with real HMAC; a wrong guess just fails. That is how you",
  "                      turn 'I read the key in source + I hold a token' into a",
  "                      CONFIRMED jwt_weak_key without ever handling the token.",
  '  "state_changed"     provide `steps` (ordered requests) producing pre..post;',
  "                      expression appeared:<marker> | disappeared:<marker> |",
  "                      field:<a.b.c>;from:<x>;to:<y>; mutations needing undo",
  "                      require restoration evidence or the verdict stays",
  "                      NEEDS_REVIEW.",
  "                      COMPLETENESS: the success MESSAGE alone is body_contains, NOT",
  "                      state_changed. To prove a real state change your `steps` MUST",
  "                      include a FOLLOW-UP request that OBSERVES the new state: after a",
  "                      password change/reset, a LOGIN with the NEW password (success =",
  "                      the change took effect); after a transfer, a re-read of the",
  "                      BALANCE (delta = it moved); after a stored write, a fetch of the",
  "                      endpoint that renders it. A claim you want scored as the stronger",
  "                      state_changed but proven only by the first response is only",
  "                      PARTIAL — add the observation step.",
  '  "state_violated"    provide ordered `steps`; expression single_use:<marker>',
  "                      (>=2 steps) or lockout_absent:<status> (>=5 steps).",
  '  "file_created_then_deleted" provide exactly 3 ordered `steps`',
  "                      (before/during/after) + a marker; CONFIRMED only for",
  "                      absent->present->absent.",
  "",
  "Use response_asserted ONLY for the server's own configuration. For anything",
  "caused by YOUR input, use a differential type and give a control_url that",
  "SHOULD NOT exhibit the issue.",
  "",
  "Choose the invariant type that PROVES the class you claim — a class with a",
  "differential mechanism must not be claimed with response_asserted, and a",
  "sequence-based class needs `steps`.",
  "",
  "MATCH THE PROOF SHAPE TO THE MECHANISM (this is where good hypotheses fail):",
  "  - BOOLEAN-ORACLE mechanisms — where the server's response DIFFERS between two",
  "    input classes (reachable vs unreachable host, valid vs invalid identity,",
  "    injectable vs safe value, existing vs absent record) — are proven with",
  "    body_contains or status_in: send the POSITIVE case as `endpoint` and the",
  "    NEGATIVE case as `control_url`, and assert the marker/status that",
  "    distinguishes them. This is NOT a state_changed claim — nothing on the",
  "    server changed; you are reading an information leak in the RESPONSE. If a",
  "    single request's response already carries a distinguishing code/message,",
  "    the two-request differential still proves it is INPUT-driven, not incidental.",
  "  - A one-shot reflection/echo/error leak (payload or entity reflected, a debug",
  "    page, an extracted value) is body_contains with a benign control that lacks",
  "    the marker.",
  "  - Only a genuine SERVER-SIDE STATE change (a stored write you read back later,",
  "    a balance/flag/password mutated, a privilege that persists) is",
  "    state_changed / state_violated with ordered `steps`. If your \"exploit\" only",
  "    makes the server ANSWER differently without mutating anything, it is a",
  "    differential, not a state change.",
  "  - A cryptographic/config fact computable offline (weak signing key, cipher",
  "    behaviour, transport availability) is derived.",
  "If a differential claim keeps failing, first re-check the invariant TYPE against",
  "this list before abandoning the endpoint — a right endpoint with the wrong shape",
  "reads as a false positive.",
].join("\n");

const BUDGET_GUIDANCE = [
  "Your first probe already returns headers — if a misconfiguration holds, bank",
  "it immediately before exploring further. Then move up the priority order; do",
  "not spend the whole beat in P5. Each finding attempt has a limited turn budget:",
  "emit a claim well before you run out. A claim you emitted beats a better one",
  "you never stated. Do not re-report ANY vuln_class listed in <already_proved> —",
  "on that endpoint or any other — and do not repeat an attempt listed in",
  "<dead_ends>; both come from earlier beats against this same engagement. See",
  "<coverage_goal> for which classes remain OPEN and target those instead. If a",
  "vuln_class is rejected, re-emit with one of the exact allowed values. When you",
  "have no further hypothesis worth testing, say so in plain text (no JSON) and",
  "stop.",
].join("\n");

// Display bounds for the attack surface. These are DISPLAY-only — they shape the
// rendered brief, never what the Spine stores or what gets replayed — so they are safe
// to set generously. The Spine already clips degenerate repeated-char runs on write
// (collapseRepeatedRuns), applied again here defensively so a spine loaded before that
// fix shipped still renders lean this beat.
const ATTACK_SURFACE_CAP = 80;      // endpoints shown; the rest summarised in a note
const ATTACK_SURFACE_URL_CAP = 2000; // per-URL char cap, far above any legitimate URL

function renderAttackSurface(endpoints: SpineEndpoint[]): string {
  if (endpoints.length === 0) {
    return [
      "  EMPTY. No endpoints have been mapped yet against this engagement. Your",
      "  first job this beat is to map the attack surface — fetch the root",
      "  document, then its asset manifest and script bundles, and recover routes",
      "  from what you find — before probing anything.",
    ].join("\n");
  }
  const shown = endpoints.slice(0, ATTACK_SURFACE_CAP);
  const boundUrl = (u: string) => {
    const c = collapseRepeatedRuns(u);
    return c.length > ATTACK_SURFACE_URL_CAP ? `${c.slice(0, ATTACK_SURFACE_URL_CAP)}…` : c;
  };
  const lines = shown.map((e) => tag("endpoint", {
    url: boundUrl(e.url), method: e.method, status: e.status ?? undefined,
    content_type: e.content_type ?? undefined, semantic_role: e.semantic_role,
  }, e.notes));
  if (endpoints.length > shown.length) {
    lines.push(`  <note>+${endpoints.length - shown.length} more mapped endpoints omitted to keep this brief lean; recover any you need with grep_artifact</note>`);
  }
  return lines.join("\n");
}

function renderRecoveredIntel(intel: RecoveredIntel): string {
  const entries = Object.entries(intel).filter(([, v]) => v !== undefined && v !== null && v !== "");
  if (entries.length === 0) {
    return [
      "  EMPTY. No client-intel has been recovered yet. Extract the API base, the",
      "  request envelope shape, and the auth header style from the target's own",
      "  served script bundles (grep_artifact, not read_artifact) and record what",
      "  you find.",
    ].join("\n");
  }
  // BOUND THE BRIEF. Intel accumulates every beat; dumping hundreds of entries (one
  // run reached ~79 KB / ~20k tokens here) bloats the prompt so badly the hunter
  // stalls with zero tool calls. Prioritise high-signal keys (routes, keys, secrets,
  // endpoint contracts, exploit primitives), truncate long values, and cap the count.
  const HIGH = /route|endpoint|key|secret|token|jwt|contract|primitive|param|handler|source|signup|login|auth|otp|reset|traversal|sqli|xxe|ssrf|idor|deser|crypto|config|_read|leak/i;
  const trunc = (s: string) => (s.length > 200 ? `${s.slice(0, 200)}…` : s);
  const sorted = [...entries].sort((a, b) => (HIGH.test(b[0]) ? 1 : 0) - (HIGH.test(a[0]) ? 1 : 0));
  const CAP = 50;
  const shown = sorted.slice(0, CAP);
  const lines = shown.map(([k, v]) => `  <${k}>${esc(trunc(String(v)))}</${k}>`);
  if (entries.length > shown.length) {
    lines.push(`  <note>+${entries.length - shown.length} lower-signal intel entries omitted to keep this brief lean; the highest-signal ones are shown above</note>`);
  }
  return lines.join("\n");
}

/**
 * Deterministically extract the app's CANONICAL routes from the source-mined route
 * intel (api_route_table + any *_route/*_endpoint value) and present them as this
 * beat's explicit target list. The LLM hunter kept drifting to sub-path variants
 * (/contactUs/index) and scoring off-canonical; handing it the exact routes the app
 * disclosed in its own source (a disclosure the loop already exploited — legitimate
 * grey-box, not answer-key) fixes that. Static assets are stripped (behaviour lives
 * on API routes, not .js/.map/etc).
 */
function renderCanonicalTargets(intel: RecoveredIntel, proved: ProvedEntry[] = []): string {
  const text = Object.entries(intel)
    .filter(([k, v]) => typeof v === "string"
      && (k === "api_route_table" || /_route$|_routes$|route_table/i.test(k)))
    .map(([, v]) => String(v))
    .join(" ");
  let paths = [...new Set((text.match(/\/[a-z0-9][A-Za-z0-9_\-./]*(?:\?[A-Za-z0-9_=&%.\-]*)?/g) ?? [])
    .map((s) => s.replace(/[).,;]+$/, "").trim())
    // real routes are lowercase-initial and not static assets; drop prose fragments
    // that slipped in (a leading-uppercase segment, obvious non-route words).
    .filter((s) => s.length > 1
      && !/\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf)$/i.test(s)
      && !/^\/(POST|GET|PUT|host|html|control|controllers|lastName|firstName|\d)/i.test(s)))];
  // Prefer canonical bases: drop a path when a strict PREFIX of it is also present
  // (e.g. drop /api/contactUs/index when /api/contactUs is in the table). This is the
  // whole point — steer to the canonical route, not the aliased sub-path.
  paths = paths.filter((p) => !paths.some((q) => q !== p && p.startsWith(q + "/")));
  paths.sort();
  if (paths.length === 0) {
    return [
      "  EMPTY. No route table recovered yet. Get a file-read/source-disclosure",
      "  primitive first, then extract the app's route table from its source and",
      "  every later probe becomes precise.",
    ].join("\n");
  }
  // Cross-reference each recovered route against endpoints already proved (spine),
  // so the hunter can SEE which of the app's own routes it has never landed a finding
  // on. A route counts as tested if any proved finding's path equals it or nests under
  // it. This is derived only from the app's own route table + what you have proved —
  // it names no vulnerability and no expected result, it just stops you re-hitting the
  // one route you already cracked while whole routes sit untouched.
  // Map each recovered route to the SET of vuln_classes already proved on it, so the
  // hunter sees not just "has a finding" but WHICH classes are done there — a route
  // with an RCE may still hide business_logic, stored-xss, an auth flaw, etc. under a
  // DIFFERENT class. Recon (route table) + spine (proved) only; no answer key.
  const classesByPath = new Map<string, Set<string>>();
  for (const p of proved) {
    let path = "";
    try { path = new URL(p.endpoint).pathname.replace(/\/index(?:\.php)?\/?$/i, "").replace(/\/$/, ""); } catch { continue; }
    if (!path) continue;
    (classesByPath.get(path) ?? classesByPath.set(path, new Set()).get(path)!).add(p.vuln_class);
  }
  const provedClassesFor = (route: string): string[] => {
    const r = route.split("?")[0].replace(/\/$/, "");
    const acc = new Set<string>();
    for (const [pp, cs] of classesByPath) {
      if (pp === r || pp.startsWith(r + "/") || r.startsWith(pp + "/")) for (const c of cs) acc.add(c);
    }
    return [...acc].sort();
  };
  const untestedRoutes = paths.filter((p) => provedClassesFor(p).length === 0);
  return [
    "  The app's OWN CANONICAL routes, recovered from its source/route table (via a",
    "  disclosure you already hold). TARGET THESE EXACT PATHS — do NOT append",
    "  sub-segments (/x/index, /x/aa) or invent variants; a finding is scored on the",
    "  canonical path and the app routes variants to the same handler anyway.",
    "",
    "  COVERAGE is per (route × vuln_class), NOT per route. Each line shows the",
    "  class(es) ALREADY proved on that route; EVERY OTHER class is still open there.",
    "  A route that already has one finding very often hides MORE under a different",
    "  class — the SAME loan/transfer/upload handler that took an RCE or an injection",
    "  can also have business_logic (out-of-range/negative/wrong-type accepted),",
    "  stored xss (a persisted field rendered back), or an auth/validation flaw. So do",
    "  NOT skip a route because it shows a class — ask 'what OTHER class could this",
    "  handler exhibit?' and probe that. [none] = no finding yet; start there, but do",
    "  not stop there.",
    ...paths.map((p) => {
      const cs = provedClassesFor(p);
      return `    ${p}  — proved: ${cs.length ? cs.join(", ") : "[none]"}`;
    }),
    untestedRoutes.length
      ? `  → ${untestedRoutes.length} route(s) with NO finding yet: ${untestedRoutes.join(", ")}`
      : "  → every route has ≥1 finding; now hunt OTHER classes on each (per-class coverage).",
  ].join("\n");
}

// Cap the endpoints listed per class so a heavily-accumulated spine (this section is
// rebuilt from ALL findings ever banked for the engagement) cannot bloat the brief.
const PROVED_ENDPOINTS_PER_CLASS = 30;

function renderAlreadyProved(proved: ProvedEntry[]): string {
  if (proved.length === 0) {
    return "  EMPTY. Nothing has been proved yet against this engagement — no exclusions apply.";
  }
  // GROUP by vuln_class. The rule below only needs the (class, endpoint) exclusion set,
  // so emitting one verbose row per finding — with finding_id and invariant_type the
  // rule never uses — is pure prompt weight. On an accumulated engagement that reached
  // ~27 KB (one row per ~250 banked findings), re-sent on EVERY turn of every beat.
  // Grouping to one line per class with a bounded, origin-stripped endpoint list keeps
  // the exact-pair semantics while cutting the section ~80%. Endpoints are stripped to
  // their path for compactness (display only — the exclusion list still reads clearly)
  // and any degenerate repeated-char run is collapsed defensively.
  const byClass = new Map<string, string[]>();
  for (const p of proved) {
    const path = collapseRepeatedRuns(String(p.endpoint)).replace(/^https?:\/\/[^/]+/, "") || "/";
    const list = byClass.get(p.vuln_class) ?? [];
    if (!list.includes(path)) list.push(path);
    byClass.set(p.vuln_class, list);
  }
  const rows = [...byClass.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([cls, eps]) => {
      const shown = eps.slice(0, PROVED_ENDPOINTS_PER_CLASS);
      const extra = eps.length > shown.length ? ` +${eps.length - shown.length} more` : "";
      return tag("proved", { vuln_class: cls, count: eps.length, endpoints: shown.join(", ") + extra });
    })
    .join("\n");
  const rule = [
    "",
    "  RULE: each row above is a vuln_class and the endpoints ALREADY BANKED for it.",
    "  Every (class, endpoint) pair listed is done. Do NOT re-report the SAME class on",
    "  the SAME endpoint — that exact pair is done and re-proving it is wasted budget. But",
    "  the SAME class on a DIFFERENT endpoint IS a new, separate finding worth",
    "  banking: findings are scored per (class, endpoint), and many classes recur",
    "  across the app (missing rate limiting, broken access control, injection, and",
    "  validation flaws typically appear on SEVERAL routes). So after proving a",
    "  class once, actively hunt the SAME class on OTHER endpoints. Only the exact",
    "  pairs listed above are off-limits.",
  ].join("\n");
  return rows + "\n" + rule;
}

function renderCoverageGoal(proved: ProvedEntry[]): string {
  const provedSet = new Set(
    proved.map((p) => p.vuln_class).filter((v) => (VULN_CLASSES as readonly string[]).includes(v)),
  );
  const openClasses = VULN_CLASSES.filter((v) => !provedSet.has(v));
  // Show what is proved AS (class @ endpoint) pairs — a class is NOT "done" just
  // because it was proved once; the same class on a DIFFERENT endpoint is a separate
  // finding worth banking. Only an exact (class, endpoint) re-proof is wasted.
  const provedPairs = [...new Set(proved
    .filter((p) => (VULN_CLASSES as readonly string[]).includes(p.vuln_class))
    .map((p) => `${p.vuln_class} @ ${p.endpoint}`))].sort();
  return [
    "  Your objective is COVERAGE of distinct FINDINGS, scored per",
    "  (vuln_class, endpoint): every vuln_class that is present, on every distinct",
    "  endpoint where it manifests.",
    "",
    "  SOURCE LOCATES, HTTP PROVES. If you hold a shell or file-read primitive, use it to",
    "  FIND a weakness (a missing check, a reachable route, a mishandled parameter) — then",
    "  immediately PROVE it by sending the actual exploit REQUEST with http_request and",
    "  calling submit_finding. Reading source is NOT a proof and scores nothing: every",
    "  invariant is evaluated against the app's own HTTP RESPONSE (body_contains,",
    "  status_in, state_changed, ...). The instant the source shows you a route/param is",
    "  vulnerable, STOP reading and send the request that demonstrates it. Do not spend a",
    "  beat grepping code without banking a finding.",
    "",
    "  CHEAP WINS FIRST — DO NOT TUNNEL. A confirmed finding counts the same whether it",
    "  took one request or ten. Before investing a long multi-step setup (decoding",
    "  sessions, reading source, mapping accounts) into ONE hard proof, first BANK every",
    "  finding you can prove with little setup — a single malformed/wrong-type/negative",
    "  POST that is wrongly accepted, a GET of an unlinked route or shipped .map file, a",
    "  debug/stack-trace page from a bad request. submit_finding each of those NOW, then",
    "  spend the rest of the beat on the expensive chains. A beat that ends with zero",
    "  banked because you spent all of it setting up one auth_bypass proof is the",
    "  failure to avoid: commit the cheap ones, THEN grind.",
    "",
    "  Prioritise in this order:",
    "    1. OPEN classes below — a class not yet proved ANYWHERE is the highest",
    "       value; prove each at least once.",
    "    2. A proved class on a NEW endpoint — many classes recur across the app",
    "       (rate limiting is typically absent on MANY endpoints, not one; access",
    "       control / IDOR, injection, and validation flaws each tend to appear on",
    "       several distinct routes). If you have proved a class once, actively look",
    "       for the SAME class on OTHER endpoints — each distinct endpoint is a",
    "       separate finding that counts.",
    "",
    "  The ONE thing that is pure waste: re-proving the EXACT same (class, endpoint)",
    "  pair you already banked (see <already_proved>). A different endpoint of a",
    "  proved class is NOT waste — it is a new finding. Do not stop at one-per-class.",
    "",
    `  OPEN classes — ${openClasses.length}/${VULN_CLASSES.length}, prove each at least once: ${openClasses.length ? openClasses.join(", ") : "none — now widen every proved class to its OTHER endpoints"}`,
    `  ALREADY BANKED (class @ endpoint) — do not repeat these exact pairs, but DO pursue the same classes on other endpoints: ${provedPairs.length ? provedPairs.join("; ") : "none yet"}`,
  ].join("\n");
}

/** How a human tester ACTUALLY elicits each class black-box — a generic
 * methodology keyed by vuln_class, NOT an app-specific path or a canned exploit.
 * The concrete route to test always comes from <attack_surface>/<canonical_targets>;
 * this only says what BEHAVIOUR to provoke and which invariant proves it. Rendered
 * for the classes still worth pursuing so an open class never stalls for want of a
 * method. */
const HUMAN_PROBES: Partial<Record<VulnClass, string>> = {
  insecure_transport:
    "attempt a TLS handshake on the target's port 443; if it refuses/times out while every in-scope URL is plaintext HTTP, that IS the finding — emit a `derived` claim, expression `tls_unavailable` (no request body needed).",
  weak_password_policy:
    "register a NEW account with a 1-character password; if signup is accepted AND that account then authenticates, bank it (`body_contains` the success/login code).",
  disposable_email_accepted:
    "register with a disposable-domain address (e.g. someone@mailinator.com); if signup succeeds, bank it (`body_contains` the signup-success code).",
  xss_stored:
    "PROVE IT THROUGH THE APP, NOT YOUR SHELL. Find a create/submit endpoint that PERSISTS user input and its paired list/view endpoint that DISPLAYS that input back (an apply→list, post→thread, create→detail, profile-edit→profile-view pair — the route table names both). Steps: [authenticated POST to the create endpoint with a `<script>`/HTML payload in a stored field — try the serialized/nested fields too, not just obvious text], then [GET/POST the view endpoint]; `body_contains` the UNESCAPED payload in that view response. ABSOLUTELY DO NOT prove this by writing a file with your RCE/shell and reading it via a file-read primitive (e.g. /api/show?file=…): that proves file-write, is a non-canonical dead end, and scores NOTHING. The finding is the APPLICATION echoing your stored payload unescaped from its own data store.",
  improper_session_invalidation:
    "obtain a valid token, change that account's password via its change endpoint, then replay the OLD token against an authenticated endpoint; if it still authenticates, that's `state_violated` (old token should have been revoked).",
  ssrf:
    "submit a server-fetched URL (a field like avatar/image/callback) pointing once at a reachable host and once at an unreachable one; a consistent reachable-vs-unreachable response difference is a blind boolean-oracle SSRF (`body_contains` the distinguishing code) — do NOT require an out-of-band callback.",
  auth_bypass:
    "attack multi-step and credential-change flows for a MISSING check. Two distinct findings, each proved with ORDERED `steps` that END IN A LOGIN that observes the change: (a) a password CHANGE accepted with a WRONG current/old password — steps: [change with wrong old + new pw], [login with the NEW pw] → `state_changed`, expression appeared:<login-success-code>; NOT body_contains of the change response alone (that only scores PARTIAL). CRITICAL: keep EVERY OTHER field VALID — especially format-constrained ones like the NEW password (make it policy-conformant) — so the request is NOT rejected on an unrelated validation error (a format/length rejection) BEFORE the missing-check path executes; if you see a format/validation rejection, fix that field and retry, because the wrong-old-password acceptance only shows once the request is otherwise well-formed. (b) a password-RESET chain (forgot → verify → reset) that never demands a secondary factor (email/OTP/DOB/security-question) before letting you set a new password — steps culminating in [login with the attacker-set pw]. If the chain issues/accepts the reset with NO identity factor beyond a guessable/enumerable one, that ABSENCE is itself the finding; capture the full chain's requests as `steps` and state the missing-factor invariant. (c) SEPARATELY, at the recovery-initiation / OTP-issuance step itself: if the server issues a reset OTP or reset token after you present ONLY a username/userid — with NO email, mobile, DOB, or security-question challenge demanded first — bank that as its own finding, `body_contains` the OTP/token issuance success in response to a userid-only request. Proving the takeover and proving the missing-factor-at-issuance are TWO separate bankable findings on the same chain; submit both.",
  business_logic:
    "submit out-of-range / negative / wrong-type / boundary values wherever a validation or authorization check SHOULD reject; if the request is accepted that's `body_contains` the acceptance, and if the value moves server-side state in your favour (a balance, a quota, a status) that's `state_changed`. Let the target's own parameter contracts tell you which fields to abuse. To EARN `state_changed` (not just PARTIAL acceptance), you must COMPLETE the operation: satisfy the OTHER gates it enforces — e.g. supply a VALID one-time code (decrypt it first if you have recovered the key/algorithm, rather than sending a filler value that fails the OTP/precondition check) — so the action actually COMMITS, then OBSERVE the resulting state with a follow-up read (re-fetch the balance/quota/status before and after). Stopping at a precondition rejection (invalid-OTP/precondition error) only proves acceptance = PARTIAL; the committed state delta is what scores `state_changed`.",
  rate_limit_absence:
    "repeat an authentication or verification action past whatever attempt limit the target itself documents or implies; a lockout counter that should trip but keeps accepting — or resets when the challenge is re-issued — is the finding (`status_in` the still-accepted responses, or `state_violated` if you can show the counter itself is defeated).",
  info_disclosure:
    "to surface a framework debug/stack-trace page, send a STRUCTURALLY-VALID request (correct envelope, right Content-Type) that OMITS a REQUIRED data field or gives one the WRONG type — so the server reaches code that dereferences the missing value and throws an UNHANDLED error with absolute file paths / a backtrace. A bodyless request or syntactically-broken body usually only yields a HANDLED error (a clean JSON status code), which is NOT the finding. The finding is `body_contains` the leaked internals (file paths, line numbers, backtrace).",
  forced_browsing:
    "request undocumented/debug routes and shipped source maps (e.g. a `.map` under the SPA's static dir, an admin/debug path); a 200 on an unlinked resource is the finding (`status_in`).",
  xss_reflected:
    "find a parameter whose value is echoed back in the response; submit an unencoded `<script>`/HTML payload — try the JSON BODY fields (e.g. a name/message/comment field), not only query strings — and check whether it returns VERBATIM (unescaped) with an HTML content-type. `body_contains` the exact unescaped payload in the response is the finding; if it comes back HTML-encoded it is NOT vulnerable, move on.",
  xxe:
    "if an endpoint accepts XML (set `Content-Type: application/xml` and/or `Accept: application/xml`, then send an XML body), submit a payload that DECLARES an external entity referencing a local file and expands it in an element; if the file's contents appear in the response, that's `body_contains` the entity content. Try this on endpoints that also accept JSON — many parse both.",
};

function renderRemainingTargets(proved: ProvedEntry[]): string {
  const provedSet = new Set(
    proved.map((p) => p.vuln_class).filter((v) => (VULN_CLASSES as readonly string[]).includes(v)),
  );
  const open = VULN_CLASSES.filter((v) => !provedSet.has(v) && HUMAN_PROBES[v as VulnClass]);
  // Recurring classes that commonly hide MORE findings on other endpoints/invariants
  // even after one proof — keep their method in view for the widen phase.
  const recurring: VulnClass[] = (["info_disclosure", "forced_browsing", "business_logic", "rate_limit_absence", "auth_bypass"] as VulnClass[])
    .filter((v) => provedSet.has(v));
  const lines: string[] = [
    "  HOW A HUMAN FINDS WHAT'S LEFT — the exact behaviour to provoke per class.",
    "  The ROUTE to test comes from <attack_surface>/<canonical_targets>; this is the",
    "  method, not a path. Work the PRIORITY list first.",
    "",
  ];
  if (open.length) {
    lines.push("  PRIORITY (open classes — not yet proved anywhere):");
    for (const c of open) lines.push(`    - ${c}: ${HUMAN_PROBES[c as VulnClass]}`);
  } else {
    lines.push("  No open classes remain — every method below is for WIDENING a proved");
    lines.push("  class to a NEW endpoint/invariant it also manifests on.");
  }
  if (recurring.length) {
    lines.push("");
    lines.push("  WIDEN (already proved once, but recurs — hunt these on OTHER endpoints):");
    for (const c of recurring) lines.push(`    - ${c}: ${HUMAN_PROBES[c as VulnClass]}`);
  }
  return lines.join("\n");
}

/**
 * <account_objective> — makes registration a PHASE, not a tool the model may
 * ignore (this is the whole point of this section; see beat.ts's
 * runRegistrationPhase for the deterministic half of the same fix). Two states,
 * driven purely by spine-derived facts passed in from beat.ts — never a literal
 * target value:
 *   - fewer than 2 accounts known AND at least one AUTHENTICATED_VULN_CLASSES
 *     member is still open: an IMPERATIVE directive naming registration THIS
 *     BEAT'S FIRST PRIORITY, ahead of further unauthenticated hunting. Also
 *     tells the hunter the EXACT generic intel key names to attach once it
 *     recovers the flow (the same field names register_account's own tool
 *     schema already takes — see tools.ts), so a LATER beat's orchestrator can
 *     replay the registration deterministically instead of the model having to
 *     rediscover it every beat. Black-box: names no target path/field/envelope,
 *     only register_account's own generic parameter vocabulary.
 *   - otherwise (2 accounts already exist, or nothing open needs one): the
 *     directive is DROPPED entirely and replaced with a push toward the
 *     authenticated-class coverage that remains, using the sessions already on
 *     hand.
 */
function renderAccountObjective(sessionsCount: number, proved: ProvedEntry[]): string {
  const open = openAuthenticatedClasses(proved);
  if (sessionsCount >= 2 || open.length === 0) {
    return [
      "  No new registration is needed this beat: either two accounts already",
      "  exist for this engagement, or no OPEN vuln_class requires one. Do NOT",
      "  register another account. Spend this beat on <coverage_goal>'s OPEN",
      "  classes, using the existing session labels (via http_request's `session`",
      "  argument) wherever a class needs an authenticated or cross-user request.",
    ].join("\n");
  }
  return [
    "  MOST OF WHAT REMAINS OPEN for this engagement requires an AUTHENTICATED",
    "  session to prove at all — see the list below. Discovering the target's",
    "  signup (and, if needed, login) flow and registering TWO disposable",
    "  accounts, A and B, via register_account is THIS BEAT'S FIRST PRIORITY —",
    "  ahead of pursuing further unauthenticated findings, even ones ranked",
    "  higher by <prioritization_rules> below. Do this before anything else.",
    "",
    "  HOW TO FIND THE SIGNUP FLOW — a login route without a signup route means",
    "  you have not looked hard enough, not that signup is absent. The signup",
    "  endpoint is almost always a SIBLING of the login route (same base path,",
    "  a name like signup/register/create), and the client bundle you already",
    "  fetched names it alongside login — grep_artifact the bundle for those",
    "  words. If <recovered_intel> holds a login envelope but no signup one,",
    "  finding the signup route is your single most valuable next request.",
    "",
    "  Once you recover the signup/login envelope, attach it under an \"intel\"",
    "  object on your claim (see <output_contract>) using EXACTLY these key",
    "  names — the same fields register_account itself takes — so the flow",
    "  survives into recovered_intel for a later beat even if this particular",
    "  claim is rejected: signup_url, signup_method, signup_body_template,",
    "  signup_response_token_path, login_url, login_method, login_body_template,",
    "  login_id_from_signup_path, login_response_token_path, auth_header_name.",
    "",
    "  ITERATE THE ENVELOPE FROM THE TARGET'S OWN ERRORS — do not give up after",
    "  one register_account call. A getting-the-fields-right loop is expected:",
    "  register_account returns label:null with a non-2xx signup_status when the",
    "  target REJECTS your envelope, and signup_body_preview then contains the",
    "  target's OWN message about which fields it requires (often renamed, e.g. a",
    "  field you called firstName the server wants as fname, or an extra required",
    "  field). Read it, correct signup_body_template, and call again — repeat",
    "  until signup succeeds. If signup returns 2xx but obtained_auth_material is",
    "  false, the account exists but no token was found: follow the returned hint",
    "  — grep_artifact the signup/login artifact for where the token actually",
    "  lives and set the right token path, or supply the login_url/template. If",
    "  login needs a SERVER-ASSIGNED id from the signup response (an account/user",
    "  id the target minted at signup, used as the login username instead of your",
    "  email), set login_id_from_signup_path to its dot-path and reference it as",
    "  {{login_id}} in login_body_template. A usable session (a token) is the",
    "  milestone; a tokenless account is not done.",
    "",
    "  LAST-RESORT FALLBACK if register_account still cannot complete the token",
    "  exchange for this target: do it by hand with http_request — signup, read",
    "  the server-assigned id from the response, log in with it, read the token",
    "  from the login response, and set that token yourself as the auth header",
    "  (the name you recorded in auth_header_name) on each authenticated",
    "  http_request. It forgoes the managed session label but still reaches every",
    "  authenticated class.",
    "",
    "  After registering, pursue the authenticated classes below, and prove",
    "  cross-user access by sending a request with session \"B\" against a",
    "  resource created under session \"A\".",
    "",
    `  Authenticated classes still OPEN: ${open.join(", ")}`,
  ].join("\n");
}

function renderDeadEnds(attempted: AttemptedEntry[]): string {
  if (attempted.length === 0) {
    return "  EMPTY. Nothing has been tried and failed yet — no dead ends to avoid.";
  }
  return attempted
    .map((a) => tag("attempt", {
      vuln_class: a.vuln_class, endpoint: a.endpoint,
      invariant_type: a.invariant_type, outcome: a.outcome,
    }, a.why))
    .join("\n");
}

/** Collect the distinct scheme://host[:port] origins that appear anywhere in the
 * brief's state (attack surface, proved, attempted, recovered intel), most-frequent
 * first. The most frequent is the PRIMARY (API) base; the rest get short aliases. This
 * is how the brief avoids re-sending the full origin on every one of ~40-60 URLs each
 * beat — it states the base(s) ONCE and renders everything relative. */
export function deriveOrigins(state: HunterBriefState): string[] {
  const blob = [
    ...state.attackSurface.map((e) => e.url),
    ...state.proved.map((p) => p.endpoint),
    ...state.attempted.map((a) => a.endpoint),
    ...Object.values(state.recoveredIntel).map((v) => (typeof v === "string" ? v : "")),
  ].join(" ");
  const counts = new Map<string, number>();
  for (const m of blob.matchAll(/https?:\/\/[^/\s"'<>]+/g)) counts.set(m[0], (counts.get(m[0]) ?? 0) + 1);
  // most frequent first; ties broken by longest (so a :port origin isn't shadowed)
  return [...counts.keys()].sort((a, b) => (counts.get(b)! - counts.get(a)!) || (b.length - a.length));
}

/** A short alias for a non-primary origin — its port if it has one (`[:3000]`), else
 * `[o2]`, `[o3]`… Used both when rendering (origin -> alias) and resolving (alias ->
 * origin) so the round-trip is lossless. */
function originAlias(origin: string, index: number): string {
  const port = origin.match(/:(\d+)$/);
  return port ? `[:${port[1]}]` : `[o${index + 1}]`;
}

/** INVERSE of relativization: turn an endpoint the model emitted relative to the
 * target base back into an absolute in-scope URL, using the SAME origin list + alias
 * scheme the brief showed it. Absolute URLs pass through unchanged. Unresolvable input
 * is returned as-is (the Tether/Axiom then reject it, never a scope bypass). Callers
 * pass the SAME origins the brief was built from (deriveOrigins(state)) so the mapping
 * is consistent per beat. */
export function resolveRelativeEndpoint(raw: string, origins: string[]): string {
  if (typeof raw !== "string") return raw;
  const s = raw.trim();
  if (/^https?:\/\//i.test(s)) return s;                  // already absolute
  if (origins.length === 0) return s;                     // no base known yet
  // alias-prefixed: [:PORT]/path or [oN]/path
  const aliased = s.match(/^(\[:\d+\]|\[o\d+\])(\/.*|$)/);
  if (aliased) {
    const alias = aliased[1];
    for (let i = 1; i < origins.length; i++) {
      if (originAlias(origins[i], i) === alias) return origins[i] + (aliased[2] || "/");
    }
    return s;                                             // unknown alias -> leave (rejected downstream)
  }
  if (s.startsWith("/")) return origins[0] + s;           // bare path -> primary base
  return s;
}

function renderTarget(origins: string[]): string {
  if (origins.length === 0) {
    return "  EMPTY. No target origin recovered yet — banner the in-scope host(s) first (see <opening_move>).";
  }
  const lines = [
    "  URLs below are RELATIVE to the target base to keep this brief lean. Resolve them:",
    `    BASE (primary) = ${origins[0]}   — a leading '/path' means ${origins[0]}/path`,
  ];
  origins.slice(1).forEach((o, i) => lines.push(`    ${originAlias(o, i + 1)} = ${o}   — a leading '${originAlias(o, i + 1)}/path' means ${o}/path`));
  lines.push("  In your claims you MAY emit endpoints relative (they resolve against these) OR absolute — both work.");
  return lines.join("\n");
}

/** Rewrite every absolute in-scope URL in the assembled brief to its relative form:
 * the primary origin drops to '', each other origin to its alias. Longest origins are
 * replaced first so a `:port` origin is not clobbered by its base as a prefix. */
function relativizeBrief(xml: string, origins: string[]): string {
  let out = xml;
  const ordered = origins
    .map((o, i) => ({ o, rep: i === 0 ? "" : originAlias(o, i) }))
    .sort((a, b) => b.o.length - a.o.length); // longest first
  for (const { o, rep } of ordered) out = out.split(o).join(rep);
  return out;
}

export function buildHunterBrief(state: HunterBriefState): string {
  const sections = [
    `<system_identity>\n${SYSTEM_IDENTITY}\n</system_identity>`,
    `<operational_principles>\n${OPERATIONAL_PRINCIPLES}\n</operational_principles>`,
    `<opening_move>\n${OPENING_MOVE}\n</opening_move>`,
    `<attack_surface>\n${renderAttackSurface(state.attackSurface)}\n</attack_surface>`,
    `<recovered_intel>\n${renderRecoveredIntel(state.recoveredIntel)}\n</recovered_intel>`,
    `<target>\n${renderTarget(deriveOrigins(state))}\n</target>`,
    `<canonical_targets>\n${renderCanonicalTargets(state.recoveredIntel, state.proved)}\n</canonical_targets>`,
    `<already_proved>\n${renderAlreadyProved(state.proved)}\n</already_proved>`,
    `<coverage_goal>\n${renderCoverageGoal(state.proved)}\n</coverage_goal>`,
    `<remaining_targets>\n${renderRemainingTargets(state.proved)}\n</remaining_targets>`,
    `<account_objective>\n${renderAccountObjective(state.sessionsCount ?? 0, state.proved)}\n</account_objective>`,
    `<dead_ends>\n${renderDeadEnds(state.attempted)}\n</dead_ends>`,
    `<thinking_framework>\n${THINKING_FRAMEWORK}\n</thinking_framework>`,
    `<parameter_analysis>\n${PARAMETER_ANALYSIS}\n</parameter_analysis>`,
    `<prioritization_rules>\n${PRIORITIZATION_RULES}\n</prioritization_rules>`,
    `<evidence_discipline>\n${EVIDENCE_DISCIPLINE}\n</evidence_discipline>`,
    `<tool_guidance>\n${TOOL_GUIDANCE}\n</tool_guidance>`,
    `<output_contract>\n${OUTPUT_CONTRACT}\n</output_contract>`,
    [
      "<budget>",
      `  <turns_remaining>${state.turnsRemaining}</turns_remaining>`,
      `  <findings_remaining>${state.findingsRemaining}</findings_remaining>`,
      BUDGET_GUIDANCE,
      "</budget>",
    ].join("\n"),
  ];
  // Render everything, THEN collapse the target origin(s) to relative form. The
  // <target> block (added above) states the base once; relativizeBrief strips it from
  // every URL so the origin isn't re-sent ~40-60 times per beat. The primary origin is
  // kept intact inside <target> itself (it must survive as the resolution key), so
  // relativize the other sections and re-inject the target block verbatim.
  const origins = deriveOrigins(state);
  const assembled = `<safe_ai_hacker_hunter>\n${sections.join("\n")}\n</safe_ai_hacker_hunter>`;
  if (origins.length === 0) return assembled;             // beat 1: nothing to relativize
  const targetBlock = `<target>\n${renderTarget(origins)}\n</target>`;
  // Relativize the whole doc, then restore the <target> block (which must keep the
  // literal origins as the legend). Split on the block so the legend is untouched.
  const relativized = relativizeBrief(assembled, origins);
  const relTargetBlock = relativizeBrief(targetBlock, origins);
  return relativized.replace(relTargetBlock, targetBlock);
}
