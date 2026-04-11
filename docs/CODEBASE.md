# sailpoint-isc-auditor — Codebase Documentation

This document explains every file in the project: what it does, why it exists,
how it fits into the overall system, and what you should know before touching it.

Written for the engineer who built this tool and wants to own it fully.

---

## How the project fits together

Before reading individual files, here's the flow of one audit run from start to finish:

```
User runs: isc-audit run --all

cli.py          → reads args, loads config and policy pack
engine.py       → opens ISC connection, calls each module in order
  modules/mi.py   → collects machine identity data, runs MI-01 to MI-07
  modules/ih.py   → collects account/identity data, runs IH-01 to IH-06
  modules/li.py   → collects lifecycle data, runs LI-01 to LI-06
  modules/ar.py   → collects access/SOD data, runs AR-01 to AR-07
  modules/gq.py   → collects certification data, runs GQ-01 to GQ-08
  modules/cr.py   → collects source/provisioning data, runs CR-01 to CR-08
suppressions.py → marks any suppressed findings
scoring.py      → computes risk scores and tenant health score
ai/analyzer.py  → sends findings to Claude for plain-English explanation
cli.py          → prints results to terminal or writes HTML/JSON report
```

Every file in the project feeds into this pipeline. Nothing exists outside it.

---

## File index

| File | Role |
|---|---|
| `auditor/models.py` | Data types — the shape of every object in the system |
| `auditor/config.py` | Configuration — credentials and policy pack loading |
| `auditor/client.py` | ISC API client — all network calls go through here |
| `auditor/engine.py` | Orchestrator — runs the full audit pipeline |
| `auditor/scoring.py` | Scoring — computes risk scores and tenant health |
| `auditor/suppressions.py` | Suppression store — manages muted findings |
| `auditor/cli.py` | Command-line interface — what the user interacts with |
| `auditor/modules/mi.py` | Detectors — Machine & Privileged Identity (MI-01 to MI-07) |
| `auditor/modules/ih.py` | Detectors — Identity Hygiene (IH-01 to IH-06) |
| `auditor/modules/li.py` | Detectors — Lifecycle Integrity (LI-01 to LI-06) |
| `auditor/modules/ar.py` | Detectors — Access Risk (AR-01 to AR-07) |
| `auditor/modules/gq.py` | Detectors — Governance Quality (GQ-01 to GQ-08) |
| `auditor/modules/cr.py` | Detectors — Coverage & Reconciliation (CR-01 to CR-08) |
| `auditor/ai/analyzer.py` | AI layer — sends findings to Claude after detection |
| `policy_packs/default.yaml` | Default thresholds and classifications |

---

---

# `auditor/models.py`

## What it is

The type definitions for the entire project. Every object that flows through
the pipeline — findings, scores, evidence, results — is defined here.

Think of this file as the contract. Every other file speaks the language defined here.
If you change a model, every file that uses it needs to know about it.

Uses **Pydantic**, which gives you typed, validated Python objects instead of raw
dictionaries. If you pass the wrong type to a Pydantic model, it tells you immediately
rather than failing silently three steps later.

## The objects, in the order they're created during a run

### `CollectionStatus`
A label that tags every piece of collected data with how trustworthy it is:
- `FULL` — came from the real ISC API, complete data
- `PARTIAL` — real API, but known gaps (e.g. governance-group certifications can't be inspected at item level)
- `FALLBACK` — the experimental endpoint wasn't available, we used a heuristic instead
- `SKIPPED` — we didn't even try because the API scope was missing
- `FAILED` — something unexpected broke

This status travels with data all the way to the final report so you're always honest
about how confident you are in each finding.

### `CollectionResult`
Wraps every ISC API response. A collector doesn't return a raw list — it returns a
`CollectionResult` that carries:
- `data` — the actual records from ISC
- `status` — how reliable is this data? (one of the `CollectionStatus` values above)
- `warning` — if it's a fallback, what should the user know?
- `collected_at` — timestamp of when this was fetched

Every detector receives a `CollectionResult` rather than a raw list. That way it
always knows whether the data it's working with is fully reliable or approximated.

### `FindingEvidence`
The most important design decision in the project. Every finding must carry structured
evidence — not just "this thing fired" but exactly why, with supporting facts.

Fields:
- `affected_object_ids` — the ISC IDs of the objects that triggered this finding
- `affected_object_names` — human-readable names for those objects (used in reports)
- `object_type` — what kind of object: "account", "identity", "role", etc.
- `why_fired` — plain English explanation of exactly why this detector fired
- `source_data` — the raw supporting facts (e.g. `{"enabled": True, "days_inactive": 94}`)
- `recommended_fix` — what to do about it
- `confidence` — 0.0 to 1.0; lower if the data came from a heuristic fallback

Claude reads `why_fired` and `source_data` to write its explanations. It's not
inventing context — it's summarizing facts you already captured at detection time.

This is what separates a professional audit tool from a basic scanner. Every finding
can be reproduced, explained to an auditor, and challenged if wrong.

### `RiskScore`
The two-axis risk score for a single finding.

```
risk_score = impact × exploitability × governance_failure
```

All three inputs are 0.0–1.0. The `raw_score` is therefore also 0.0–1.0.
`normalized` converts it to 0–100 for display.

Computed automatically by `model_post_init` when you create the object — you never
calculate it manually. The `scoring.py` file is responsible for deciding what the
three input values should be based on the finding's evidence.

### `Suppression`
Records that a specific finding has been intentionally muted. Stores:
- which detector + object triggered it
- the reason it was suppressed
- an optional ticket reference (e.g. `JIRA-4521`)
- an optional expiry date (after which it automatically un-suppresses)

Without suppressions, every repeat run of the auditor produces the same noise for
known, accepted risks — and engineers stop reading the output. Suppressions are how
you separate "known and accepted" from "new and urgent."

### `Finding`
The core output unit of every detector. When MI-02 fires on a service account,
it creates one of these.

A finding is enriched in stages across the pipeline:
1. **Detectors** fill in: `finding_id`, `detector_id`, `family`, `title`, `severity`, `evidence`
2. **Scoring engine** adds: `risk_score`
3. **Claude analyzer** adds: `ai_explanation`, `ai_blast_radius`, `ai_remediation`, `ai_audit_note`
4. **Suppression engine** sets: `suppressed`, `suppression`

The same object is passed through and enriched at each stage. Nothing is thrown away
and rebuilt — one `Finding` object carries the full lifecycle.

### `DetectorCoverage`
Tracks what each individual detector could and couldn't see during a run. Stored
alongside findings in the `AuditResult` so the report can show a coverage summary:

```
MI-01   FULL     82 eligible, 3 affected
MI-03   FALLBACK 61 eligible, 8 affected  ← came from heuristic, reduced confidence
GQ-08   PARTIAL  12 eligible              ← governance-group API limitation
```

This is how the tool is honest about its own blind spots.

### `CoverageConfidence`
A rolled-up 0–100 score representing how much of the ISC environment this audit
could actually see. Made up of seven individual signals:
- Were critical sources connected and aggregating?
- Did entitlements have owners?
- Were machine identities visible via the API?
- Was high-risk access covered by certifications?
- etc.

This feeds directly into the tenant health score formula:
```
tenant_health = posture_score × (0.80 + 0.20 × coverage_confidence)
```

A tenant that looks healthy but has poor coverage visibility gets penalized — because
"we couldn't see enough to know" is itself a risk.

### `TenantHealthScore`
The top-level KPI. Exposes three numbers, not one:

```
Tenant Health Score:  77  (Stable)
Coverage Confidence:  60
30-Day Trend:         +5
```

Why three numbers? Because 77 with 95% confidence is genuinely strong. 77 with 42%
confidence means "this number is shaky — we couldn't see much." The single number
without the confidence context is misleading.

`FAMILY_WEIGHTS` (line 306) is where the strategic priority call lives:
- MI gets 25% — machine identity is the headline differentiator and the fastest-growing risk
- LI and AR each get 20% — terminated users and SOD violations are the highest-stakes findings
- IH gets 15% — orphans and stale accounts are important but lower acute risk
- GQ and CR each get 10% — governance quality and reconciliation are important but supporting

**Critical conditions** are a separate banner that fires regardless of the overall
score. Seven specific detectors (LI-01, LI-02, AR-01, AR-06, MI-05, CR-04, CR-05)
trigger this because their findings are dangerous enough that a 77/100 score should
never hide them. This is the "green score, red reality" prevention.

### `AuditResult`
The complete output of one full audit run. This is what the engine hands to reporters.

Contains everything needed to produce terminal output, an HTML report, or JSON:
- All findings (active and suppressed)
- Coverage metadata per detector
- The full health score breakdown
- Timestamps and metadata

The `@property` methods (`critical_count`, `total_active`, etc.) compute on the fly
from the findings list rather than storing separate counts — so they're always accurate
even if findings are modified after the fact.

## What to know before changing this file

- Changing a field name on any model requires updating every file that creates or
  reads that field — detectors, scoring, CLI, reporters
- Adding a new model is safe; removing or renaming fields is a breaking change
- Pydantic validates types on creation, so type mismatches fail loudly at runtime

---

---

# `auditor/config.py`

## What it is

The configuration layer. Handles two distinct concerns:
1. **Credentials** — how to connect to ISC and Anthropic (from environment variables)
2. **Policy** — what thresholds and classifications to use when auditing (from a YAML file)

These are intentionally kept separate because credentials are secret and per-user,
while policy packs are shareable and version-controlled.

## `PolicyPack`

Defines all the customizable thresholds and classifications that detectors use.
Loaded from a YAML file so engineers can tune the tool for their environment
without touching code.

Key settings:

**Thresholds** — these drive detector logic directly:
- `stale_account_days: 90` — IH-02 fires if an account has been inactive longer than this
- `inactivity_days: 60` — MI-03 fires if a machine identity has been dormant longer than this
- `non_employee_grace_days: 7` — LI-05 fires if a non-employee is this many days past end date
- `mover_grace_days: 30` — LI-03 fires if a mover still has pre-role-change access after this
- `peer_group_outlier_pct: 95` — AR-03 fires if an identity is above this percentile vs peers
- `certification_overdue_days: 7` — GQ-01 fires if a campaign is this many days past due
- `source_stale_days: 3` — CR-02 fires if a source hasn't aggregated in this many days

**Classifications** — these determine what counts as "privileged" or "sensitive":
- `privileged_apps` — apps where machine identity access is flagged as high-impact (MI-02)
- `sensitive_entitlements` — entitlements checked for broad population in AR-06
- `critical_sources` — sources given extra scrutiny in CR-07 and CR-02

**Naming conventions** (regex patterns):
- `service_accounts` — pattern that identifies a service account by name (e.g. `^svc[-_]`)
- `break_glass` — pattern that identifies emergency accounts (e.g. `^(bg|emergency)[-_]`)
- `shared_accounts` — pattern that identifies generic shared accounts

**Detector overrides** — lets you disable a specific detector or change its threshold
without touching code:
```yaml
detector_overrides:
  MI-06:
    enabled: false        # turn off naming convention checks for MI
  IH-02:
    stale_account_days: 60   # use 60 days instead of the default 90 for this detector
```

**Key methods:**
- `from_yaml(path)` — loads a policy pack from a YAML file
- `default()` — loads `policy_packs/default.yaml`, falls back to hardcoded defaults
- `is_detector_enabled(detector_id)` — checks whether a specific detector is enabled
- `detector_threshold(detector_id, key)` — reads a per-detector threshold override

## `AuditorConfig`

Holds runtime credentials and connection settings. Loaded from environment variables
(the `.env` file) via `from_env()`.

Required environment variables:
- `ISC_TENANT_URL` — your ISC tenant URL (e.g. `https://yourorg.identitynow.com`)
- `ISC_CLIENT_ID` — OAuth client ID from ISC API Management
- `ISC_CLIENT_SECRET` — OAuth client secret
- `ANTHROPIC_API_KEY` — your Anthropic API key

Optional tuning:
- `ISC_API_TIMEOUT` — seconds before a request times out (default: 30)
- `ISC_MAX_RETRIES` — how many times to retry transient failures (default: 3)
- `ISC_PAGE_SIZE` — records per page when paginating (default: 250)
- `AUDIT_LOG_LEVEL` — logging verbosity: INFO, DEBUG, WARNING (default: INFO)

`normalise_tenant_url` (line 107) strips trailing slashes from the URL automatically.
This prevents double-slash issues like `https://yourorg.com//v3/identities`.

`history_file` (line 103) defaults to `~/.isc-audit/history.json`. This is where
each run's score is saved for trend tracking.

## What to know before changing this file

- Never commit your `.env` file — it contains secrets. It's in `.gitignore`.
- Adding new policy pack fields requires a default value so existing YAML files
  don't break when loaded with the new field
- The policy pack is passed to every detector — any field you add here is available
  in every module via the `policy` argument

---

---

# `auditor/client.py`

## What it is

The only file that makes network calls to SailPoint ISC. Every HTTP request in
the entire project goes through this file. Nothing else calls the ISC API directly.

This is intentional. Centralizing all API calls means:
- Auth logic lives in one place
- Retry logic lives in one place
- Fallback exceptions are defined once and reused everywhere
- Pagination is handled automatically — no module has to think about it

## Custom exceptions

Five typed exceptions represent every meaningful failure mode from the ISC API:

```python
ISCAuthError           # 401 on token request — bad credentials
ISCPermissionDenied    # 403 — missing API scope
ISCEndpointUnavailable # 404/501 — experimental or tier-restricted endpoint
ISCRateLimitExceeded   # 429 — rate limited, tenacity will retry
ISCServerError         # 5xx — transient server error, tenacity will retry
```

Why type these? Because collectors need to react differently to each one.

When MI's `collect_machine_identities()` calls `client.get_machine_identities()`:
- `ISCEndpointUnavailable` → fall back to account-based heuristic detection
- `ISCPermissionDenied` → skip the detector entirely, warn the user
- `ISCRateLimitExceeded` → tenacity retries automatically
- `ISCServerError` → tenacity retries automatically

Without typed exceptions, you'd have to inspect raw HTTP status codes in every
collector — messy and error-prone.

## `_TokenCache`

A simple in-memory token cache. ISC tokens expire after 3600 seconds (1 hour).

The cache holds the current token and its expiry time. `get()` returns the cached
token if it's valid with at least 30 seconds of margin — the 30 second buffer prevents
using a token that expires mid-request. `set()` stores a new token after a successful
auth call.

Without this, every API call would trigger a new OAuth token request — wasteful and
potentially rate-limited.

## `ISCClient`

The main class. Constructed with an `AuditorConfig` and used as a context manager:

```python
with ISCClient(config) as client:
    accounts = client.get_accounts()
```

The `with` block ensures `close()` is called even if an exception occurs — important
for releasing the underlying HTTP connection pool.

**`_get_token()`** — OAuth2 client credentials flow. Checks the cache first, requests
a new token from `/oauth/token` if needed, caches it. If the token request fails with
a 401, raises `ISCAuthError` with a clear message pointing to the `.env` file.

**`_headers()`** — returns the HTTP headers needed for every API call. Always calls
`_get_token()` first, so the token is always fresh.

**`_request()`** — the core HTTP method. Decorated with `@retry` from the `tenacity`
library, which means it automatically retries on `ISCRateLimitExceeded` and
`ISCServerError` using exponential backoff (starts at 2s, maxes at 30s, tries 4 times).

Each HTTP status code maps to a specific exception or behavior:
- `200` → return the response
- `401` → clear token cache and retry once (handles mid-run token expiry)
- `403` → `ISCPermissionDenied` (not retried — it won't fix itself)
- `404/501` → `ISCEndpointUnavailable` (not retried — endpoint doesn't exist)
- `429` → sleeps for `Retry-After` seconds, then raises `ISCRateLimitExceeded` (tenacity retries)
- `5xx` → `ISCServerError` (tenacity retries)

**`get_all()`** — handles ISC's offset/limit pagination automatically. Keeps fetching
pages until it gets a page smaller than the page size (meaning it was the last one).
Also handles the slight inconsistency in ISC's API where some endpoints return a plain
list and others return `{"items": [...]}`.

**Convenience methods** — one method per ISC resource type (`get_identities`,
`get_accounts`, `get_roles`, etc.). These make collector code readable:

```python
# Clear
identities = client.get_identities()

# Versus the alternative
identities = client.get_all("/v3/identities", params={})
```

`get_machine_identities()` is the only one on a `/beta/` path — it's the experimental
endpoint that requires graceful fallback in the MI module.

## What to know before changing this file

- If ISC changes an API endpoint path, update the corresponding method here
- Never add auth logic or pagination logic in a detector module — it belongs here
- To add a new ISC resource, add a new convenience method following the existing pattern
- `get_all()` has a `max_records` parameter if you ever need to limit results during
  testing without hitting the full dataset

---

---

# `auditor/scoring.py`

## What it is

The math engine. Takes all the findings produced by detectors and computes:
1. A risk score for each individual finding
2. A score for each control family (MI, IH, LI, AR, GQ, CR)
3. A posture score (weighted average of family scores)
4. A tenant health score (posture adjusted for coverage confidence)
5. A list of critical conditions (dangerous findings that get a banner regardless of score)

No detectors live here. No API calls. Pure calculation.

## The scoring pipeline (5 steps)

### Step 1: Score each finding individually

`score_finding(finding)` computes a `RiskScore` for one finding using three factors:

**Impact** (how bad is this if exploited?) — derived directly from severity:
- CRITICAL → 1.0
- HIGH → 0.75
- MEDIUM → 0.45
- LOW → 0.20

**Exploitability** (how easy is it to exploit right now?) — starts at 0.5, increases for:
- Account is currently enabled → +0.30
- Object has privileged access → +0.20
- No MFA on the account → +0.15
- Externally reachable → +0.10

**Governance failure** (how badly did controls fail?) — starts at 0.40 (because if
a finding fired at all, some control already failed), increases for:
- No owner assigned → +0.25
- Never been reviewed → +0.20
- Deprovisioning failed → +0.20
- Drift confirmed between ISC and target system → +0.15

The final score: `impact × exploitability × governance_failure`, normalized to 0–100.

Why start `gov_failure` at 0.40? Because the detector already established that
something went wrong. 0.40 is the floor — you can't have zero governance failure
and still have a finding.

### Step 2: Compute detector-level penalty

`compute_detector_penalty()` produces a penalty score (0–100) for each detector.

```
penalty = detector_weight × normalized_exposure × avg_severity_weight × 100
```

- `detector_weight` — a hardcoded weight per detector in `DETECTOR_WEIGHTS` (1.00 for critical
  detectors like MI-01, 0.25 for informational ones like AR-07)
- `normalized_exposure` — `affected_count / eligible_count` (bounded 0–1)
  This is the key to fairness: 5 orphaned accounts in a 200-identity tenant is more serious
  than 5 in a 100,000-identity tenant
- `avg_severity_weight` — weighted by how serious the findings are

`MAX_DETECTOR_PENALTY = 40.0` means no single detector can tank the family score by
more than 40 points. Without this cap, one badly configured detector could destroy the
entire score.

### Step 3: Family scores

`compute_family_score()` starts each family at 100 and subtracts each detector's penalty.
If all detectors in a family produce zero penalty (no findings), the family scores 100.

`FAMILY_DETECTOR_MAP` defines which detectors belong to which family — this is the
source of truth for that mapping.

### Step 4: Posture score

Simple weighted sum:
```
posture_score = (MI_score × 0.25) + (LI_score × 0.20) + (AR_score × 0.20) +
                (IH_score × 0.15) + (GQ_score × 0.10) + (CR_score × 0.10)
```

The weights must sum to 1.0. If you want to rebalance priorities, this is where
you do it.

### Step 5: Apply coverage confidence

```
tenant_health = posture_score × (0.80 + 0.20 × coverage_confidence)
```

The 0.80/0.20 split was deliberate. Coverage matters — a tenant with poor visibility
can't claim a clean bill of health. But coverage doesn't completely dominate the score.

Example: posture=84, coverage_confidence=0.60:
```
tenant_health = 84 × (0.80 + 0.20 × 0.60)
              = 84 × 0.92
              = 77.3
```

That feels fair. The tenant is actually doing well — it's just not showing us everything.

## Critical conditions

`CRITICAL_CONDITION_DETECTORS` lists 7 detectors whose findings always trigger a
separate banner, regardless of the overall health score:

- `LI-01` — terminated identity with active accounts
- `LI-02` — terminated identity with privileged access
- `AR-01` — active SOD violation
- `AR-06` — sensitive access held by broad population
- `MI-05` — break-glass account with no control evidence
- `CR-04` — deprovisioning requested but not completed
- `CR-05` — revoked in ISC, still present in target system

These represent the "green score, red reality" problem. A tenant scoring 82 overall
can still have a terminated admin with active Workday and AWS access — the score
shouldn't hide that. The banner appears alongside the score, not instead of it.

## What to know before changing this file

- Changing `DETECTOR_WEIGHTS` changes which findings have the most impact on scores
- Changing `family_weights` in `compute_tenant_health()` changes strategic priority
- Adding a new detector requires adding it to `DETECTOR_WEIGHTS` and `FAMILY_DETECTOR_MAP`
- Adding a new detector to `CRITICAL_CONDITION_DETECTORS` means it will always
  trigger a banner — use this sparingly

---

---

# `auditor/suppressions.py`

## What it is

A persistent store for suppressed findings. Engineers can mark a finding as
"known and accepted" with a reason, an optional ticket reference, and an optional
expiry date. On subsequent runs, those findings are still detected but marked
suppressed rather than active.

Without this, every run of the auditor is noisy with findings you already know about
and have accepted. Engineers stop reading the output. The tool becomes useless.

Data is persisted to `~/.isc-audit/suppressions.json` — per user, on disk, survives
between runs. This is simple and portable. No database needed for v1.

## How it works

`add_suppression()` writes a record to the JSON file with:
- `detector_id` — which detector fired
- `object_id` — the specific ISC object ID being suppressed
- `reason` — why it's being suppressed (mandatory — forces documentation)
- `ticket` — optional ticket reference so you can trace back to the remediation work
- `suppressed_at` — when it was suppressed
- `expires_at` — optional expiry date (ISO8601 string)

`list_suppressions()` loads all suppressions and automatically prunes expired ones
(where `expires_at` is in the past). This is how suppressions self-clean without
anyone having to manually delete them.

`apply_suppressions(findings)` is called by the engine after detectors run. It loops
through all findings, checks each one against the active suppression list, and sets
`finding.suppressed = True` and `finding.suppression = <Suppression object>` for
any matches. The finding isn't removed — it's still in the results, just marked.
This means the report can show suppressed findings separately and explain why they
were muted.

Suppression matching is by `(detector_id, object_id)` pair. Suppressing MI-02 on
object `abc123` only suppresses that specific finding — it doesn't suppress MI-02
findings on any other object.

`load_history()` is a separate utility that reads the history file for trend tracking.
It lives here for convenience since it's similar infrastructure.

## What to know before changing this file

- The JSON file is per-user on disk. If you're running the auditor in CI or as a
  service, you'd need to change the storage location to something shared
- Suppressions match on both `detector_id` AND `object_id` — you can't blanket-suppress
  an entire detector, only specific findings from it
- Expired suppressions are cleaned up automatically on `list_suppressions()` — no
  cron job or manual cleanup needed

---

---

# `auditor/engine.py`

## What it is

The orchestrator. The engine's job is to call everything in the right order and
wire the outputs of each step into the inputs of the next.

It doesn't do any detection logic. It doesn't score anything directly. It doesn't
talk to Claude. It coordinates the pieces that do those things.

## The run order

```
1.  Open ISC connection (ISCClient)
2.  For each family (MI, IH, LI, AR, GQ, CR):
      a. Call the module's run_*_detectors() function
      b. Collect findings and coverage metadata
      c. Track eligible_count per detector (for scoring normalization)
3.  Apply suppressions to all findings
4.  Estimate coverage confidence from collection results
5.  Compute tenant health score (calls scoring.py)
6.  Run Claude AI analysis on active (non-suppressed) findings
7.  Return the populated AuditResult
```

## `should_run(family)`

A small helper that decides whether a given family should run based on the user's
CLI arguments:
- `--all` → always true for every family
- `--families MI LI` → true only for MI and LI
- `--detectors MI-01 LI-05` → true for any family that has one of the specified detectors

This is how partial runs work. You can audit just machine identity and lifecycle
without running all 25 detectors.

## `_estimate_coverage_confidence()`

Currently simplified — it uses the ratio of `FULL` vs `FALLBACK/SKIPPED` collectors
as a proxy for several of the coverage signals. The `TODO` comments mark where each
signal will be derived from real data in a later build.

This is intentional. Shipping a simplified version that works is better than waiting
for a perfect version. The formula is correct — it's the inputs that will be refined.

## The `with ISCClient(config) as client:` pattern

The engine uses ISC client as a context manager. This means:
- The HTTP connection is opened once and reused across all 6 module calls
- Even if a module throws an exception, `client.close()` is called automatically
- You don't have to think about connection lifecycle in detector code

## Module imports are deferred (inside `if should_run` blocks)

Each module is imported inside its `if should_run()` block rather than at the top
of the file. This means:
- If you run `--families MI` only, the other 5 modules are never imported
- Import errors in a module you're not using don't crash the run
- Startup time is faster for partial runs

## What to know before changing this file

- The order of module calls matters if modules share data (currently they don't —
  each module fetches its own data from ISC independently)
- `eligible_by_detector` is built here and passed to scoring — make sure every
  module's coverage output is added to this dict
- AI analysis runs after suppressions are applied — Claude only analyzes active findings,
  not suppressed ones
- If you add a new module family, add it to this file in the same pattern as the others

---

---

# `auditor/cli.py`

## What it is

The user-facing interface. What you actually run. Built with **Click** (command
definitions) and **Rich** (colorized terminal output).

## Commands

### `isc-audit run`

The main command. Flags:
- `--all` — run all 25 detectors
- `--families MI LI AR` — run specific families
- `--detectors MI-01 LI-05` — run specific detectors
- `--output terminal|html|json` — output format (default: terminal)
- `--out filename` — file path for HTML or JSON output
- `--policy-pack path.yaml` — custom policy pack
- `--no-ai` — skip Claude analysis (faster, useful for debugging detectors)
- `--verbose / -v` — enable debug logging

After the run, the CLI:
1. Prints the health score banner
2. Prints the family breakdown table
3. Prints the top 5 findings
4. Writes the output file if requested
5. Saves the run to `~/.isc-audit/history.json` for trend tracking

### `isc-audit suppress`

Mutes a specific finding. Requires `--object-id` and `--reason`. Optional `--ticket`
and `--expires` (date string: `2025-09-01`).

Example:
```bash
isc-audit suppress MI-06 \
  --object-id svc-legacy-erp \
  --reason "Legacy system migration tracked in JIRA-4521" \
  --ticket JIRA-4521 \
  --expires 2025-09-01
```

### `isc-audit suppressions list`

Shows all active (non-expired) suppressions in a table.

### `isc-audit history`

Shows the last 20 audit runs with scores, bands, and coverage confidence. This is
where the trend tracking pays off — you can see whether scores are improving over time.

## Output formatting

`_print_health_score()` — prints the health score with color coding:
- 90+ → green
- 75–89 → cyan
- 60–74 → yellow
- below 60 → red

If critical conditions are present, a red panel appears below the score listing
each one by name. The score doesn't hide them.

`_print_summary_table()` — family breakdown table with per-family score, critical count,
and high count. Color-coded the same way.

`_print_top_findings()` — top 5 active findings, sorted critical first then by risk
score. Shows detector ID, title, and affected object names.

`_save_history()` — appends the run's key metrics to `history.json`. Wrapped in a
try/except so a history write failure never crashes the run — history is nice-to-have.

## What to know before changing this file

- The health score banner and summary table print to the terminal regardless of
  `--output` flag — only the detailed report goes to a file
- `_print_top_findings()` shows at most 5 by default — change the `limit` argument
  to show more
- The `Progress` spinner from Rich is `transient=True` — it disappears when the run
  finishes, leaving a clean terminal

---

---

# `auditor/modules/mi.py`

## What it is

The Machine & Privileged Identity detector family. Seven detectors covering the
fastest-growing attack surface in enterprise identity security.

This is the headline differentiator of the tool — almost no IGA tooling addresses
machine identity governance specifically, and the market research confirms it's the
#1 emerging risk.

## The collectors

### `collect_machine_identities()`

The most important collector in the project because it has to handle the graceful
fallback pattern explicitly.

**Happy path:** calls `client.get_machine_identities()` → the `/beta/machine-identities`
endpoint → returns a `CollectionResult` with `status=FULL`.

**Fallback path:** if `ISCEndpointUnavailable` is raised (experimental endpoint not
available on this tenant tier), it falls back to `client.get_accounts()` and filters
using `_is_machine_identity()`.

`_is_machine_identity()` applies heuristics:
- Account type is `service`, `machine`, `system`, or `application`
- Account name starts with `svc-`, `svc_`, `app-`, `bot-`, `sys-`, `sa-`, or `automation-`

This is honest about its limitations — the `CollectionResult` comes back with
`status=FALLBACK` and a `warning` explaining what happened and why confidence is reduced.

**Skip path:** if `ISCPermissionDenied` is raised (missing scope), returns
`status=SKIPPED` with a clear message about which scope to add.

## The detectors

### MI-01 — Machine identity without owner
**Why it matters:** An unowned machine identity can never be reviewed, rotated, or
decommissioned. It becomes a permanent liability — valid credentials with no one
accountable for them.

**Logic:** any machine identity where `owner`, `ownerId`, and `ownerName` are all empty.

**Severity:** Critical — this is the worst possible state for a machine identity.

### MI-02 — Machine identity with privileged access
**Why it matters:** Machine identities can't use MFA. A privileged machine identity
with non-expiring credentials and no multi-factor protection is the highest-risk
object type in the environment.

**Logic:** checks assigned roles (name contains "admin", "administrator", "privileged",
"superuser", "root", "global", "owner", "manage") and direct entitlements with similar
keywords. Also flags access to any app in `policy.privileged_apps`.

**Severity:** Critical.

### MI-03 — Dormant machine identity still enabled
**Why it matters:** Dormant credentials are actively sought by attackers. A service
account that hasn't been used in 90 days but still has valid credentials is exactly
the kind of forgotten entry point that enables long-term persistent access.

**Logic:** checks `lastActivity`, `lastAuthentication`, or `lastModified` (in that order)
against `policy.inactivity_days`. Only fires on enabled identities.

**Severity:** High.

### MI-04 — Shared privileged account not tied to a person
**Why it matters:** Shared accounts violate non-repudiation. You can never know which
person performed an action — critical for incident response and compliance.

**Logic:** uses `policy.naming_conventions["shared_accounts"]` regex against account
names, then checks whether the account is correlated to an identity. Runs against all
accounts (not just machine identities) because shared accounts often aren't in the
machine identity API.

**Severity:** High. Confidence is 0.75 because pattern matching produces some false
positives.

### MI-05 — Break-glass access with no control evidence
**Why it matters:** Break-glass accounts exist for emergencies but must be tightly
controlled. An emergency account that's permanently enabled, has no owner, and has
never been reviewed is a disaster waiting to happen — and a top compliance finding.

**Logic:** matches names against `policy.naming_conventions["break_glass"]` regex.
Flags any break-glass account that has: no owner, never been reviewed, or is
permanently enabled (should be disabled by default with vaulted checkout).

**Severity:** Critical.

### MI-06 — Service account outside naming/tagging policy
**Why it matters:** Standardized naming and required attributes make machine identities
discoverable, governable, and decommissionable. Without standards, you end up with
hundreds of one-off service accounts that nobody can inventory.

**Logic:** checks for missing attributes (`description`, `environment`, `criticality`)
and validates the name against `policy.naming_conventions["service_accounts"]`.

**Severity:** Medium — this is a hygiene issue, not an acute risk.

### MI-07 — Machine identity created but never reviewed
**Why it matters:** Unreviewed machine identities may hold access that was provisioned
but never formally approved. It also means nobody has confirmed the access is still
needed.

**Logic:** checks `lastCertified` and `lastReviewed`. If neither exists and the
identity is more than 30 days old (grace period for new ones), it fires.

**Severity:** Medium.

## What to know before changing this file

- All 7 detectors share the same `machine_identities` collection result — it's
  fetched once and passed to each detector
- The heuristic fallback in `collect_machine_identities()` produces `confidence=0.55`
  vs `0.85-0.90` for real API data — this flows into finding confidence scores
- `_days_since()` is a local utility that handles ISC's mix of ISO8601 date formats;
  it's duplicated across module files intentionally (each module is self-contained)

---

---

# `auditor/modules/ih.py`

## What it is

Identity Hygiene detectors. The "classic audit findings" bucket — issues that
accumulate silently over time and are the first thing external auditors look for.

## The detectors

### IH-01 — Orphaned account (no correlated identity)
**Why it matters:** An orphaned account has no accountable human owner. It can't be
included in access reviews, can't be attributed in audit logs, and is a direct target
for attackers because it's unlikely to be monitored.

**Logic:** account exists in a source, is enabled, but has no `identityId` or `identity`
reference. Confidence is 0.95 — this is one of the most reliable detectors.

**Severity:** Critical.

### IH-02 — Stale enabled account
**Why it matters:** An account that hasn't been used in 90+ days but still has valid
credentials expands the attack surface with no business value. Former access that
was never cleaned up.

**Logic:** checks `lastActivity` or `lastRefreshed` against `policy.stale_account_days`.
Only fires on enabled accounts.

**Severity:** High.

### IH-03 — Disabled in source, still active in governance view
**Why it matters:** ISC's governance view should always reflect reality. If the source
system says disabled but ISC still treats the identity as active, certifications and
governance decisions are based on a lie. Auditors call this a data integrity failure.

**Logic:** account's `enabled` field is False, but the correlated identity's status
in ISC is not INACTIVE/TERMINATED/DISABLED. Confidence is 0.80 because the status
field names vary across ISC versions.

**Severity:** High.

### IH-04 — Duplicate identity collision indicators
**Why it matters:** The same person split across multiple identities means their total
access can never be seen in one place. Certifications only see half the picture.
Often caused by HR system mismatches or manual identity creation.

**Logic:** groups identities by email address (more stable than name as a dedup key).
Any email with 2+ identities is flagged. Avoids double-reporting the same group by
tracking a frozenset of IDs.

**Severity:** High.

### IH-05 — Missing core identity attributes
**Why it matters:** Manager, department, employment type, and email drive:
- Peer group analysis in AR-03 (can't group without department + job code)
- JML lifecycle automation (can't route leavers without employment type)
- Certification campaign routing (can't find the right reviewer without manager)

Missing attributes don't just break this tool — they break ISC's own automation.

**Logic:** checks `REQUIRED_IDENTITY_ATTRS = ["manager", "department", "employmentType", "email"]`
on both the identity object and its `attributes` dict (ISC stores data in both places).

**Severity:** Medium — important for governance quality but not an acute security risk.

### IH-06 — Account with no recent aggregation confidence
**Why it matters:** If ISC hasn't aggregated a source recently, every finding for
accounts in that source is based on stale data. An account you think is enabled might
already be deprovisioned. An account you think is fine might have new privileged access.
This detector makes the tool honest about its own data quality.

**Logic:** builds a set of stale source IDs first (sources not aggregated within
`policy.source_stale_days`), then flags accounts whose source is in that set.

**Severity:** Medium — the risk is in the data uncertainty, not the account itself.

## What to know before changing this file

- IH-04 groups by email. If your tenant uses a non-email field as the unique person
  identifier, you'd want to add that as a second dedup signal
- IH-06 and CR-02 both check source aggregation staleness from different angles:
  IH-06 flags individual accounts from stale sources; CR-02 flags the stale source itself

---

---

# `auditor/modules/li.py`

## What it is

Lifecycle Integrity detectors. Where real operational pain shows up. The gap between
"HR says this person left" and "all their access is actually gone" is one of the most
common and most serious audit findings in enterprise identity programs.

## Helper functions

`_is_terminated()` — checks both `identity.status` and the `employmentStatus` attribute.
ISC normalizes some of this, but authoritative HR sources often populate the attribute
directly and ISC's own status field may lag. Checking both catches the mismatch case
that LI-06 specifically looks for.

`_has_privileged_access()` — checks account names and entitlement names for privileged
keywords. Used by LI-02 to determine whether a terminated identity's remaining access
is elevated or not.

## The detectors

### LI-01 — Terminated identity with active accounts
**Why it matters:** A former employee with active credentials is one of the highest-risk
scenarios in identity security. The insider threat window is open. It's also a direct
compliance violation in SOX, HIPAA, and most data protection frameworks.

**Logic:** finds all identities where `_is_terminated()` is True, then checks if any
of their correlated accounts are still enabled. Includes days since termination in the
evidence.

**Severity:** Critical. This is one of the 7 critical condition detectors — it triggers
a banner regardless of overall score.

### LI-02 — Terminated identity with privileged access
**Why it matters:** Same as LI-01 but more severe. A terminated admin with active
Workday or AWS access is a catastrophic control failure and typically a reportable
incident.

**Logic:** subset of LI-01 findings where the active accounts include privileged ones
(by name keywords or `privileged=True` flag).

**Severity:** Critical.

### LI-03 — Mover with stale access after role change
**Why it matters:** Movers are the most dangerous unchecked group. They accumulate
access silently — old access isn't removed when they change roles, new access is
added for the new role. Over years, a mover can accumulate access to systems across
half the organization.

**Logic:** looks for identities with a `lastDepartmentChange`, `lastJobCodeChange`,
or `lastTitleChange` attribute older than `policy.mover_grace_days`. For matching
identities, finds accounts whose `created` date predates the role change.

**Confidence:** 0.70 — this is heuristic-based (account age as a proxy for pre-role
access). Some false positives are expected, especially for identities who changed roles
but legitimately kept access.

**Severity:** High.

### LI-04 — Joiner missing baseline, manual compensating access
**Why it matters:** If the role model doesn't cover a new hire's profile, someone
manually workarounds it. That workaround becomes permanent. Next time someone with
the same profile joins, they get the same workaround. Over time you have hundreds of
one-off direct grants instead of a governed role structure.

**Logic:** only checks identities created in the last 90 days (joiners). Looks for
manual accounts (`manuallyCorrelated=True` or `origin=MANUAL`) without any role-based
accounts.

**Confidence:** 0.70 — detecting "manual" vs "role-based" depends on ISC populating
the `origin` field, which not all connectors do.

**Severity:** Medium.

### LI-05 — Non-employee past contract end date still active
**Why it matters:** Contractor access past expiry is one of the clearest compliance
violations. The contract specifies the end date. After that date, the access should
not exist. ISC's non-employee lifecycle management supports this explicitly — if
you're using it, this detector provides first-class coverage.

**Logic:** reads from `client.get_non_employees()` and checks `endDate` against
`policy.non_employee_grace_days`. Flags the record if past expiry AND either still
has active accounts OR the non-employee record itself isn't terminated.

**Severity:** Critical. One of the 7 critical condition detectors.

### LI-06 — Identity status mismatch across authoritative and target systems
**Why it matters:** ISC is supposed to be the enforcement layer. If HR says someone
is terminated but ISC still shows them as active, the lifecycle automation has failed.
This isn't just a data quality issue — it means deprovisioning didn't happen.

**Logic:** compares `identity.status` with `attributes.employmentStatus`. When they
disagree (ISC says ACTIVE but HR says TERMINATED, or vice versa), and the identity
has active downstream accounts, it fires.

**Confidence:** 0.80 — depends on the authoritative source populating `employmentStatus`
consistently.

**Severity:** High.

## What to know before changing this file

- `accounts_by_identity` is built once in `run_li_detectors()` and passed to all
  detectors — this avoids re-scanning the full accounts list six times
- LI-01 and LI-02 are similar but separate because their remediation paths differ:
  LI-01 is "disable accounts now," LI-02 is "escalate to security immediately"
- LI-05 flags the non-employee record using `ne_id` as the object ID, not the
  correlated identity ID — this is intentional since the non-employee record is
  the governance object

---

---

# `auditor/modules/ar.py`

## What it is

Access Risk detectors. Combines two approaches:
1. **Hard policy checks** — AR-01 uses ISC's own SOD engine output directly
2. **Statistical and heuristic analysis** — AR-02 through AR-07 detect patterns
   that aren't encoded as formal policies

## The detectors

### AR-01 — Active SOD violation
**Why it matters:** These are violations that ISC's own policy engine has already
identified and flagged. They represent direct policy breaches — conflicts the
organization explicitly defined as unacceptable.

**Logic:** reads directly from `client.get_sod_violations()`. Every violation record
becomes one finding. Confidence is 1.0 — this is straight from ISC's engine, not
our heuristic.

**Severity:** Critical. One of the 7 critical condition detectors.

### AR-02 — Toxic entitlement combination (outside formal SOD)
**Why it matters:** Organizations never encode all toxic combinations as formal SOD
policies. This detector catches the ones they forgot. `KNOWN_TOXIC_COMBOS` is a
list of high-risk pairs based on common audit findings:
- Payroll + GL Posting
- Payroll + Finance Admin
- IAM Admin + Audit
- Create User + Approve
- Deploy + Approve Deploy
- HR Admin + Payroll

**Logic:** for each identity, checks whether they hold entitlements matching both
keywords in any toxic pair.

**Confidence:** 0.75 — keyword matching will produce false positives (an entitlement
named "Payroll Report Viewer" might match "payroll" but isn't the same as "Payroll Admin").

**Severity:** High.

### AR-03 — Excessive access vs peer group
**Why it matters:** The best signal for over-provisioning is comparison to peers.
Someone with 3x the entitlements of their department colleagues almost certainly has
access accumulation from old roles, approved exceptions, or workarounds.

**Logic:** groups identities by `department + jobCode`. For groups with 3+ members
(too small for meaningful statistics otherwise), uses `statistics.quantiles` to find
the 95th percentile (configurable via `policy.peer_group_outlier_pct`). Any identity
above that threshold is flagged.

**Why 95th percentile?** You want to flag outliers, not everyone above average. The
95th percentile means only the top 5% of each peer group is flagged — a meaningful
signal without too much noise.

**Severity:** High.

### AR-04 — Direct entitlement where role should be used
**Why it matters:** Direct grants bypass role governance. When the same entitlement
exists both in a role AND as a direct grant on an identity, it means someone worked
around the role model. Over time this creates certifications that are impossible to
maintain and access that nobody can explain.

**Logic:** builds a set of entitlement IDs covered by any role, then finds identities
that have those entitlements granted directly (not via role or access profile).

**Severity:** Medium — structural drift, not acute risk.

### AR-05 — Role or access profile with entitlement bloat
**Why it matters:** Oversized roles violate least privilege and are impossible to
certify meaningfully. A reviewer looking at a role with 200 entitlements will approve
everything — which is exactly the rubber-stamp behavior GQ-03 flags.

**Logic:** checks both roles and access profiles. Fires if the object has 50+ entitlements
(High) or 100+ (Critical). Also reports how many are sensitive.

**Severity:** High or Critical depending on count.

### AR-06 — Sensitive access held by broad population
**Why it matters:** "Payroll Admin" held by 200 people is not governance — it's a
control failure. Sensitive entitlements should be held by the smallest possible set
of people with a documented business need.

**Logic:** counts holders of each `policy.sensitive_entitlements` name across all
identities. Fires if holders exceed 5% of the total identity population or 10 people
(whichever is higher).

**Severity:** Critical. One of the 7 critical condition detectors.

### AR-07 — Redundant access paths
**Why it matters:** If an identity receives the same entitlement through a role, an
access profile, AND a direct grant, that's three separate certification items for
the same access. It makes certifications harder, confuses reviewers about the intended
model, and can mask unintended grants.

**Logic:** groups access items by entitlement ID, collects all sources for each.
Fires if 3+ entitlements are received through multiple overlapping paths.

**Severity:** Medium.

## What to know before changing this file

- `KNOWN_TOXIC_COMBOS` should be expanded with combinations specific to your industry
  and tenant — the current list is a starting point, not comprehensive
- AR-03 requires `statistics.quantiles` which needs Python 3.8+. If you ever need
  to target older Python, replace with a manual percentile calculation
- AR-04's logic depends on ISC populating the `source` or `type` field on access items
  to distinguish direct grants from role-based grants — this varies by connector

---

---

# `auditor/modules/gq.py`

## What it is

Governance Quality detectors. This is where the AI layer adds the most value, because
these findings describe behavioral patterns and systemic gaps that are hard to explain
mechanically but easy for Claude to contextualize.

## The detectors

### GQ-01 — Overdue certification campaign
**Why it matters:** An overdue campaign means access hasn't been confirmed as appropriate
for that period. Auditors treat campaign completion rate as a direct compliance metric.
An overdue campaign on privileged access is a reportable finding.

**Logic:** checks open campaigns (status not COMPLETE, CLOSED, or CANCELLED) for
due dates more than `policy.certification_overdue_days` past.

**Severity:** High.

### GQ-02 — Privileged roles not in certification scope
**Why it matters:** Governance without coverage of the most sensitive access is security
theater. If your privileged roles are never reviewed, the certification program isn't
protecting what matters most.

**Logic:** identifies privileged roles (name contains "admin", "privileged", "superuser",
"global") and checks which of them appear in any certification campaign's item list.
Flags the gap.

**Severity:** High.

### GQ-03 — Rubber-stamp pattern
**Why it matters:** This is the most subtle detector and the one where AI explanation
adds the most value. A certification campaign where 99% of items are approved in 15
seconds each looks clean in ISC's dashboard — but it's evidence that access is being
certified without being genuinely reviewed.

**Logic:** looks at completed campaigns for two signals:
- Approval rate ≥ 98% on campaigns with 20+ items
- Average decision time < 30 seconds per item

**Severity:** High. Confidence is 0.80 — fast approvals have legitimate explanations
(AI recommendations, pre-filtered campaigns) so this needs human review.

### GQ-04 — Unowned governance object
**Why it matters:** A role, access profile, or source with no owner cannot be governed.
There's no one to approve access requests, complete certifications, or make changes.
It becomes an orphan governance object — technically managed but practically abandoned.

**Logic:** checks all roles, access profiles, and sources for missing `owner`, `ownerId`,
or `ownerName`. Combines them into a single set of findings since the remediation is the
same regardless of object type.

**Severity:** High.

### GQ-05 — Empty or weak governance group
**Why it matters:** ISC uses governance groups to make certification and access request
decisions. An empty governance group means those processes fail or route incorrectly
when triggered. Common after people leave an organization — they're removed from the
group but nobody adds a replacement.

**Logic:** checks `members` count on each governance group. Fires on zero-member groups.

**Severity:** Medium.

### GQ-06 — Self-review or conflicted review path
**Why it matters:** Self-reviews are explicitly prohibited by SOX, SOC2, and most
internal audit standards. They're a direct conflict of interest — the person being
reviewed is confirming their own access is appropriate.

**Logic:** compares `item.reviewer.id` with `item.subject.id` for each certification
item. ISC should prevent this in configuration, but misconfigured campaigns can
allow it through.

**Severity:** Medium.

### GQ-07 — Access item missing description
**Why it matters:** Reviewers in certification campaigns can't make informed decisions
about access they don't understand. A role named "SYS_ADMIN_ROLE_47" with no description
will be rubber-stamped (GQ-03) because the reviewer has no basis to revoke it.

**Logic:** checks `description` on all roles and access profiles. Fires if missing or
shorter than 20 characters (too short to be meaningful).

**Severity:** Medium.

### GQ-08 — Certification blind spot (governance group assignments)
**Why it matters:** This is the most honest detector in the project. The ISC
`access-review-items` API doesn't support certifications assigned to Governance Groups
at the item level. This means the auditor itself has a blind spot — and it surfaces that
fact explicitly rather than silently skipping it.

**Logic:** finds certifications where `reviewerType` or `certifierType` is `GOVERNANCE_GROUP`.
Creates one finding (even if multiple campaigns are affected) explaining the API limitation.

**Why make this a finding?** Because "I couldn't see this" is itself information. The user
should know the auditor's coverage is incomplete here and review those campaigns manually.

**Severity:** Medium. Confidence is 1.0 — the blind spot itself is certain, even though
the content of the campaigns is uncertain.

## What to know before changing this file

- GQ-03 (rubber-stamp) is the most likely to generate complaints from the business.
  It's intentionally moderate confidence (0.80) — use Claude's AI explanation to help
  reviewers understand why fast approvals on large campaigns are a concern
- GQ-08 should be updated if SailPoint ever adds governance-group support to the
  access-review-items API

---

---

# `auditor/modules/cr.py`

## What it is

Coverage & Reconciliation detectors. The module most teams forget, and the one
that makes the tool feel mature. These detectors surface gaps in what ISC can actually
see and govern, and catch provisioning failures that other modules miss.

## The detectors

### CR-01 — Connected source with no owner
**Why it matters:** Every source feeding accounts into ISC needs an accountable owner.
Without one, there's nobody responsible when aggregation breaks, when certifications
route incorrectly, or when the source's data quality degrades.

**Logic:** checks all sources for missing `owner`, `ownerId`. Simple but high-value.

**Severity:** High.

### CR-02 — Source not recently aggregated
**Why it matters:** If ISC hasn't successfully aggregated a source in 3+ days, every
finding for accounts in that source is based on outdated data. This detector makes the
tool honest about the freshness of its own inputs.

**Logic:** checks `lastAggregationDate` or `lastSuccessfulAggregation` against
`policy.source_stale_days`. Applies higher severity to sources in `policy.critical_sources`.

**Severity:** Medium (High for critical sources).

### CR-03 — Stuck or failed provisioning activity
**Why it matters:** A stuck provisioning operation means the intended access change
didn't happen. Access that should have been granted wasn't. Access that should have
been removed wasn't. The governance layer and reality have diverged.

**Logic:** reads account activities with stuck statuses (PENDING, IN_PROGRESS, RETRYING,
FAILED). Only fires on activities older than 24 hours — recent ones may still complete.

**Severity:** High.

### CR-04 — Deprovisioning requested but not completed
**Why it matters:** This is the most legally significant reconciliation detector. A
deprovision was explicitly requested in ISC but the account is still active. This means
the governance layer said "remove access" and the enforcement layer ignored it.

**Logic:** finds account activities where the operation type contains "DEPROVISION",
"DISABLE", or "REMOVE", then checks whether the corresponding account is still in the
active accounts list.

**Severity:** Critical. One of the 7 critical condition detectors.

### CR-05 — Revoked in ISC, still present in target system
**Why it matters:** Similar to CR-04 but detected from the other direction. ISC's
internal record shows the account as REVOKED or DISABLED, but the native account
attributes show it's still active. This is confirmed access drift.

**Logic:** finds accounts with ISC status REVOKED/DISABLED/INACTIVE, then checks
native identity attributes for `active=True` or `enabled=True`.

**Confidence:** 0.85 — depends on ISC having received and stored the native attribute
state from a recent aggregation.

**Severity:** Critical. One of the 7 critical condition detectors.

### CR-06 — Manual source governance hot spot
**Why it matters:** Manual or flat-file sources have no automated lifecycle management.
Accounts are only updated when someone manually intervenes. A manual source with 200+
accounts and no owner is a governance blind spot that will accumulate risk indefinitely.

**Logic:** identifies sources with a manual/flat/csv connector type, counts their
accounts, and flags ones with 50+ accounts and no owner.

**Severity:** High.

### CR-07 — Critical source with low governance coverage
**Why it matters:** Critical sources (defined in `policy.critical_sources`) should have
the highest level of governance coverage. Any gap here represents the highest-risk
blind spots in the environment.

**Logic:** finds sources that match `policy.critical_sources`, checks for owner and
whether they appear in any certification campaign's scope.

**Severity:** Medium.

### CR-08 — Source with abnormally high orphan ratio
**Why it matters:** This is a source-level health signal rather than individual findings.
A source where 20% of accounts are orphaned isn't just a finding problem — it's a
systemic problem with the correlation rules or the data quality from that source.

**Logic:** calculates `orphaned_accounts / total_accounts` per source. Fires if the
ratio exceeds 15% and the source has at least 20 accounts (too small to be meaningful).

**Severity:** Medium.

## What to know before changing this file

- CR-04 and CR-05 are the highest-value detectors in this module. If you have to
  prioritize testing, start with these two
- CR-05 depends on ISC having stored the native system's attribute state — if
  aggregation is stale (CR-02), CR-05 may miss real drift
- CR-06's definition of "manual source" is based on connector name keywords — if
  your manual sources use a different connector name pattern, update the keyword list

---

---

# `auditor/ai/analyzer.py`

## What it is

The Claude AI integration layer. Runs after all detectors have fired and all findings
have been scored. Takes the completed, scored findings and sends them to Claude to
generate plain-English explanations.

## Design philosophy (critical to understand)

Claude's role is strictly defined and intentionally limited:

**What Claude does:**
- Explain why a finding matters in plain English for both engineers and business stakeholders
- Describe blast radius — what an attacker could reach if this finding were exploited
- Suggest remediation priority and first steps
- Write auditor-ready language for audit packages

**What Claude does NOT do:**
- Decide whether a control failed (the detectors already did that deterministically)
- Invent context that isn't in the evidence
- Replace threshold logic
- Generate findings on its own

This is the right boundary. The deterministic part of the tool is reproducible,
auditable, and trustworthy. Claude adds the "so what" layer on top of facts that
were already established by code.

## How it works

`analyze_findings()` takes the list of active (non-suppressed) findings and sends
them to Claude in batches of up to 10.

The system prompt establishes Claude's role clearly — read it carefully, it's the
contract for every AI interaction this tool produces.

Each batch sends a JSON representation of the findings with all their evidence,
severity, risk score, and recommended fix. Claude returns a JSON array with four
fields per finding:
- `ai_explanation` — 2–3 sentences for a CISO or manager
- `ai_blast_radius` — 1–2 sentences on what an attacker could access
- `ai_remediation` — numbered steps
- `ai_audit_note` — formal language for an audit package

Results are matched back to findings by `finding_id`. The findings are enriched
in-place — the same `Finding` objects come back with `ai_*` fields populated.

## Error handling

Every batch is wrapped in a try/except. If Claude returns malformed JSON or an
API error, the batch is skipped and the findings retain their original values
(no AI fields). The run never crashes because of AI analysis failures.

This is intentional. The tool produces value without AI — the AI is an enhancement,
not a dependency.

Findings are sorted priority-first (CRITICAL before HIGH before MEDIUM) before
batching, so if you hit a token limit or rate limit partway through, the most
important findings get AI analysis first.

## What to know before changing this file

- The system prompt is the most important thing in this file. If you want to change
  how Claude frames its explanations, change the system prompt
- `MAX_FINDINGS_PER_BATCH = 10` keeps prompts focused. Larger batches risk Claude
  truncating output or losing context across findings
- The model is hardcoded to `claude-sonnet-4-6` — change this if you want to use
  a different Claude model
- The JSON fence stripping (lines 90–92) handles cases where Claude wraps its
  response in markdown code blocks despite being asked not to

---

---

# `policy_packs/default.yaml`

## What it is

The default configuration for the auditor. Defines what counts as "privileged",
what thresholds trigger detectors, and what naming conventions are expected.

This file is version-controlled and ships with the tool. It represents reasonable
defaults for a mid-large enterprise ISC deployment.

## How to customize for your tenant

Copy the default pack and modify it:

```bash
cp policy_packs/default.yaml policy_packs/myorg.yaml
isc-audit run --all --policy-pack policy_packs/myorg.yaml
```

Key things to customize:

**Thresholds** — adjust based on your org's risk tolerance and operational cadence.
A highly regulated financial org might set `stale_account_days: 30`. A smaller org
might be comfortable with `90`.

**Privileged apps** — add every application in your environment where admin access
is genuinely sensitive. The default list is broad; your list should be specific to
what you actually run.

**Sensitive entitlements** — match the exact entitlement names in your ISC environment.
These are case-insensitive substring matches, so "Payroll Admin" will match
"SYS_PAYROLL_ADMIN_ROLE" — but be specific enough to avoid false positives.

**Critical sources** — list your authoritative systems. At minimum: your HR system,
Active Directory, and your primary cloud platform.

**Naming conventions** — update the regex patterns to match what your team actually uses.
If service accounts at your org are named `app-<name>` rather than `svc-<name>`, update
the pattern.

**Detector overrides** — disable detectors that don't apply to your environment, or
override thresholds for specific detectors:
```yaml
detector_overrides:
  MI-06:
    enabled: false     # Your org doesn't enforce naming conventions yet
  IH-02:
    stale_account_days: 45   # Stricter threshold for your environment
```

## What to know before changing this file

- Changes to this file affect every audit run that uses the default policy pack
- The YAML keys must exactly match the field names in `PolicyPack` in `config.py`
- Adding new keys that don't exist in `PolicyPack` will cause a Pydantic validation
  error when the file is loaded — add the field to the model first
