# sailpoint-isc-auditor

**An AI-powered audit engine for SailPoint Identity Security Cloud (ISC).**

Runs deterministic security checks across your ISC tenant, then uses Claude AI to explain findings in plain English, score remediation priority, and generate auditor-ready reports — in minutes, not weeks.

---

## What it does

Connects to your ISC tenant via the REST API, runs 25 security detectors across 6 control families, scores every finding on a two-axis risk model, and produces a **tenant health score** (0–100) that leadership can track over time.

```
$ isc-audit run --all

  SailPoint ISC Auditor v0.1.0
  Tenant: acme-corp.identitynow.com
  ─────────────────────────────────────────────────

  Collecting data...
    ✓ Machine identities       (experimental API — full coverage)
    ✓ Accounts & identities    (4,821 identities, 12,304 accounts)
    ✓ Roles & entitlements     (342 roles, 8,902 entitlements)
    ✓ SOD violations           (ISC policy engine)
    ✓ Certifications           (partial — governance-group assignments excluded)
    ✓ Sources & provisioning   (47 sources)

  Running detectors...
    ✓ Machine & privileged identity    MI-01 to MI-07
    ✓ Identity hygiene                 IH-01 to IH-06
    ✓ Lifecycle integrity              LI-01 to LI-06
    ✓ Access risk                      AR-01 to AR-07
    ✓ Governance quality               GQ-01 to GQ-08
    ✓ Coverage & reconciliation        CR-01 to CR-08

  Analyzing findings with Claude AI...

  ─────────────────────────────────────────────────
  TENANT HEALTH SCORE: 61 / 100  [NEEDS ATTENTION]
  ─────────────────────────────────────────────────

  CRITICAL  4 findings
  HIGH      11 findings
  MEDIUM    8 findings

  Top priority: MI-02 — 3 machine identities hold admin-level roles
                LI-01 — 7 terminated users still have active accounts
                AR-01 — 2 active SOD violations (Payroll + GL Posting)

  Report written to: audit_acme-corp_2025-04-10.html
```

---

## Control families & detectors

| ID | Detector | Severity |
|---|---|---|
| **MI — Machine & Privileged Identity** |||
| MI-01 | Machine identity without owner | Critical |
| MI-02 | Machine identity with privileged access | Critical |
| MI-03 | Dormant machine identity still enabled | High |
| MI-04 | Shared privileged account not tied to a person | High |
| MI-05 | Break-glass access with no control evidence | Critical |
| MI-06 | Service account outside naming/tagging policy | Medium |
| MI-07 | Machine identity created but never reviewed | Medium |
| **IH — Identity Hygiene** |||
| IH-01 | Orphaned account (no correlated identity) | Critical |
| IH-02 | Stale enabled account (90+ days inactive) | High |
| IH-03 | Source disabled, still active in governance view | High |
| IH-04 | Duplicate identity collision indicators | High |
| IH-05 | Missing core identity attributes | Medium |
| IH-06 | Account with no recent aggregation confidence | Medium |
| **LI — Lifecycle Integrity** |||
| LI-01 | Terminated identity with active accounts | Critical |
| LI-02 | Terminated identity with privileged access | Critical |
| LI-03 | Mover retained stale access after job change | High |
| LI-04 | Joiner missing baseline, compensating access granted manually | Medium |
| LI-05 | Non-employee past end date still active | Critical |
| LI-06 | Identity status mismatch across authoritative and target systems | High |
| **AR — Access Risk** |||
| AR-01 | Active SOD violation | Critical |
| AR-02 | Toxic entitlement combination (no formal SOD policy) | High |
| AR-03 | Excessive access vs peer group | High |
| AR-04 | Direct entitlement where role should be used | Medium |
| AR-05 | Role or access profile with entitlement bloat | High |
| AR-06 | Sensitive access held by broad population | Critical |
| AR-07 | Redundant access paths | Medium |
| **GQ — Governance Quality** |||
| GQ-01 | Overdue certification campaign | High |
| GQ-02 | Low coverage on high-risk access | High |
| GQ-03 | Bulk-approval / rubber-stamp pattern | High |
| GQ-04 | Unowned governance object | High |
| GQ-05 | Empty or weak governance group | Medium |
| GQ-06 | Self-review or conflicted review path | Medium |
| GQ-07 | Access item missing business context | Medium |
| GQ-08 | Certification blind spots (governance-group model) | Medium |
| **CR — Coverage & Reconciliation** |||
| CR-01 | Connected source with no governance owner | High |
| CR-02 | Source not recently aggregated | Medium |
| CR-03 | Provisioning failure or stuck account activity | High |
| CR-04 | Deprovisioning requested but not completed | Critical |
| CR-05 | Revoked in ISC, still present in target system | Critical |
| CR-06 | Manual / disconnected governance hot spots | High |
| CR-07 | Critical source with low policy attachment | Medium |
| CR-08 | High-volume source with abnormal risk ratios | Medium |

---

## Tenant health score

Every audit produces a single **0–100 health score** — a weighted rollup of all findings, coverage completeness, and governance posture.

| Score | Band | Meaning |
|---|---|---|
| 90–100 | Excellent | Strong controls, minor gaps only |
| 75–89 | Good | Solid posture with addressable issues |
| 60–74 | Needs attention | Meaningful risk present |
| 40–59 | At risk | Significant gaps requiring urgent action |
| 0–39 | Critical | Systemic governance failure |

Score trends over time are tracked in `~/.isc-audit/history.json` so you can chart improvement.

---

## Risk scoring model

Each finding is scored on two axes:

```
risk_score = impact_score × exploitability_score × governance_failure_score
```

**Impact** — how bad is this if exploited? (object type, privilege level, population size)
**Exploitability** — how easy is it to exploit? (account enabled, access active, no MFA)
**Governance failure** — how badly did controls fail? (no owner, no review, drift confirmed)

---

## Installation

```bash
pip install sailpoint-isc-auditor
```

Or from source:

```bash
git clone https://github.com/yourusername/sailpoint-isc-auditor
cd sailpoint-isc-auditor
pip install -e .
```

---

## Configuration

```bash
cp .env.example .env
```

Edit `.env`:

```env
ISC_TENANT_URL=https://yourorg.identitynow.com
ISC_CLIENT_ID=your-client-id
ISC_CLIENT_SECRET=your-client-secret
ANTHROPIC_API_KEY=your-anthropic-api-key
```

### Creating an ISC API client

In ISC: **Admin → API Management → New API Client**

Required scopes:
- `isc:identity:read`
- `isc:account:read`
- `isc:role:read`
- `isc:entitlement:read`
- `isc:sod-policy:read`
- `isc:certification:read`
- `isc:source:read`
- `isc:machine-identity:read` *(optional — enables MI detectors fully)*

---

## Usage

```bash
# Full audit — all 25 detectors
isc-audit run --all

# Specific families
isc-audit run --families MI LI AR

# Specific detectors
isc-audit run --detectors MI-01 MI-02 LI-01 AR-01

# Output format
isc-audit run --all --output html --out report.html
isc-audit run --all --output json --out findings.json

# Use a custom policy pack
isc-audit run --all --policy-pack ./policy_packs/financial_services.yaml

# Suppress a known finding
isc-audit suppress MI-06 --object-id "svc-legacy-erp" \
  --reason "Remediation tracked in JIRA-4521" \
  --expires 2025-09-01

# Show suppressed findings
isc-audit suppressions list

# View score history
isc-audit history
```

---

## Policy packs

Customize thresholds for your environment. Copy and edit the default pack:

```bash
cp policy_packs/default.yaml policy_packs/myorg.yaml
```

Key settings:

```yaml
thresholds:
  stale_account_days: 90
  inactivity_days: 60
  non_employee_grace_days: 7
  peer_group_outlier_percentile: 95

privileged_apps:
  - "AWS"
  - "Workday"
  - "Snowflake"
  - "GitHub Enterprise"

naming_conventions:
  service_accounts: "^svc-"
  break_glass: "^bg-|^emergency-"

sensitive_entitlements:
  - "Payroll Admin"
  - "GL Posting"
  - "IAM Admin"
  - "Production Deploy"

critical_sources:
  - "Workday"
  - "Active Directory"
  - "AWS"
```

---

## AI explanation

Claude analyzes findings *after* the deterministic checks run — it never decides whether a control failed. Its job is to:

- Explain why a finding matters in plain English
- Estimate blast radius
- Suggest remediation order
- Write auditor-ready notes
- Group related findings into a single story

---

## Output formats

| Format | Best for |
|---|---|
| Terminal (default) | Engineers running the tool |
| HTML report | Sharing with leadership and auditors |
| JSON | Integration with SIEM, ticketing, dashboards |

---

## Graceful API fallback

Some ISC endpoints are experimental or tier-restricted. The auditor degrades gracefully:

- Falls back to heuristic detection where possible
- Skips unavailable detectors cleanly
- Reports exactly what it could and couldn't see in a **coverage summary**
- Never crashes the run due to a missing endpoint

---

## Contributing

Issues, PRs, and discussion welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

This project follows an evidence-first philosophy: every finding must be reproducible, traceable, and suppressible before it ships.

---

## License

MIT — use freely, contribute back.
