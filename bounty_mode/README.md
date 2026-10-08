# Bounty Mode

**Authorized AI bug-bounty workflow for a red-teaming engine.**

Bounty Mode turns raw attack execution into a *submittable, scope-compliant*
bug-bounty report. It does not re-implement a single attack — it wraps an
existing offensive AI red-teaming engine (the Agathon engine in this repo) and
adds the six things that stand between "we found something" and "a triager
paid for it":

| Layer | What it does |
|---|---|
| **Scope importer** | Parses a HackerOne / Bugcrowd / Intigriti / YesWeHack policy into machine-readable rules |
| **Authorization gate** | Deny-by-default enforcement: scope, technique policy, human-in-the-loop |
| **Stop-condition engine** | Kill switch, request/time/error budgets, latch-on-fire |
| **Evidence vault** | Redacts secrets and PII, hash-chains everything it writes |
| **Triage scorer** | Real CVSS v3.1 + bounty-specific adjustments (cross-tenant > jailbreak) |
| **Report generator** | HackerOne / Bugcrowd-shaped writeups + structured submission JSON |

Plus de-duplication and regression retest, a case runner, and a CLI.

---

## Why this exists

Raw scanners do not produce accepted reports. Triagers reject submissions that
are out of scope, non-reproducible, missing impact, or that leaked the very
data the bug was about. Bounty Mode makes each of those failures structurally
impossible:

1. **Deny by default.** A target must match an in-scope asset *and* clear the
   gate before the engine is ever called.
2. **No destructive actions.** DoS / rate-limit / resource-exhaustion
   techniques are blocked for every program, even when the target is in scope.
3. **Minimal proof of impact.** Credentials and personal data are replaced with
   `[REDACTED:<category>]` markers *before* anything reaches disk.
4. **Human in the loop.** Any technique flagged `side_effects` requires an
   audited approval registered with the gate.
5. **Offline first.** Scope parsing, gating, redaction, scoring, de-duplication
   and report rendering need no network access and no API keys.

---

## Install

Requires **Python 3.9+**. Core has **zero runtime dependencies**.

```bash
git clone https://github.com/kkcyber2/bounty-machine.git
cd bounty-machine/bounty_mode

# Editable install with dev extras (pytest + PyYAML)
pip install -e ".[dev]"

# Or minimal, no dependencies at all
pip install -e .
```

`PyYAML` is optional and only needed for YAML policy/case files. JSON always works.

Verify the install:

```bash
python -m bountymode techniques      # lists the 19-technique catalogue
python -m pytest -q                  # runs the test suite
```

---

## Quickstart — policy to report in five commands

```bash
# 1. Turn a program policy into machine-readable scope rules.
python -m bountymode scope import examples/policy-example.md --program acme -o scope.json

# 2. Read it back and confirm the numbers before arming anything.
python -m bountymode scope show scope.json

# 3. Dry-run the authorization gate for one target. (Exit 3 = blocked.)
python -m bountymode check scope.json api.acme.com --technique prompt_injection

# 4. Run a case. This is a DRY RUN unless you pass --live.
python -m bountymode run examples/case-example.yaml -o bounty-run/acme-pass-1

# 5. Score findings, then render reports.
python -m bountymode triage findings.json -o triaged.json
python -m bountymode report triaged.json --platform hackerone --program acme -o reports/
```

There is also a fully offline end-to-end demo — no network, no keys, no engine:

```bash
python examples/demo_offline.py
```

It prints the gate allowing one technique, denying one, and deferring one; a
case run in which the destructive technique never reaches the engine; the
redaction count on captured evidence; and a rendered HackerOne report.

### Arming a live run

`run` contacts a target **only** when you pass `--live`:

```bash
export INTERNAL_SCAN_TOKEN="..."      # never hard-code this

python -m bountymode run examples/case-example.yaml \
    --live \
    --engine https://your-engine \
    --token "$INTERNAL_SCAN_TOKEN" \
    -o bounty-run/acme-live
```

---

## Configuration

### Scope file (canonical JSON)

Produced by `scope import`; hand-editable. Review it before every run.

```json
{
  "program": "acme",
  "platform": "hackerone",
  "in_scope": [
    {"pattern": "api.acme.com", "kind": "api"},
    {"pattern": "*.acme.ai", "kind": "web"}
  ],
  "out_of_scope": [
    {"pattern": "admin.acme.com", "reason": "internal admin console"}
  ],
  "prohibited_techniques": ["destructive", "economic_denial", "malware"],
  "permitted_techniques": [],
  "rate_limit_rps": 2.0,
  "max_requests": 300,
  "max_duration_s": 1800,
  "requires_test_account": true,
  "safe_harbour": true,
  "disclosure_days": 90
}
```

**Matching rules**

| Pattern | Matches | Does not match |
|---|---|---|
| `example.com` | `example.com`, `www.example.com` | `api.example.com` |
| `*.example.com` | `api.example.com`, `deep.api.example.com` | `example.com` (apex excluded) |
| `api.example.com:443` | `api.example.com` | `other.example.com` |
| `https://api.example.com/v1` | `https://api.example.com/v1/chat` | `https://api.example.com/v2/chat` |

Exclusions are evaluated **first** and always win. `localhost`,
`127.0.0.1`, `0.0.0.0` and the cloud metadata address `169.254.169.254` are
refused even if a policy lists them.

### Case file (YAML or JSON)

```yaml
id: acme-assistant-pass-1
scope: scope.json
target: api.acme.com
output_dir: bounty-run/acme-pass-1

techniques:
  - prompt_injection
  - data_exfiltration
  - cross_tenant
  - tool_misuse          # side effects -> needs an approval entry
  - economic_denial      # destructive -> always blocked

approvals:               # human-in-the-loop, audited
  - technique: tool_misuse
    target: api.acme.com
    approved_by: "analyst-name"
    approved_at: "2026-10-08T09:00:00Z"
    note: "Authorised to test the tool-calling surface with a test account."
```

Add an `approvals` entry **only** after a human has explicitly authorised that
test. Bounty Mode records who approved what and when.

---

## CLI reference

| Command | Purpose |
|---|---|
| `scope import <policy> --program <name> -o scope.json` | Import a policy (`.md`, `.txt`, `.yaml`, `.json`) |
| `scope show <scope.json>` | Print the parsed scope |
| `techniques` | List the technique catalogue as JSON |
| `check <scope> <target> [--technique ...]` | Dry-run the gate; exit 3 if nothing is allowed |
| `run <case> [--live --engine URL --token T] -o DIR` | Execute a case (dry run by default) |
| `triage <findings.json> -o out.json [--min-score 4.0]` | Score + rank findings |
| `report <findings.json> --platform hackerone\|bugcrowd -o DIR` | Render submission reports |
| `retest <finding_id> --registry registry.json [--fixed]` | Record a regression retest |

`run` writes `result.json`, `evidence/` and `registry.json` under the output
directory. `report` writes one `.md` and one `.json` per finding — the JSON is
a ready-to-POST submission payload.

---

## Python API

```python
from bountymode import (
    Approval, AuthorizationGate, CaseRunner, DedupRegistry, EvidenceVault,
    ReportGenerator, ScopeImporter, StopConditionEngine, StopConditions,
    TriageScorer, Verdict, TechniqueRegistry,
)

# 1. Import the program, build the gate.
scope = ScopeImporter().import_file("policy.md", program="acme")
gate = AuthorizationGate(scope)

# 2. Authorize one test. Denials are data, not exceptions.
tech = TechniqueRegistry().require("prompt_injection")
decision = gate.authorize("api.acme.com", tech)
assert decision.verdict is Verdict.ALLOW

# 3. Run the case behind the gate.
runner = CaseRunner(
    gate=gate,
    stops=StopConditionEngine(StopConditions.from_scope(scope)),
    vault=EvidenceVault("run/evidence"),
    dedup=DedupRegistry("run/registry.json"),
)
result = runner.run("pass-1", scope, "api.acme.com", ["prompt_injection", "cross_tenant"])

# 4. Rank, then render.
ranked = TriageScorer().ranked_findings(result.findings)
gen = ReportGenerator("hackerone", program="acme")
for finding in ranked:
    gen.write(gen.render(finding), "run/reports")
```

### The engine contract

Bounty Mode talks to an engine through one narrow interface:

```python
from bountymode import EngineResult

def dispatch(technique, target) -> EngineResult:
    raw = my_engine.run(technique.engine_key, target)   # your engine
    return EngineResult.from_dict(raw, technique.id, target)
```

`EngineResult` mirrors `attacks/base_tester.py::AttackResult`
(`success`, `success_score`, `payload_used`, `response`, `evidence`,
`vulnerability_type`, `confidence`, `target_model`). An
`AgathonAdapter` for the engine's HTTP scan surface ships in
`bountymode/runner/adapter.py`. A dispatcher that raises is recorded as an
error, never a false success.

---

## Architecture

```
bountymode/
├── models.py            Finding, Technique, Observation, ProgramScope, Severity, Verdict
├── errors.py            ScopeViolationError, AuthorizationError, StopConditionError, ...
├── scope/
│   ├── importer.py      policy (.md/.txt/.yaml/.json) -> ProgramScope
│   └── matcher.py       host / glob / URL-prefix matching, exclusion precedence
├── authority/
│   ├── gate.py          AuthorizationGate + audited Approvals
│   └── stop_conditions.py  budgets, kill switch, latch-on-fire
├── evidence/
│   ├── redactor.py      14 credential + 5 personal-data patterns
│   └── vault.py         redact-before-persist, SHA-256 hash chain
├── triage/
│   ├── cvss.py          dependency-free CVSS v3.1 base score
│   └── scorer.py        bounty adjustments + submission priority
├── report/generator.py  HackerOne / Bugcrowd markdown + structured JSON
├── dedupe/registry.py   fingerprints, known-issue import, regression retest
├── runner/
│   ├── adapter.py       technique catalogue + engine bridge
│   └── case_runner.py   one technique at a time, gate-enforced
└── cli.py               the `bountymode` entry point
```

**Data flow**

```
policy ─► ScopeImporter ─► ProgramScope ─► AuthorizationGate ─┐
                                                               │ ALLOW only
TechniqueRegistry ─► CaseRunner ─► StopConditionEngine ────────┤
                        │                                      ▼
                        │                            engine (your red-team engine)
                        │                                      │
                        ▼                                      ▼
                  EvidenceVault ◄── Finding ◄── FindingBuilder ◄┘
                        │
                        ▼
                  TriageScorer ─► ReportGenerator ─► .md + .json
```

---

## Testing

The suite runs offline and requires no credentials.

```bash
python -m pytest -q
```

**Verified result on Python 3.11.2 (the sandbox this was built in):**

```
76 passed in 0.15s
```

Coverage by module:

| Test file | Tests | What it proves |
|---|---|---|
| `tests/test_scope.py` | 19 | glob/exclusion precedence, unsafe-host refusal, text-policy extraction, JSON round-trip |
| `tests/test_gate.py` | 19 | all three gate guarantees; stop-conditions fire and latch |
| `tests/test_evidence.py` | 16 | every credential class redacted, chain detects tampering, nothing sensitive on disk |
| `tests/test_triage_report.py` | 19 | CVSS matches FIRST reference vectors, de-dup, report field contract |
| `tests/test_runner.py` | 18 | out-of-scope never dispatched, stop latches mid-run, exceptions contained |
| `tests/test_cli.py` | 5 | full pipeline end to end through the real CLI |

### What the tests actually assert

These are the load-bearing guarantees, each backed by a test:

* `test_runner_never_dispatches_out_of_scope_target` — the dispatcher is
  asserted to have **zero** calls for an out-of-scope target.
* `test_gate_blocks_destructive_technique_even_when_in_scope`.
* `test_gate_requires_human_for_side_effects_then_allows_after_approval`.
* `test_stop_latches_after_firing` — a fired condition stays fired.
* `test_vault_persists_redacted_evidence_and_verifies_chain` — no secret
  survives on disk.
* `test_vault_chain_detects_tampering`.
* `test_cvss_reference_vectors` — CVSS 3.1 scores checked against
  published FIRST reference vectors (9.8, 6.1, 7.8, 5.9, 0.0).

### Demonstrated end to end (live CLI, real output)

A policy was imported and the gate consulted for a single target:

```
summary: {"allow": 1, "deny": 1, "needs_human": 1}

prompt_injection   -> ALLOW        in scope; technique permitted
economic_denial    -> DENY         destructive techniques are blocked in Bounty Mode
tool_misuse        -> NEEDS_HUMAN  technique has side effects and no human approval is registered

# same scope, out-of-scope target -> exit code 3
evil.test / prompt_injection -> DENY   target is not covered by any in-scope asset
```

### Explicitly NOT verified here

Being precise about the boundary matters more than an impressive claim:

* **No live scan against a real target was executed.** This sandbox has no
  authorized target and no engine credentials, so every engine-side test uses a
  fake dispatcher. The wiring is tested; a real end-to-end scan is not.
* **No bounty was submitted.** The report format is modelled on the platforms'
  documented field sets; it has not been through a live triage queue.
* **The text-policy parser is best-effort.** It is conservative and always
  reports what it extracted, but a human must review the generated scope
  before a run. Use the JSON form when accuracy matters.
* **Reward figures** in examples are illustrative, not quotes.

---

## Legal and authorization notice

> **Authorized security testing only.**

Bounty Mode is built for testing systems you **own** or have **explicit written
permission** to test — typically through a published bug-bounty program or a
signed engagement. It enforces scope by design, but *the operator carries the
legal responsibility for every test they authorize*.

In practice this means:

* **Read the program's policy.** Enforcement is only as good as the scope file
  you feed it. Import, then review the JSON by hand.
* **Respect safe harbour.** Only test programs that offer it, and stay strictly
  inside the published scope and rules.
* **Never authorize a test you cannot justify.** The `approvals` mechanism
  exists so that a human signs off on anything with side effects; do not treat
  it as a formality.
* **Minimal proof only.** Take the least evidence that proves the finding.
  Bounty Mode redacts secrets and PII automatically — do not disable that.
* **No destructive testing.** Denial of service, resource exhaustion and
  rate-limit abuse are prohibited by nearly every program. Bounty Mode blocks
  them unconditionally; do not work around it.
* **Disclose responsibly.** Follow the program's embargo. Do not publish
  before the agreed disclosure window.
* **No data retention beyond the finding.** Delete captured evidence once the
  report is accepted and paid.
* **Jurisdiction matters.** Computer-misuse law varies. Get legal advice if you
  are unsure whether a test is permitted.

Unauthorized access to computer systems is a criminal offence in most
jurisdictions. Using this tool without authorization is not a defence.

---

## Requirements and environment

| Item | Requirement |
|---|---|
| Python | 3.9 – 3.12 (CI matrix covers all four) |
| Runtime dependencies | none |
| Optional | `PyYAML` for `.yaml`/`.yml` policies and case files |
| Dev | `pytest` |
| Network | not required except for `run --live` |
| Environment variables | `INTERNAL_SCAN_TOKEN` (only for live runs; never commit it) |

`.gitignore` excludes `.env`, key material, and run artifacts. **Never commit
credentials.** If you fork this, check that no secret file came along.

---

## License

MIT — see [LICENSE](LICENSE). The bundled Agathon engine keeps its own license
terms; check it before redistribution.

---

## Status

**v0.1.0.** Scope, gate, evidence, triage, de-duplication, reports, runner and
CLI are implemented and tested. The engine bridge is implemented against the
`AttackResult` contract and exercised with fakes. Multimodal (image/audio) and
supply-chain (SBOM / dependency) technique classes are catalogued but not yet
wired to engine modules.
