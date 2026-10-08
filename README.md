# Bounty Machine

An **authorized AI red-teaming engine** with a **bounty-grade workflow layer**
on top. The engine (`agathon/`, `attacks/`) does the offensive testing; the
workflow layer (`bounty_mode/`) turns its output into scope-compliant,
submittable bug-bounty reports.

> ⚠️ **Authorized security testing only.** Test systems you own or have
> explicit written permission to test, typically through a published
> bug-bounty program. Scope enforcement is built in, but the operator carries
> the legal responsibility for every test they authorize. See
> [`bounty_mode/README.md`](bounty_mode/README.md#legal-and-authorization-notice).

---

## Repository layout

```
.
├── agathon/             # the red-teaming engine (Brain, orchestrator, EVOLVE, sandbox)
├── attacks/             # 19 attack modules + 100-vector library + dynamic plugins
├── api/                 # FastAPI service surface (POST /scan/start, GET /scan/{id})
├── tests/               # engine tests
└── bounty_mode/         # ← the bounty workflow layer (this repo's new component)
    ├── bountymode/      # the pip-installable package
    ├── tests/           # 76 offline tests
    └── examples/        # policy, scope, case and finding examples
```

The two halves are independent: the engine can run alone, and the workflow
layer can drive **any** engine that speaks the `AttackResult` contract.

---

## Quickstart — the workflow layer

```bash
cd bounty_mode
pip install -e ".[dev]"

python -m bountymode techniques          # the 19-technique catalogue
python examples/demo_offline.py          # full pipeline, no network, no keys
python -m pytest -q                      # 76 tests, no credentials needed
```

Then point it at a real program:

```bash
python -m bountymode scope import examples/policy-example.md --program acme -o scope.json
python -m bountymode check scope.json api.acme.com --technique prompt_injection
python -m bountymode run examples/case-example.yaml -o bounty-run/acme-pass-1   # dry run
```

Full documentation, the CLI reference, the Python API, the architecture diagram
and the **real test results** live in
[`bounty_mode/README.md`](bounty_mode/README.md).

---

## What the workflow layer adds

| Component | Problem it solves |
|---|---|
| **Scope importer** | Policies are prose; testing needs machine-readable rules |
| **Authorization gate** | Deny-by-default: nothing runs without an in-scope target *and* a permitted technique |
| **Stop-conditions** | Kill switch, request/time/error budgets that latch |
| **Evidence vault** | Redacts secrets/PII before persist; hash-chains everything for integrity |
| **Triage scorer** | Real CVSS v3.1 + bounty weighting (cross-tenant > one-off jailbreak) |
| **Report generator** | HackerOne/Bugcrowd-shaped writeups + JSON submission payloads |
| **Dedup + retest** | Never submit a duplicate; verify a fix after remediation |

---

## Safety model

The layer enforces, by design:

1. **Scope** — target must resolve to an in-scope asset and match no exclusion.
2. **Technique policy** — disruptive classes (DoS / rate-limit exhaustion) are
   blocked for every program, even when the target is in scope.
3. **Minimal proof** — the vault redacts 14 credential classes and 5
   personal-data classes; nothing sensitive is written to disk.
4. **Human in the loop** — any side-effecting technique requires an audited
   approval registered with the gate.
5. **Dry run by default** — `run` contacts a target only with an explicit
   `--live`.

---

## Testing

```
76 passed in 0.15s        # bounty_mode/tests, Python 3.11, offline
```

What is verified (and what is not) is stated precisely in the
[Testing section](bounty_mode/README.md#testing) — including the explicit
limitation that **no live scan against a real target was executed** in the
environment this was built in.

---

## License

`bounty_mode/` is MIT (see [`bounty_mode/LICENSE`](bounty_mode/LICENSE)).
The engine under `agathon/`, `attacks/` and `api/` retains its own license;
check it before redistribution.
