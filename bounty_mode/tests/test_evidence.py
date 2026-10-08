"""Tests for the redactor and evidence vault."""

from __future__ import annotations

import json

from bountymode.evidence.redactor import Redactor, redact
from bountymode.evidence.vault import EvidenceVault
from bountymode.models import Finding


def _finding(**kw) -> Finding:
    base = dict(
        id="F-test1",
        title="Test finding",
        technique_id="prompt_injection",
        target="api.acme.com",
        category="data_exfiltration",
    )
    base.update(kw)
    return Finding(**base)


# --- redactor: credentials ------------------------------------------------- #

def test_redacts_openai_key():
    r = Redactor().redact("key=sk-abcdefghijklmnopqrstuvwxyz012345")
    assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in r.text
    assert "[REDACTED:openai_key]" in r.text
    assert r.count == 1


def test_redacts_anthropic_and_groq_keys():
    out = redact("a=sk-ant-abcdefghijklmnop123456 b=gsk_abcdefghijklmnopqrst")
    assert "sk-ant-abcdefghijklmnop123456" not in out
    assert "gsk_abcdefghijklmnopqrst" not in out


def test_redacts_aws_access_key():
    out = redact("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_redacts_github_token():
    out = redact("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert "ghp_" not in out


def test_redacts_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    out = redact(f"Authorization: Bearer {jwt}")
    assert jwt not in out


def test_redacts_password_field():
    out = redact('{"password": "hunter2secret", "user": "bob"}')
    assert "hunter2secret" not in out
    assert "[REDACTED:password_field]" in out


def test_redacts_api_key_field():
    out = redact('{"api_key": "abcd1234efgh"}')
    assert "abcd1234efgh" not in out


def test_redacts_connection_string():
    out = redact("postgres://user:pass@db.internal:5432/app")
    assert "[REDACTED:connection_string]" in out


def test_redacts_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    out = redact(pem)
    assert "MIIEowIBAAKCAQEA" not in out
    assert "[REDACTED:private_key]" in out


# --- redactor: personal data ---------------------------------------------- #

def test_redacts_email_by_default():
    out = redact("contact admin@example.com now")
    assert "admin@example.com" not in out
    assert "[REDACTED:email]" in out


def test_redacts_ssn_and_credit_card():
    out = redact("ssn 123-45-6789 card 4111 1111 1111 1111")
    assert "123-45-6789" not in out
    assert "4111 1111 1111 1111" not in out


def test_phone_and_private_ip_are_opt_in():
    text = "call +1 415 555 0100 from 10.0.0.5"
    assert "415 555 0100" in redact(text)  # phone off by default
    on = redact(text, {"phone": True, "private_ip": True})
    assert "415 555 0100" not in on
    assert "10.0.0.5" not in on


# --- redactor: behaviour --------------------------------------------------- #

def test_redactor_is_deterministic():
    text = "sk-abcdefghijklmnopqrstuvwxyz012345 admin@x.com"
    assert redact(text) == redact(text)


def test_by_category_counts():
    r = Redactor().redact("a@b.com c@d.com")
    assert r.by_category()["email"] == 2


def test_empty_text_is_safe():
    assert redact("") == ""


def test_redaction_never_includes_the_secret_in_preview():
    secret = "sk-abcdefghijklmnopqrstuvwxyz012345"
    r = Redactor().redact(secret)
    assert all(secret not in red.preview for red in r.redactions)


# --- vault ----------------------------------------------------------------- #

def test_vault_persists_redacted_evidence_and_verifies_chain(tmp_path):
    vault = EvidenceVault(str(tmp_path / "evidence"))
    f = _finding()
    secret = "sk-abcdefghijklmnopqrstuvwxyz012345"

    obs = vault.capture(
        f,
        request=f'{{"api_key": "{secret}"}}',
        response=f"here it is: {secret} and admin@acme.com",
        url="api.acme.com/v1/chat",
        status=200,
    )

    assert secret not in obs.response
    assert "admin@acme.com" not in obs.response
    assert obs.redactions >= 2
    assert obs.sha256
    assert vault.verify_chain() is True

    # nothing sensitive anywhere on disk
    for p in (tmp_path / "evidence").rglob("*.json"):
        assert secret not in p.read_text(encoding="utf-8")
        assert "admin@acme.com" not in p.read_text(encoding="utf-8")


def test_vault_appends_observations_to_finding(tmp_path):
    vault = EvidenceVault(str(tmp_path / "ev"))
    f = _finding()
    vault.capture(f, request="a", response="b")
    vault.capture(f, request="c", response="d")
    assert len(f.observations) == 2
    assert len(vault.entries) == 2


def test_vault_chain_detects_tampering(tmp_path):
    vault = EvidenceVault(str(tmp_path / "ev"))
    f = _finding()
    vault.capture(f, request="a", response="b")
    vault.capture(f, request="c", response="d")
    assert vault.verify_chain()

    vault.entries[0].hash = "0" * 64  # simulate an edit
    assert vault.verify_chain() is False


def test_vault_writes_chain_ledger(tmp_path):
    vault = EvidenceVault(str(tmp_path / "ev"))
    f = _finding()
    vault.capture(f, request="a", response="b")

    chain = json.loads((tmp_path / "ev" / "chain.json").read_text())
    assert chain["count"] == 1
    assert chain["entries"][0]["finding_id"] == f.id


def test_vault_attach_note(tmp_path):
    vault = EvidenceVault(str(tmp_path / "ev"))
    f = _finding()
    note = vault.attach_note(f, "observed via UI at 12:00 UTC")
    assert note.kind == "note"


def test_vault_finding_bundle_is_serialisable(tmp_path):
    vault = EvidenceVault(str(tmp_path / "ev"))
    f = _finding()
    vault.capture(f, request="a", response="b")
    bundle = vault.finding_bundle(f)
    json.dumps(bundle)  # must not raise
    assert bundle["chain_verified"] is True
