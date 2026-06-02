"""Tests for the NHI runtime decision-rights gate."""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate import (  # noqa: E402
    ActionClass,
    IdentityRefused,
    NHIRuntimeGate,
    TokenClaims,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "schema" / "examples"


def ci_gate():
    return NHIRuntimeGate(EXAMPLES / "ci-pipeline-token.json")


def wif_gate():
    return NHIRuntimeGate(EXAMPLES / "workload-identity-federation.json")


def valid_ci_claims(now: int) -> TokenClaims:
    return TokenClaims(
        issuer="token.actions.githubusercontent.com",
        subject="repo:example-org/example-app:ref:refs/heads/main",
        audience="https://deploy.example.com",
        issued_at_epoch=now - 60,
    )


def test_ci_pipeline_valid_token_can_deploy_to_staging():
    gate = ci_gate()
    now = int(time.time())
    claims = valid_ci_claims(now)
    cls = gate.evaluate(claims, "deploy_to_staging", now_epoch=now)
    assert cls == ActionClass.EXTERNAL_REVERSIBLE


def test_ci_pipeline_valid_token_can_deploy_to_prod_classified_irreversible():
    gate = ci_gate()
    now = int(time.time())
    claims = valid_ci_claims(now)
    cls = gate.evaluate(claims, "deploy_to_prod", now_epoch=now)
    assert cls == ActionClass.IRREVERSIBLE


def test_wrong_issuer_refused():
    gate = ci_gate()
    now = int(time.time())
    claims = TokenClaims(
        issuer="some-other-issuer",
        subject="repo:example-org/example-app:ref:refs/heads/main",
        audience="https://deploy.example.com",
        issued_at_epoch=now - 60,
    )
    with pytest.raises(IdentityRefused, match="Issuer mismatch"):
        gate.evaluate(claims, "fetch_artifact", now_epoch=now)


def test_wrong_subject_refused():
    gate = ci_gate()
    now = int(time.time())
    claims = TokenClaims(
        issuer="token.actions.githubusercontent.com",
        subject="repo:attacker-org/attacker-app:ref:refs/heads/main",
        audience="https://deploy.example.com",
        issued_at_epoch=now - 60,
    )
    with pytest.raises(IdentityRefused, match="Subject mismatch"):
        gate.evaluate(claims, "fetch_artifact", now_epoch=now)


def test_wrong_audience_refused():
    gate = ci_gate()
    now = int(time.time())
    claims = TokenClaims(
        issuer="token.actions.githubusercontent.com",
        subject="repo:example-org/example-app:ref:refs/heads/main",
        audience="https://attacker.example.com",
        issued_at_epoch=now - 60,
    )
    with pytest.raises(IdentityRefused, match="Audience mismatch"):
        gate.evaluate(claims, "fetch_artifact", now_epoch=now)


def test_stale_token_refused():
    gate = ci_gate()
    now = int(time.time())
    claims = TokenClaims(
        issuer="token.actions.githubusercontent.com",
        subject="repo:example-org/example-app:ref:refs/heads/main",
        audience="https://deploy.example.com",
        issued_at_epoch=now - 5000,
    )
    with pytest.raises(IdentityRefused, match="Token too old"):
        gate.evaluate(claims, "fetch_artifact", now_epoch=now)


def test_undeclared_action_refused():
    gate = ci_gate()
    now = int(time.time())
    claims = valid_ci_claims(now)
    with pytest.raises(IdentityRefused, match="not permitted"):
        gate.evaluate(claims, "delete_everything", now_epoch=now)


def test_wif_gate_read_only_action():
    gate = wif_gate()
    now = int(time.time())
    claims = TokenClaims(
        issuer="spiffe://example.org",
        subject="spiffe://example.org/ns/prod/sa/api",
        audience="https://cloud-api.example.com",
        issued_at_epoch=now - 30,
    )
    cls = gate.evaluate(claims, "read_cloud_object", now_epoch=now)
    assert cls == ActionClass.READ_ONLY
