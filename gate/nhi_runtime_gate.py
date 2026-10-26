"""
NHI Runtime Decision-Rights Gate. Reference implementation.

Pairs with the AISVS action-class reference. Where AISVS C9.2.3 says
'the action class is declared in the manifest and evaluated by a
deterministic gate, not derived from agent runtime output', this gate
adds the identity-side check: 'the calling NHI is the one declared,
the token is fresh, the audience is correct, and the action is
permitted for this NHI.'

This is a minimal reference. Production deployments will wire this
into actual JWT verification, JWKS rotation, SPIFFE SVID validation,
and audit logging.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Optional


class ActionClass(Enum):
    READ_ONLY = "read_only"
    REVERSIBLE = "reversible"
    EXTERNAL_REVERSIBLE = "external_reversible"
    IRREVERSIBLE = "irreversible"


class IdentityRefused(Exception):
    """Raised when the NHI gate refuses an action for identity or token reasons."""


@dataclass
class TokenClaims:
    """Minimal token claim set the gate checks. In practice this comes from a verified JWT."""

    issuer: str
    subject: str
    audience: str
    issued_at_epoch: int

    def age_seconds(self, now_epoch: Optional[int] = None) -> int:
        now = now_epoch if now_epoch is not None else int(time.time())
        return now - self.issued_at_epoch


class NHIRuntimeGate:
    def __init__(self, manifest_path: str | Path) -> None:
        manifest_path = Path(manifest_path)
        with manifest_path.open("r", encoding="utf-8") as f:
            self.manifest = json.load(f)
        self.nhi_id: str = self.manifest["nhi_id"]
        self.identity_provenance = self.manifest["identity_provenance"]
        self._permitted: Dict[str, dict] = {
            entry["action"]: entry for entry in self.manifest["permitted_actions"]
        }

    def verify_identity(self, claims: TokenClaims, now_epoch: Optional[int] = None) -> None:
        """Refuse if the calling identity does not match the declared provenance."""
        expected_issuer = self.identity_provenance.get("issuer")
        if claims.issuer != expected_issuer:
            raise IdentityRefused(
                f"Issuer mismatch. Expected '{expected_issuer}', got '{claims.issuer}'."
            )

        expected_subject = self.identity_provenance.get("subject")
        if claims.subject != expected_subject:
            raise IdentityRefused(
                f"Subject mismatch. Expected '{expected_subject}', got '{claims.subject}'."
            )

        expected_audience = self.identity_provenance.get("audience")
        if expected_audience is not None and claims.audience != expected_audience:
            raise IdentityRefused(
                f"Audience mismatch. Expected '{expected_audience}', got '{claims.audience}'."
            )

        max_age = self.identity_provenance.get("max_age_seconds")
        if max_age is not None:
            age = claims.age_seconds(now_epoch)
            if age > max_age:
                raise IdentityRefused(
                    f"Token too old. Age {age}s exceeds max_age {max_age}s for "
                    f"NHI '{self.nhi_id}'."
                )

    def verify_action(self, action_name: str) -> ActionClass:
        """Refuse if the action is not permitted for this NHI."""
        if action_name not in self._permitted:
            raise IdentityRefused(
                f"Action '{action_name}' not permitted for NHI '{self.nhi_id}'. Refused."
            )
        return ActionClass(self._permitted[action_name]["class"])

    def evaluate(
        self,
        claims: TokenClaims,
        action_name: str,
        now_epoch: Optional[int] = None,
    ) -> ActionClass:
        """Run the full check. Returns the action class on pass, raises on refuse."""
        self.verify_identity(claims, now_epoch=now_epoch)
        return self.verify_action(action_name)
