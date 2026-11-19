"""Deterministic, fail-closed policy gate proof of concept.

IMPORTANT: evidence must originate from a trusted telemetry collector, never
from the AI agent proposing an action. This module makes no cloud API calls and
never executes infrastructure changes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

POLICY_VERSION = "mvp-0.1"
MAX_EVIDENCE_AGE_SECONDS = 300
CLOUD = "aws"
ENVIRONMENTS = {"sandbox", "dev", "staging", "prod"}
READ_ONLY = {"describe_route_table": "rtb-", "describe_security_groups": "sg-"}
CHANGES = {"replace_route": "rtb-", "revoke_security_group_ingress": "sg-"}
RESOURCE_PATTERN = re.compile(r"^(?:rtb|sg)-[0-9a-f]{8,17}$")
PROPOSAL_FIELDS = {"cloud", "environment", "action", "resource_id", "rollback_plan_ref"}
EVIDENCE_FIELDS = {"cloud", "resource_id", "age_seconds", "resource_exists", "rollback_tested", "canary_status"}


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason_code: str
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _decision(outcome: str, reason: str) -> Decision:
    return Decision(outcome=outcome, reason_code=reason)


def evaluate(proposal: Mapping[str, Any], evidence: Mapping[str, Any]) -> Decision:
    """Evaluate a proposed AWS action using separately obtained trusted evidence.

    No actor can authorize execution by setting a flag in proposal.
    Mutations are never automatically permitted in this MVP.
    """
    if not isinstance(proposal, dict) or set(proposal) != PROPOSAL_FIELDS:
        return _decision("DENY", "INVALID_PROPOSAL_SCHEMA")
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS:
        return _decision("DENY", "INVALID_EVIDENCE_SCHEMA")

    cloud, env, action, resource = (
        proposal["cloud"], proposal["environment"], proposal["action"], proposal["resource_id"]
    )
    rollback_ref = proposal["rollback_plan_ref"]
    if not all(isinstance(v, str) for v in (cloud, env, action, resource)):
        return _decision("DENY", "INVALID_PROPOSAL_TYPES")
    if rollback_ref is not None and (not isinstance(rollback_ref, str) or len(rollback_ref) > 256):
        return _decision("DENY", "INVALID_ROLLBACK_REFERENCE")
    if cloud != CLOUD or env not in ENVIRONMENTS:
        return _decision("DENY", "UNSUPPORTED_SCOPE")
    if not RESOURCE_PATTERN.fullmatch(resource):
        return _decision("DENY", "INVALID_RESOURCE_ID")

    if action in READ_ONLY:
        required_prefix = READ_ONLY[action]
    elif action in CHANGES:
        required_prefix = CHANGES[action]
    else:
        return _decision("DENY", "ACTION_NOT_ALLOWLISTED")
    if not resource.startswith(required_prefix):
        return _decision("DENY", "ACTION_RESOURCE_MISMATCH")

    age = evidence["age_seconds"]
    if (evidence["cloud"] != cloud or evidence["resource_id"] != resource
            or type(age) is not int or not 0 <= age <= MAX_EVIDENCE_AGE_SECONDS
            or evidence["resource_exists"] is not True
            or type(evidence["rollback_tested"]) is not bool
            or evidence["canary_status"] not in ("not_run", "passed", "failed")):
        return _decision("DENY", "UNTRUSTED_OR_STALE_EVIDENCE")

    if action in READ_ONLY:
        return _decision("ALLOW", "READ_ONLY_VALIDATED")

    if env == "prod":
        return _decision("DENY", "PRODUCTION_MUTATIONS_DISABLED")
    if not rollback_ref or not rollback_ref.strip() or evidence["rollback_tested"] is not True:
        return _decision("DENY", "ROLLBACK_NOT_VERIFIED")
    if evidence["canary_status"] == "failed":
        return _decision("DENY", "CANARY_FAILED")
    if evidence["canary_status"] == "not_run":
        return _decision("CANARY_REQUIRED", "AWAITING_CANARY_VALIDATION")
    return _decision("HUMAN_APPROVAL_REQUIRED", "CANARY_PASSED_APPROVAL_REQUIRED")
