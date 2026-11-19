"""Run a simulation with synthetic evidence. No cloud credentials required."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit import append_decision, verify_log
from policy_gate import evaluate


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated multi-cloud safety gate (AWS MVP)")
    parser.add_argument("--audit", default="demo-audit.jsonl", help="Path for local append-only demo log")
    args = parser.parse_args()
    proposal = {
        "cloud": "aws", "environment": "dev", "action": "replace_route",
        "resource_id": "rtb-0123456789abcdef0", "rollback_plan_ref": "runbooks/revert-route-v1",
    }
    # Synthetic collector data. In production this MUST be obtained independently.
    evidence = {
        "cloud": "aws", "resource_id": "rtb-0123456789abcdef0",
        "age_seconds": 12, "resource_exists": True,
        "rollback_tested": True, "canary_status": "passed",
    }
    decision = evaluate(proposal, evidence)
    digest = append_decision(args.audit, proposal, decision.to_dict())
    print(json.dumps({"simulation": True, "proposal": proposal,
                      "decision": decision.to_dict(), "audit_hash": digest,
                      "audit_verified": verify_log(Path(args.audit))}, indent=2))
    print("NO CLOUD API CALLS OR INFRASTRUCTURE MUTATIONS WERE PERFORMED")


if __name__ == "__main__":
    main()
