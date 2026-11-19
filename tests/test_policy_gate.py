"""Run with python -m unittest discover -s tests -v (standard library only)."""

import json
import tempfile
import unittest
from pathlib import Path

from audit import append_decision, verify_log
from policy_gate import evaluate


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.proposal = {
            "cloud": "aws", "environment": "dev", "action": "describe_route_table",
            "resource_id": "rtb-0123456789abcdef0", "rollback_plan_ref": None,
        }
        self.evidence = {
            "cloud": "aws", "resource_id": "rtb-0123456789abcdef0",
            "age_seconds": 10, "resource_exists": True,
            "rollback_tested": False, "canary_status": "not_run",
        }

    def assert_outcome(self, expected):
        self.assertEqual(evaluate(self.proposal, self.evidence).outcome, expected)

    def test_read_only_allow(self):
        self.assert_outcome("ALLOW")

    def test_missing_evidence_denied(self):
        self.evidence.pop("age_seconds")
        self.assert_outcome("DENY")

    def test_stale_evidence_denied(self):
        self.evidence["age_seconds"] = 301
        self.assert_outcome("DENY")

    def test_future_evidence_denied(self):
        self.evidence["age_seconds"] = -1
        self.assert_outcome("DENY")

    def test_boolean_age_denied(self):
        self.evidence["age_seconds"] = True
        self.assert_outcome("DENY")

    def test_resource_mismatch_denied(self):
        self.evidence["resource_id"] = "rtb-aaaaaaaaaaaaaaaaa"
        self.assert_outcome("DENY")

    def test_unknown_action_denied(self):
        self.proposal["action"] = "delete_vpc"
        self.assert_outcome("DENY")

    def test_unsupported_cloud_denied(self):
        self.proposal["cloud"] = "azure"
        self.assert_outcome("DENY")

    def test_untrusted_approval_flag_denied(self):
        self.proposal["human_approved"] = True
        self.assert_outcome("DENY")

    def test_wrong_resource_for_action_denied(self):
        self.proposal["action"] = "describe_security_groups"
        self.assert_outcome("DENY")

    def make_mutation(self):
        self.proposal["action"] = "replace_route"
        self.proposal["rollback_plan_ref"] = "runbooks/revert-route-v1"
        self.evidence["rollback_tested"] = True

    def test_prod_mutation_denied(self):
        self.make_mutation()
        self.proposal["environment"] = "prod"
        self.evidence["canary_status"] = "passed"
        self.assert_outcome("DENY")

    def test_missing_rollback_denied(self):
        self.make_mutation()
        self.proposal["rollback_plan_ref"] = ""
        self.assert_outcome("DENY")

    def test_untested_rollback_denied(self):
        self.make_mutation()
        self.evidence["rollback_tested"] = False
        self.assert_outcome("DENY")

    def test_needs_canary(self):
        self.make_mutation()
        self.assert_outcome("CANARY_REQUIRED")

    def test_failed_canary_denied(self):
        self.make_mutation()
        self.evidence["canary_status"] = "failed"
        self.assert_outcome("DENY")

    def test_passed_canary_still_needs_human(self):
        self.make_mutation()
        self.evidence["canary_status"] = "passed"
        self.assert_outcome("HUMAN_APPROVAL_REQUIRED")

    def test_audit_hash_chain_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as dirname:
            target = Path(dirname) / "audit.jsonl"
            result = evaluate(self.proposal, self.evidence).to_dict()
            append_decision(target, self.proposal, result)
            append_decision(target, self.proposal, result)
            self.assertTrue(verify_log(target))
            lines = target.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[0])
            entry["record"]["decision"]["outcome"] = "DENY"
            lines[0] = json.dumps(entry)
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(verify_log(target))
            with self.assertRaises(ValueError):
                append_decision(target, self.proposal, result)


if __name__ == "__main__":
    unittest.main()
