# Executable Policy Gate MVP

This MVP implements deterministic policy evaluation using synthetic AWS telemetry. It is not deployed and never calls cloud APIs or executes infrastructure changes.

Run tests with `python -m unittest discover -s tests -v` and demo with `python demo.py --audit demo-audit.jsonl`.

Decision states: ALLOW for allowlisted read-only requests, DENY for invalid or unsafe requests, CANARY_REQUIRED for non-production changes lacking canary validation, and HUMAN_APPROVAL_REQUIRED after successful canary tests. No mutating action can return ALLOW.

The evidence input must come from trusted telemetry collectors, not an AI agent. The demo supplies synthetic evidence. Local audit hashes are tamper-evident against partial changes but not malicious whole-file rewrite.
