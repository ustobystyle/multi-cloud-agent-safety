# Architecture Overview

## High-Level Design

## Key Principles

- **No LLM in the execution path**  
  The language model only proposes. All decisions are made by deterministic rules.

- **Fail-closed by default**  
  Unknown or ambiguous actions are denied.

- **Reversible first**  
  Prefer actions that can be rolled back quickly.

- **Full auditability**  
  Every decision and action is logged with context.

## Components (Planned)

- `collectors/` : Multi-cloud telemetry ingestion (AWS, GCP, Azure)
- `policy/` : Deterministic policy definitions and evaluation engine
- `diagnosis/` : Validation of agent hypotheses against real infrastructure state
- `executor/` : Safe application of approved changes
- `audit/` : Immutable logging of all decisions

## Next Steps

1. Implement basic policy evaluation engine
2. Add initial telemetry collectors
3. Build cross-cloud network partition detection
4. Integrate with Devin Bots for rapid iteration
