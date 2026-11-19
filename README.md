# Multi-Cloud AI Agent Safety + Auto-Healer

A deterministic safety layer for AI agents operating on real infrastructure.

## Problem
Autonomous AI agents (including coding agents like Devin) can propose powerful infrastructure changes. Letting an LLM directly execute those changes is dangerous — hallucinations can lead to misconfigurations, network partitions, or worse.

## Solution
This project separates **proposal** from **execution**:

- The AI agent can freely reason and propose actions
- A **deterministic policy engine** evaluates every proposed action against real telemetry and topology
- Only explicitly allowed, reversible, and low-risk actions can proceed
- High-risk changes require canary execution or human approval

## Core Architecture

1. **Telemetry Collectors**  
   Gather data from AWS, GCP, and Azure (VPC Flow Logs, network metrics, routing tables, etc.)

2. **Diagnosis Layer**  
   Combines agent hypotheses with deterministic validation against actual infrastructure state

3. **Policy Gate**  
   Fail-closed, allowlist-first decision engine. No LLM in the execution path.

4. **Safe Execution**  
   Only approved actions are applied, with full audit logging

## Current Status
This repository is the starting point.  
The goal is to use Devin Bots to rapidly expand the system into a production-ready multi-cloud auto-healer.

## Roadmap
- [ ] Deterministic policy engine core
- [ ] Multi-cloud telemetry ingestion
- [ ] Cross-cloud network partition detection
- [ ] Safe auto-remediation workflows
- [ ] Full audit trail & observability

## License
MIT
