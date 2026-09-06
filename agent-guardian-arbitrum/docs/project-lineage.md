# Project Lineage

Agent Guardian is the next iteration of an ongoing line of agent-security engineering work. The earlier repositories remain unchanged and independently inspectable.

## 1. Agentic Wallet Guardian v3

Repository: https://github.com/rudimentall1/agentic-wallet-guardian-v3

The v3 system established the off-chain security intelligence foundation: wallet analysis, risk fusion, reputation, security memory, policy evaluation, explainable decisions, simulation, MCP and API integration.

### Reused concepts

- wallet intelligence
- risk fusion
- reputation
- security memory
- explainable decisions
- simulation
- policy evaluation
- agent-facing API/MCP patterns

### Re-engineered for this project

The original decision layer is advisory. Agent Guardian separates it from deterministic execution authorization and binds authorization to an exact signed intent and policy commitment.

## 2. Agent Guardrail

Repository: https://github.com/rudimentall1/agent-guardrail

Guardrail explored deterministic controls around agent actions and the limitation of relying only on an agent-side guardrail.

### Reused concepts

- explicit action guardrails
- fail-closed policy thinking
- side-effect boundaries

### Re-engineered for this project

The critical financial boundary moves to an on-chain execution guard so an agent cannot obtain additional authority merely by bypassing an off-chain or MCP-level call.

## 3. AttestGuard

Repository: https://github.com/rudimentall1/AttestGuard

AttestGuard explored cryptographic attestation, proof verification, Solidity policy gates and circuit-breaker controls.

### Reused concepts

- cryptographic evidence
- proof verification
- on-chain policy enforcement
- emergency controls

### Re-engineered for this project

Attestation becomes evidence within a larger authorization protocol. It does not independently grant unlimited execution authority.

## 4. This repository

`agent-guardian-arbitrum` combines those lessons into a new execution-security model for autonomous financial agents.

The central design change is:

```text
risk intelligence != authorization

AI recommendation != execution permission

agent wallet access != unrestricted authority
```

The new system introduces financial mandates, signed intents, EIP-712 domain separation, policy commitments, replay protection, deterministic execution controls and chain adapters for Arbitrum and Robinhood Chain.

## Engineering principle

The project history is intentionally preserved through independent repositories rather than rewritten into a single artificial history. This repository documents the actual lineage and the technical reasons for each major architectural change.
