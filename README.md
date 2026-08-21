# Agent Guardian

Security infrastructure for autonomous financial agents on Arbitrum and Robinhood Chain.

Agent Guardian gives autonomous agents programmable financial authority instead of unrestricted wallet control.

## Project status

Early protocol implementation. The repository is being built in security gates: protocol specification first, deterministic on-chain authorization second, Guardian intelligence integration third, and live chain deployment last.

This is intentionally not a copy of an earlier repository. The project reuses proven security concepts while introducing a new execution model for autonomous financial agents.

## Core model

```text
AI Agent
   |
   v
Signed Intent
   |
   v
Guardian Intelligence
   |-- risk
   |-- reputation
   |-- simulation
   |-- threat intelligence
   |
   v
Deterministic Execution Guard
   |-- agent identity
   |-- policy commitment
   |-- nonce
   |-- deadline
   |-- exact target/value/calldata
   |-- financial mandate
   |
   +-------> Arbitrum
   |
   +-------> Robinhood Chain
```

AI-generated analysis is advisory. Authorization is deterministic and enforced at the execution boundary.

## Project lineage

Agent Guardian builds on several earlier security-focused projects:

- [Agentic Wallet Guardian v3](https://github.com/rudimentall1/agentic-wallet-guardian-v3) — wallet intelligence, risk fusion, policy, reputation, security memory, simulation, explainable decisions, MCP/API infrastructure.
- [Agent Guardrail](https://github.com/rudimentall1/agent-guardrail) — deterministic agent-side guardrails and explicit enforcement concepts.
- [AttestGuard](https://github.com/rudimentall1/AttestGuard) — cryptographic attestation, proof verification, Solidity policy enforcement and circuit-breaker patterns.

The earlier repositories remain independent. This repository is the next protocol iteration and documents which ideas are reused, redesigned, and newly introduced.

## What is new here

- Agent financial mandates
- Signed execution intents
- EIP-712 domain separation
- Replay protection
- Policy commitments
- Deterministic execution authorization
- Explicit approval flows
- Arbitrum integration
- Robinhood Chain integration
- Adversarial and fuzz testing around authorization invariants

## Security invariants

The implementation must guarantee, at minimum:

1. An unregistered agent cannot execute.
2. A disabled agent cannot execute.
3. An invalid signature cannot execute.
4. An expired intent cannot execute.
5. A consumed nonce cannot execute twice.
6. An intent signed for another chain cannot execute here.
7. An intent signed for another execution guard cannot execute here.
8. Modified calldata invalidates authorization.
9. Modified target invalidates authorization.
10. Modified value invalidates authorization.
11. An inactive policy cannot authorize execution.
12. A policy version mismatch cannot authorize execution.
13. Execution outside a financial mandate reverts.
14. Emergency pause blocks execution.
15. Approval cannot expand authority beyond its defined scope.
16. An agent cannot bypass the execution guard within its delegated authority.

## Documentation

The protocol specification, threat model, architecture decisions, and project lineage will live under `docs/` as implementation progresses.

## Networks

The first target is Robinhood Chain testnet, followed by Arbitrum testnet integration and production-ready deployment only after the security gates pass.

## License

License will be selected before the first production release.