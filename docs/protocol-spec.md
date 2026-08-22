# Protocol Specification

## 1. Purpose

Agent Guardian is an authorization and security layer for autonomous financial agents. It separates probabilistic security intelligence from deterministic execution authority.

## 2. Trust boundaries

### Agent

The agent proposes an exact operation and signs an execution intent. The agent is not trusted with unrestricted wallet authority.

### Guardian intelligence

The off-chain Guardian evaluates risk using wallet intelligence, reputation, simulation, threat intelligence and policy context. Its output is evidence for authorization, not authorization itself.

### Execution Guard

The on-chain Execution Guard is the final authorization boundary. It validates identity, policy, signature, nonce, deadline and exact transaction parameters before execution.

### Underlying chain

Arbitrum or Robinhood Chain executes only after the guard accepts the intent.

## 3. Intent

An execution intent is bound to:

- agent identity
- controlled wallet
- chain ID
- execution guard address
- target contract
- native value
- exact calldata hash
- nonce
- deadline
- policy hash

The authorization digest must use EIP-712 domain separation so signatures cannot be replayed across chains or execution guards.

## 4. Policy commitment

A policy is represented by a canonical versioned document off-chain and a cryptographic `policyHash` on-chain. The signed intent commits to that exact policy hash.

Changing policy therefore does not silently change the meaning of an already signed intent.

## 5. Financial mandate

A mandate defines the maximum authority delegated to an agent. Examples include:

- allowed assets
- allowed target contracts
- allowed function selectors
- maximum single transaction amount
- daily spending limit
- approval threshold
- active period

Authority and risk are separate dimensions. A low-risk action outside the mandate remains unauthorized.

## 6. Execution flow

```text
intent
  -> signature verification
  -> agent status
  -> policy status
  -> deadline
  -> nonce
  -> mandate checks
  -> exact target/value/calldata checks
  -> optional Guardian evidence / approval
  -> execution
```

## 7. Approval

A high-risk but otherwise authorized action may require explicit approval. Approval may only satisfy the configured approval condition; it must not silently expand the agent's underlying mandate.

## 8. Replay protection

Every successful intent consumes its nonce. EIP-712 domain separation binds the signature to the chain and verifying contract. Expired intents are rejected.

## 9. Risk model

Risk signals may be probabilistic and may include AI-assisted analysis. Risk output never substitutes for deterministic authorization.

## 10. Required invariants

See the invariant list in the root README. Each invariant must have at least one regression test and, where practical, a fuzz/property test before deployment.

## 11. Gate 2 implementation status

`AgentExecutionGuard` (Gate 2) implements sections 3, 6 (partially), and 8
as actually deployed code — the rest of section 6's flow (policy status,
mandate checks, approval) remains specification only, not yet
implemented. Concretely, `AgentExecutionGuard.execute` currently checks,
in this order: deadline, live `AgentRegistry.isActiveAgent` status,
nonce, EIP-712 signature — then consumes the nonce and performs the
external call atomically (the whole transaction reverts, nonce included,
if the call fails). See `docs/gate-2-execution-guard.md` for the full
report and `docs/adr/0002-monotonic-per-agent-nonce.md` for why the nonce
is a monotonic per-agent counter rather than a bitmap.

Not yet implemented, and must not be assumed present by anything
integrating with this contract: `policyHash` is accepted and bound into
the signature (so it cannot be forged or altered later) but is not yet
checked against any on-chain policy state — that is PolicyRegistry, a
later gate. No mandate/spending-limit checks exist. No approval flow
exists. This contract does not custody funds; `value` forwarded through
`execute` is funded by the caller's `msg.value` for that transaction
only.
