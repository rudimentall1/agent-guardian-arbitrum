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

## 12. Gate 3 implementation status

`PolicyRegistry` implements the storage half of section 5 (financial
mandate) and the commitment half of section 4 (policy commitment): an
owner creates an immutable mandate (`maxTxValue`, `dailyLimit`,
`approvalThreshold`, `validFrom`/`validUntil`, allowed targets, allowed
selectors), gets back a deterministic `policyId` and a `policyHash`
committing to every field, and can revoke/reactivate the whole mandate
(coarse-grained; see `docs/adr/0003-immutable-policy-derived-identifier.md`).
A view function, `isCallAllowedByPolicy`, performs the *static* checks
(active, within time window, target allowed, selector allowed, value
within `maxTxValue`) that don't require execution-time state.

**Not yet implemented as of Gate 3:** `dailyLimit` and `approvalThreshold`
were stored but not enforced, and `AgentExecutionGuard` did not consult
`PolicyRegistry` at all. See section 13 — the remediation gate closes
part of that gap (agent-scoped policy binding); rolling-spend and
approval enforcement remain future work. See
`docs/gate-3-policy-registry.md` for Gate 3's own report.

## 13. Remediation gate status (pre-Gate-4)

Before Gate 4 (full mandate/approval integration), a dedicated
remediation gate closed two architectural gaps discovered by inspecting
Gate 2 and Gate 3 together rather than in isolation:

1. **`msg.value` binding.** `AgentExecutionGuard.execute` now requires
   `msg.value == value` exactly (the `value` field committed to in the
   signed intent). Previously, a caller could send more or less native
   currency than the signed intent authorized; excess ETH had no
   withdrawal path and would sit stuck in the contract, later spendable
   by an unrelated call whose own declared `value` happened to be
   coverable by that leftover balance. See
   `docs/adr/0004-msg-value-and-policy-agent-binding.md`.
2. **Policy ownership binding.** `PolicyRegistry.createPolicy` now takes
   an `agent` parameter and records which single agent a policy was
   created for. `AgentExecutionGuard.execute` looks up the agent bound to
   the intent's `policyHash` and reverts unless it matches `intent.agent`
   exactly — Agent A can never execute against a policy that was bound to
   Agent B. This is deliberately narrower than full mandate enforcement:
   `maxTxValue`/target/selector checks and `dailyLimit`/approval
   accounting remain Gate 4 scope. See the same ADR for why `policyHash`
   binding alone (without an agent check) was insufficient.

See `docs/gate-remediation-msg-value-policy-binding.md` for the full
report.

## 14. Gate 4A implementation status

`PolicyRegistry` and `AgentExecutionGuard` together now enforce two of
section 5's financial-mandate dimensions:

1. **`maxTxValue`** — `AgentExecutionGuard.execute` reverts with
   `MaxTxValueExceeded` if the intent's `value` exceeds the bound
   policy's `maxTxValue`, checked before nonce consumption.
2. **Target + selector authorization** — replaced Gate 3's independent
   `allowedTargets`/`allowedSelectors` lists (which accidentally
   authorized their full Cartesian product) with a single paired
   `(target, selector)` authorization primitive, plus a structurally
   separate native-transfer (`data.length == 0`) authorization
   dimension. See `docs/adr/0005-paired-target-selector-authorization.md`
   for the full design rationale and `docs/gate-4a-call-authorization.md`
   for the report.

**Still not enforced, unchanged from Gate 3:** `dailyLimit` and
`approvalThreshold` remain declared-only fields — no contract in this
repository tracks cumulative spend or routes high-value calls through an
approval flow. That is Gate 4B.

**Explicitly out of scope for Gate 4A, not silently assumed:**
argument-level authorization. A policy authorizing
`token.transfer(address,uint256)` on some target authorizes calling that
function, not any particular recipient or amount — the signed
`calldataHash` still binds the exact arguments used (unchanged since
Gate 2), but there is no allow-list over argument *values*. No ERC-20
accounting of any kind exists; `maxTxValue` concerns native ETH `value`
only.
