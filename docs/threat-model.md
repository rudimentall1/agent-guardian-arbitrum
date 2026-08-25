# Threat Model

## Assets

- controlled wallet funds
- agent authority
- policy integrity
- authorization signatures
- nonces
- execution configuration
- Guardian security evidence

## Adversaries

The design considers an attacker who can:

- control or compromise an agent process
- replay a previously signed intent
- alter calldata, target or value
- submit an intent on another chain
- attempt to use a revoked agent or policy
- exploit approval flows
- manipulate off-chain risk inputs
- bypass an agent-side/MCP guardrail
- exploit contract logic or authorization state transitions

## Security boundary

The critical boundary is the on-chain Execution Guard. Off-chain components can be unavailable, wrong, stale or compromised without directly granting additional financial authority.

## Required properties

1. Authorization is cryptographically bound to the exact intent.
2. Authorization is bound to chain and verifying contract.
3. Every intent has replay protection.
4. Expired authorization cannot execute.
5. Policy revocation takes effect at the execution boundary.
6. Agent deactivation takes effect at the execution boundary.
7. Financial limits are checked deterministically.
8. Approval cannot silently widen authority.
9. Emergency pause blocks the protected execution path.
10. Off-chain AI output cannot directly authorize execution.

## Out of scope for the first protocol version

- security of arbitrary third-party protocols called by an authorized transaction
- compromise of the underlying blockchain consensus
- compromised owner keys outside the protocol's delegated-authority model
- economic attacks against external markets

These boundaries will be refined as implementation and adversarial testing progress.

## Gate 1 status (AgentRegistry)

`AgentRegistry` is implemented and adversarially tested — see
`docs/gate-1-agent-registry.md` for the full report. One limitation
carried forward explicitly rather than silently: registration signatures
are verified with plain ECDSA recovery only. An agent or owner address
that is itself a smart-contract wallet (ERC-1271) cannot currently
register or be registered as an agent identity — `ECDSA.recover` has no
path to call `isValidSignature` on a contract. This is out of scope for
Gate 1 and must be resolved (either by adding ERC-1271 support via
OpenZeppelin's `SignatureChecker`, or by an explicit documented
restriction to EOA agent keys) before Gate 2 assumes agent identities can
be anything other than EOAs.

## Gate 2 status (AgentExecutionGuard)

`AgentExecutionGuard` is implemented and adversarially tested — see
`docs/gate-2-execution-guard.md` for the full report. Against the
"Required properties" list above, Gate 2 satisfies 1–4 and 6: exact
intent binding, chain/contract domain separation, nonce-based replay
protection, deadline enforcement, and live agent-deactivation
enforcement (checked against `AgentRegistry.isActiveAgent` on every
call, not cached at signing time).

**Not yet satisfied, and not to be assumed present:**

- Property 5 (policy revocation) and property 7 (financial limits) —
  `policyHash` is bound into the signature so it can't be forged, but
  nothing yet checks it against live policy state, and there are no
  spending/mandate checks at all. This is PolicyRegistry, a later gate.
- Property 8 (approval cannot widen authority) — no approval flow exists
  yet.
- Property 9 (emergency pause) — `AgentExecutionGuard` has no pause
  mechanism of its own. The only way to stop a specific agent today is
  `AgentRegistry.deactivate`, which is agent-scoped, not protocol-wide.
  A protocol-wide emergency stop (e.g. pausing the guard itself) does not
  exist and must be an explicit decision in a later gate, not retrofitted
  silently.
- ERC-1271 (ADR carried over from Gate 1): `AgentExecutionGuard.execute`
  also uses plain `ECDSA.recover` for intent signatures, inheriting the
  same EOA-only limitation.

New trust assumption introduced by Gate 2, made explicit rather than
assumed: `AgentRegistry.transferAgentOwnership` does not rotate or
invalidate the agent's underlying signing key — only its `active` flag
and `owner`. A previously-authorized operator who retains the agent's
private key can still produce valid `AgentExecutionGuard` intents after
an ownership transfer, as soon as the new owner calls `reactivate`,
unless the new owner separately arranges for a fresh agent key to be
registered instead. This is a business-process trust boundary outside
what either contract's cryptography can enforce, and is covered by a
regression test in `contracts-test/AgentExecutionGuard.integration.test.ts`.

## Gate 3 status (PolicyRegistry)

`PolicyRegistry` is implemented and adversarially tested — see
`docs/gate-3-policy-registry.md` for the full report. As originally
shipped, `PolicyRegistry` and `AgentExecutionGuard` did not talk to each
other at all — a signed intent's `policyHash` field was accepted and
bound into the signature but never checked against any registry state.
See the remediation gate below for the first piece of that integration.

## Remediation gate status (pre-Gate-4)

Two architectural gaps were found by examining Gate 2 and Gate 3
together and fixed before Gate 4: see
`docs/adr/0004-msg-value-and-policy-agent-binding.md` and
`docs/gate-remediation-msg-value-policy-binding.md` for full detail.

1. **`msg.value` was not bound to the signed intent's `value` field.** A
   caller could send arbitrary native currency regardless of what the
   agent actually signed for; the guard now reverts unless
   `msg.value == value` exactly.
2. **A `policyHash` was not bound to any specific agent.** Nothing
   prevented Agent A's intent from referencing a policy that
   `PolicyRegistry` had recorded as belonging to Agent B — the mere fact
   that *a* valid, active policy existed for *some* agent was previously
   sufficient to reference it from any intent, since Gate 2 didn't check
   `policyHash` against `PolicyRegistry` at all. `PolicyRegistry` now
   records a single agent per policy at creation, and
   `AgentExecutionGuard.execute` rejects any intent whose `policyHash`
   does not resolve to the intent's own `agent`.

Explicitly **not** addressed by this remediation gate — still open going
into Gate 4: `maxTxValue`/target/selector enforcement inside
`AgentExecutionGuard` itself (currently only `PolicyRegistry`'s own view
function checks these, unconnected to actual execution), `dailyLimit` and
`approvalThreshold` accounting, and any approval flow.

## Gate 4A status: call authorization

`AgentExecutionGuard` now enforces `maxTxValue` and paired
`(target, selector)` authorization — see
`docs/adr/0005-paired-target-selector-authorization.md` and
`docs/gate-4a-call-authorization.md`. Against the "Required properties"
list at the top of this document: property 7 (financial limits checked
deterministically) is now partially satisfied — `maxTxValue` is
enforced; `dailyLimit` is still not.

**A real vulnerability closed by this gate, not merely a missing
feature:** Gate 3's independent `allowedTargets`/`allowedSelectors`
allow-lists authorized their full Cartesian product. A policy owner who
authorized `(tokenA, transfer)` and `(tokenB, approve)` had, without
realizing it, also authorized `(tokenA, approve)` and `(tokenB,
transfer)`. This was a real privilege-escalation bug in the Gate 3
design, discovered before any deployment and fixed structurally (a
single paired-key mapping cannot express independent-list semantics at
all) rather than patched with an additional check.

**A second, related collision found and fixed during this gate's own
design review** (not by testing a shipped draft — see
`docs/gate-4a-call-authorization.md` section 8 for the full account):
an early draft of the calldata-classification logic defaulted
1–3-byte ("malformed") calldata to `selector = bytes4(0)`, which would
have meant a policy authorizing the real function selector `0x00000000`
also silently authorized any malformed short calldata sent to that
target. Fixed by making `Malformed` a structurally distinct
classification with no mapping lookup at all, rather than a value that
could coincide with a real selector.

**Still not enforced, going into Gate 4B:** `dailyLimit` and
`approvalThreshold` accounting, and any approval flow. **Explicitly out
of scope, not silently assumed:** argument-level authorization — a
policy authorizing a function selector on a target says nothing about
which specific arguments are permitted; only the signed `calldataHash`
constrains the actual argument bytes used, unchanged since Gate 2.

## P1: policy-owner authorization (Critical, confirmed exploitable, fixed)

**A real, confirmed vulnerability**, not a design limitation: Gate 4A
established `policyHash -> agent` binding but never verified that the
policy was authorized by the legitimate owner/controller of that agent.
`PolicyRegistry.createPolicy` is permissionless — a malicious or
compromised agent could call it directly, using only its own
already-possessed signing key, name itself as both `owner` and `agent`,
grant itself an arbitrarily permissive mandate, and sign a valid
`ExecutionIntent` referencing that self-created policy instead of
whatever restrictive policy its legitimate owner actually created. Every
prior check (`isActiveAgent`, `PolicyAgentMismatch`, `PolicyNotActive`,
`withinWindow`, `valueAllowed`, `callAllowed`, nonce, signature) was
satisfiable this way — none of them asked *who* created the policy.

**Confirmed exploitable** by a real adversarial test against the actual
(non-mocked) `AgentRegistry` + `PolicyRegistry` + `AgentExecutionGuard`
stack before the fix — see `contracts-test/
P1PolicyOwnerAuthorization.poc.test.ts` and
`docs/adr/0006-policy-owner-authorization.md` for the full account.

**Fixed**: `AgentExecutionGuard.execute` now additionally requires the
policy's recorded `owner` to equal `AgentRegistry.ownerOf(intent.agent)`,
checked live, not cached from policy-creation time. `PolicyRegistry`
itself is unchanged — creation remains permissionless by design (see the
ADR for why permissioning creation would be strictly weaker than this
live check). New trust boundary made explicit: after an agent's
ownership transfers, ALL policies created under the old owner become
permanently unusable — including after the new owner reactivates the
agent — until the new owner creates their own policy. This is a
deliberate consequence of policy immutability (ADR-0003) combined with
live ownership verification, not an oversight, and mirrors the same
"stale authorization must not survive an ownership change" principle
already applied to agent activity.
