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
