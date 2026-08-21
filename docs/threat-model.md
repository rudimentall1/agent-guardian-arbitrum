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
