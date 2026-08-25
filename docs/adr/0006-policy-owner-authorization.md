# ADR-0006: Policy-owner authorization (P1 fix)

## Status

Accepted (post-Gate-4A P1 remediation).

## The vulnerability

`PolicyRegistry.createPolicy` is, and was always, permissionless: any
caller becomes the `owner` of the policy they create (`owner:
msg.sender`), and names an arbitrary `agent` address with no check that
the caller has any relationship to that agent. `AgentExecutionGuard`,
before this fix, verified only that a policy's recorded `agent` field
matched the intent's `agent` (`PolicyAgentMismatch`) — it never asked
*who* created the policy, or whether that creator was the agent's
legitimate controller.

This meant a malicious or compromised agent — using nothing but its own
already-possessed signing key, the same key it legitimately uses to sign
`ExecutionIntent`s — could call `PolicyRegistry.createPolicy` itself,
name itself as `agent`, become the policy's `owner`, and grant that
policy arbitrarily permissive `maxTxValue` and target/selector
authorizations. It could then sign a valid intent referencing this
self-created policy instead of whatever restrictive policy its
legitimate owner actually intended. Every existing check —
`isActiveAgent`, `PolicyAgentMismatch`, `PolicyNotActive`,
`withinWindow`, `valueAllowed`, `callAllowed`, nonce, signature — passes,
because every one of them was satisfiable using only the agent's own,
legitimately-possessed key. No signature forgery, no AgentRegistry
compromise, no cryptographic break of anything — the gap was a missing
authorization relationship, not a broken one.

**Confirmed exploitable** by a real, non-mocked adversarial test
(`contracts-test/P1PolicyOwnerAuthorization.poc.test.ts`) against the
actual `AgentRegistry` + `PolicyRegistry` + `AgentExecutionGuard` stack,
before this fix: a legitimate owner's 0.01 ETH-capped, narrowly-scoped
policy was completely bypassed by the agent's own self-created,
1000 ETH-capped policy authorizing an otherwise-unapproved target.

## Root cause

`policyHash -> agent` binding (established by the remediation gate) is
necessary but not sufficient. It proves a policy is *for* a given agent;
it says nothing about whether the policy's *content* reflects what that
agent's actual controller authorized. `PolicyRegistry` has no dependency
on `AgentRegistry` at all (a deliberate architectural choice — see
ADR-0004 — but one that left this specific gap unaddressed until now).

## Decision: live ownership verification in AgentExecutionGuard (Option B)

`AgentExecutionGuard.execute` now additionally requires:

```
PolicyRegistry's recorded policy.owner == AgentRegistry.ownerOf(intent.agent)
```

checked live, on every call, using `AgentRegistry`'s current state —
not a value cached or asserted at policy-creation time. `PolicyRegistry`
itself is **unchanged in its access control** — `createPolicy` remains
permissionless. `AgentRegistry` is unchanged entirely. The fix is
concentrated in the one place that already has (and needs) a dependency
on both registries: the execution guard.

### Alternatives considered

**Option A — require the caller to already be the agent's owner at
`createPolicy` time** (`PolicyRegistry` takes an `AgentRegistry`
dependency and checks `AgentRegistry.ownerOf(agent) == msg.sender`
inside `createPolicy`). Rejected. This checks ownership only once, at
creation — exactly the same class of problem the remediation gate
already fixed for agent activity (`isActiveAgent` must be checked live,
not trusted from signing time). If ownership of `agent` later transfers,
a policy created under the old owner would remain valid forever under
Option A, since nothing re-checks the relationship after creation. That
reintroduces a stale-authorization bug this fix exists to prevent, not
merely fails to close a different one.

**Option C — require an explicit EIP-712 signature from the owner over
the policy's content at creation time.** Rejected as unnecessarily
large for what "smallest auditable design" calls for. A creation-time
signature has the *same* staleness problem as Option A — it proves
authorization at one point in time, not continuously — so it would still
need to be *combined* with a live check (i.e., with Option B) to
correctly handle ownership transfer, at which point the extra signature
scheme is mostly redundant: Option B alone already achieves everything
Option C would, without a new EIP-712 domain, without new signature
verification code, and without `PolicyRegistry` needing to accept or
validate a signature parameter at all. The one thing Option C adds that
B doesn't — a relayer being able to submit `createPolicy` on the true
owner's behalf without the owner spending their own gas — is not a
requirement anything in this protocol has asked for; `createPolicy`
being called directly by the owner is the existing, unremarkable
pattern.

**Option B was chosen.** It requires no new signature scheme, no new
EIP-712 domain, no change to `PolicyRegistry`'s access control model or
`AgentRegistry` at all — only one additional external view call
(`AgentRegistry.ownerOf`, which already existed, just wasn't previously
exposed through `IAgentRegistry`) and one additional comparison in
`AgentExecutionGuard.execute`. It is also the *only* one of the three
options that correctly and automatically handles ownership transfer
without any extra mechanism — see below.

## Ownership transfer semantics (explicitly defined, not silently chosen)

**Scenario:** Owner A controls Agent X, creates Policy X. Ownership of
Agent X transfers to Owner B.

**Can Owner A's old Policy X still execute? No — by design, and this is
now the enforced invariant.** `PolicyRegistry` policies are immutable
(ADR-0003) — a policy's `owner` field can never be updated to reflect a
new controller. Once ownership transfers, `AgentRegistry.ownerOf(agent)`
live-returns Owner B, but Policy X's stored `owner` remains Owner A
forever. The live comparison in `AgentExecutionGuard` therefore
correctly and automatically rejects any intent referencing Policy X from
the moment of transfer onward — with **zero additional code** in either
`AgentRegistry` or `PolicyRegistry`. This falls directly out of checking
the relationship live rather than trusting a stored snapshot, the same
principle already applied to `isActiveAgent`.

This holds even after the new owner reactivates the agent
(`AgentRegistry.reactivate`) — reactivating the *agent* restores its
`active` status, but does nothing to and cannot retroactively change
which *policy* is legitimately authorized. The new owner must establish
their own policy (a fresh `createPolicy` call, under their own address as
`owner`) for the agent to regain any execution authority. This is
verified by dedicated tests in
`contracts-test/AgentExecutionGuard.integration.test.ts`, "ownership
transfer lifecycle edge case" — including a test proving the agent's
*signing key itself* is entirely unaffected by the transfer: the same
key immediately produces valid intents again the moment the new owner's
policy exists, with no re-registration, no key rotation, nothing agent-
identity-related required at all. Only the *policy* needs refreshing,
because only the policy — not the agent's cryptographic identity — is
what became stale.

## Why `PolicyRegistry` itself is unchanged

It was tempting to "fix" this by making `createPolicy` itself
permissioned. That was rejected (see Option A above) because it solves
strictly less than Option B while adding a cross-contract dependency
`PolicyRegistry` has deliberately never had. `PolicyRegistry` remains
exactly what it was designed to be: a content-addressed, immutable
configuration store with no opinion about who *should* be allowed to
reference it — that opinion belongs entirely to
`AgentExecutionGuard`, the one contract whose job is deciding what is
actually authorized to execute. This keeps the "PolicyRegistry declares,
AgentExecutionGuard enforces" separation established since Gate 3/4A
(see ADR-0005, Decision 4) intact, and extends it consistently to this
new dimension rather than special-casing it.

## Interface changes

- `IAgentRegistry` gains `ownerOf(address) returns (address)` — the
  concrete function already existed in `AgentRegistry` since Gate 1;
  this exposes it through the minimal interface `AgentExecutionGuard`
  depends on.
- `IPolicyRegistry.checkAuthorization` gains a new first return value,
  `owner` — the policy's immutably-recorded creator. Existing callers
  that access return values by name (not position) are unaffected; this
  repository's own test suite exclusively uses named access.
- One new custom error: `PolicyOwnerMismatch(bytes32 policyHash, address
  registeredOwner, address policyOwner)`.

## Security implications

- Closes a real, confirmed Critical-severity bypass: a compromised or
  malicious agent could previously grant itself unlimited authority
  using only its own already-possessed key.
- Introduces no new signature scheme and therefore no new replay,
  cross-chain, or domain-separation surface — all of Gate 1/2's existing
  EIP-712 protections are untouched.
- `PolicyRegistry.createPolicy` remains permissionless. This is not
  itself a vulnerability post-fix: a policy created by anyone other than
  `agent`'s actual live-registered owner can never pass
  `AgentExecutionGuard`'s owner check, so an attacker "wasting" gas
  creating policies nobody can ever use is the only thing permissionless
  creation now enables.
- Adds exactly one external view call (`AgentRegistry.ownerOf`) to
  `execute`'s existing check sequence — O(1), no new loops, consistent
  with the bounded-gas requirement established in Gate 4A.

## What this fix does NOT do

- Does not touch `dailyLimit`/`approvalThreshold` — still Gate 4B scope,
  entirely unrelated to this fix.
- Does not add ERC-20 handling.
- Does not change `PolicyRegistry`'s access control, storage layout (for
  existing fields), or immutability model.
- Does not add any new signature or EIP-712 domain.
