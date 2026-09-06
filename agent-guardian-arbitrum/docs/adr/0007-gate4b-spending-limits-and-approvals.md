# ADR-0007: Gate 4B spending limits and approvals

## Status

Proposed — design only. No Gate 4B contract code is implemented by this ADR.

## Context

Gate 4A now enforces the immutable policy's `maxTxValue`, exact `(target,
selector)` authorization, native-transfer authorization, policy activity and
time window, agent binding, and live policy-owner binding. `AgentExecutionGuard`
also retains EIP-712 intent binding, monotonic per-agent nonces, exact
`msg.value == intent.value`, and atomic external execution.

The remaining mandate dimensions stored by `PolicyRegistry` are:

- `dailyLimit`
- `approvalThreshold`

Gate 4B must add execution-time accounting and explicit approval without
weakening any existing Gate 1-4A invariant.

The implementation target is native ETH only. ERC-20 accounting and
argument-level authorization remain out of scope.

## Design goals

1. A successful execution can consume no more daily allowance than its exact
   signed native `value`.
2. A reverted execution consumes no daily allowance and no nonce.
3. Approval can satisfy an approval requirement but can never enlarge the
   policy's `maxTxValue`, daily limit, target/selector permissions, time
   window, or policy-owner relationship.
4. An approval is bound to the exact execution intent and cannot be replayed
   for another nonce, value, target, calldata, policy, wallet, agent or chain.
5. Ownership transfer invalidates old-policy approvals naturally through the
   existing live policy-owner check.
6. Daily accounting has deterministic UTC-day semantics and no reset
   transaction.
7. The hot execution path remains O(1); no unbounded iteration is introduced.
8. The design must remain auditable from the existing `AgentExecutionGuard`
   execution boundary rather than distributing authorization decisions across
   multiple contracts.

## Decision 1 — daily-limit semantics

`dailyLimit` is a **policy-scoped cumulative native-ETH limit per UTC calendar
 day**. Spend is tracked by `(policyHash, utcDay)` rather than by a caller,
wallet, or transaction.

A policy therefore cannot spend more than its own configured `dailyLimit` in a
single UTC day, regardless of how many successful intents use that policy.
Different immutable policies are intentionally separate mandates; creating a
second policy is a new authorization decision by the current registered owner,
not an execution-time bypass of the first policy.

The UTC day bucket is:

```solidity
uint64 day = uint64(block.timestamp / 1 days);
```

The ledger stores the current bucket and cumulative amount. When execution is
in a new bucket, the stored cumulative amount is treated as zero for the new
day without requiring a reset transaction.

### Accounting invariant

For a policy and UTC day, after every successfully committed execution:

```text
spent(policy, day) <= policy.dailyLimit
```

The increment is exactly the intent's `value`; there is no separate amount
supplied by the caller.

### Zero daily limit

`dailyLimit == 0` means no positive-value spend is permitted under that policy.
A zero-value call may still execute if all other policy conditions pass.

## Decision 2 — approval semantics

`approvalThreshold` defines when an owner approval is mandatory.

- If `value <= approvalThreshold`, no approval is required.
- If `value > approvalThreshold`, a valid current-owner approval is required.
- `approvalThreshold == 0` therefore requires approval for every positive-value
  execution.
- Approval never bypasses `maxTxValue` or `dailyLimit`.

This deliberately makes approval an **additional authorization condition**, not
an override mechanism.

## Decision 3 — approval is a signature over the exact intent

The owner approval uses a dedicated EIP-712 typed-data structure. It MUST bind
at least:

```text
agent
wallet
target
value
calldataHash
nonce
deadline
policyHash
approvalDeadline
```

The approval is additionally domain-separated by the existing EIP-712 domain
of `AgentExecutionGuard`, so it is bound to chain ID and guard address.

The owner signer MUST equal the live `AgentRegistry.ownerOf(agent)` value that
already gates policy execution.

`approvalDeadline` MUST be no later than the intent `deadline` and must be
checked against `block.timestamp` at execution.

### Why bind nonce and all intent fields?

Binding only `(policyHash, value)` would permit an approval obtained for one
operation to be replayed for another target, calldata, wallet or nonce. The
approval is therefore intentionally a second authorization over the exact
execution object, not a generic spending permit.

### Approval replay invariant

A valid approval for intent `I` MUST fail for every intent `I'` where any bound
field differs, including a different nonce. No separate approval nonce is
needed because the execution nonce itself is part of the signed approval and
successful execution consumes the same intent nonce atomically.

## Decision 4 — execution ordering

Gate 4B should preserve the existing cheap-to-expensive ordering while adding
stateful accounting only after every authorization check that can fail without
state mutation.

Proposed flow:

```text
1. zero-address / deadline / msg.value checks
2. calldata classification
3. live agent active check
4. policy lookup + static authorization
5. live policy-owner check
6. nonce equality check
7. daily-limit calculation (read-only)
8. determine whether approval is required
9. if required: verify approval deadline + owner signature
10. verify agent intent signature
11. update daily-spend state
12. consume nonce
13. external call
14. emit execution event
```

The daily-spend write and nonce write occur immediately before the external
call. Because the external call is in the same EVM transaction, any revert
rolls back both writes.

The implementation may combine the daily-limit and approval-related reads to
keep the hot path O(1), but it must not introduce loops over historical
transactions or approvals.

## Decision 5 — no approval can widen policy authority

Approval is evaluated only after the underlying policy has already passed:

- agent binding
- live owner binding
- active state
- time window
- `maxTxValue`
- exact target/selector or native-transfer authorization

Therefore an owner approval for an unauthorized target, selector, malformed
calldata, inactive policy, expired policy, or over-`maxTxValue` value MUST NOT
make the execution valid.

Likewise, approval cannot raise the remaining daily allowance. The condition
is:

```text
value <= remainingDailyLimit
AND
(if value > approvalThreshold then validOwnerApproval)
```

not:

```text
approval => ignore dailyLimit
```

## State model

For each policy, the minimum mutable spending state is conceptually:

```solidity
struct DailySpend {
    uint64 day;
    uint128 spent;
}

mapping(bytes32 => DailySpend) dailySpend;
```

`spent + value` MUST be checked before storage. Since both values are bounded
by `uint128`, the implementation must explicitly reject an addition that would
overflow rather than rely on wraparound semantics.

The stored amount is updated only for a successful execution path. A failed
external call reverts the whole transaction and restores the previous bucket
and amount.

## Threat model / hostile attack matrix

The Gate 4B implementation must have a concrete regression test for every
scenario below.

### Daily-limit attacks

1. First spend exactly equal to `dailyLimit` → PASS.
2. First spend `dailyLimit + 1 wei` → REVERT.
3. Two spends whose sum equals `dailyLimit` → PASS/PASS.
4. Two spends whose sum exceeds `dailyLimit` → second REVERT.
5. Many small spends cannot exceed the limit through rounding → REVERT at
   first exceeding execution.
6. Spend at the last second of a UTC day, then spend after midnight → both
   are accounted in their respective buckets.
7. Crossing midnight without a reset transaction must start a fresh bucket.
8. Old-day spend must not be added to the new day's total.
9. A reverted external call must not consume daily allowance.
10. A policy check failure must not mutate daily-spend state.
11. A signature failure must not mutate daily-spend state.
12. A nonce failure must not mutate daily-spend state.
13. `value == 0` must not increase spend.
14. `dailyLimit == 0` rejects positive-value execution.
15. Maximum representable `uint128` daily limit behaves correctly at its exact
    boundary.
16. `spent + value` overflow is rejected rather than wrapped.
17. Repeated executions through the same policy share the same daily bucket.
18. A different wallet cannot create a second spend ledger for the same policy.
19. A different relayer/caller cannot create a second spend ledger for the same
    policy.
20. Changing target/selector does not reset spend when the same policy is used.

### Approval attacks

21. Value exactly equal to `approvalThreshold` requires no approval.
22. Value one wei above threshold requires approval.
23. `approvalThreshold == 0` requires approval for every positive-value call.
24. A valid approval for intent A cannot authorize intent B with a different
    nonce.
25. A valid approval cannot be replayed with a different target.
26. A valid approval cannot be replayed with different calldata.
27. A valid approval cannot be replayed with different `value`.
28. A valid approval cannot be replayed with a different `wallet`.
29. A valid approval cannot be replayed with a different `policyHash`.
30. An approval signed by the old agent owner fails after ownership transfer.
31. An approval signed by the current owner for an unauthorized target fails.
32. An expired approval fails even when the intent itself is still valid.
33. An approval whose deadline exceeds the intent deadline is rejected.
34. A malformed approval signature fails without mutating nonce or spend.
35. Approval cannot make an inactive/revoked policy executable.
36. Approval cannot make an over-`maxTxValue` execution executable.
37. Approval cannot make a malformed 1–3 byte calldata execution executable.
38. Approval cannot convert a function-call authorization into native-transfer
    authorization, or vice versa.
39. Reusing the same approval after a successful execution with the same nonce
    is impossible because the nonce has advanced.
40. Reentrancy during an approved execution cannot consume the approval or
    bypass the daily limit.

### Cross-dimension attacks

41. A transaction that would exceed the daily limit and also require approval
    must fail if either condition fails; approval cannot override the limit.
42. A transaction that passes the daily limit but violates `(target, selector)`
    must fail even with a valid owner approval.
43. A transaction that passes policy authorization but has the wrong
    `msg.value` must fail before accounting.
44. A transaction that passes all checks but whose target reverts must roll
    back both nonce and daily spend.
45. Ownership transfer between approval creation and execution must cause the
    old policy/approval path to fail through the existing live owner check.
46. A new policy created by the new owner must start with its own independent
    immutable mandate and zero daily spend.
47. An agent cannot use a policy belonging to another agent even when the
    approval signer is the other policy's owner.
48. A stale policy cannot be revived by `reactivatePolicy` after agent ownership
    transfer.
49. Approval verification must not introduce a second signature domain that is
    replayable across guards or chains.
50. No execution path may update spend or nonce before a check that can still
    cause the transaction to revert for authorization reasons.

## Required property/invariant tests

The implementation is not considered complete until the following properties
are represented in tests:

### I1 — daily cap

For every successful execution under policy P and day D:

```text
spent(P,D) <= dailyLimit(P)
```

### I2 — exact accounting

For every successful positive-value execution:

```text
spent_after = spent_before + intent.value
```

within the same UTC bucket.

### I3 — revert atomicity

If `execute` reverts for any reason, both `nextNonce[agent]` and the daily
spend state are identical before and after the transaction.

### I4 — approval implication

If `value > approvalThreshold`, execution is impossible without a valid
current-owner approval bound to the exact intent.

### I5 — approval non-escalation

A valid approval cannot make an otherwise policy-unauthorized intent valid.

### I6 — ownership freshness

The approval signer and policy owner must equal the current
`AgentRegistry.ownerOf(agent)` at execution time.

### I7 — nonce uniqueness

A successful intent consumes exactly one nonce; replaying the same intent or
approval fails.

### I8 — UTC determinism

Changing only `block.timestamp` across a UTC-day boundary changes the bucket
from D to D+1 and never carries the previous bucket's `spent` value into the
new bucket.

### I9 — native value binding

Daily accounting uses the signed `intent.value`, while execution remains gated
by `msg.value == intent.value`; no caller-controlled second amount exists.

### I10 — policy ceiling remains authoritative

Approval and daily accounting are strictly additional checks. Neither can
permit a value above `maxTxValue` or a target/call outside the immutable policy.

## Implementation boundary

`PolicyRegistry` remains the immutable configuration store. `AgentExecutionGuard`
remains the enforcement boundary and owns the mutable execution accounting.

The preferred implementation is therefore:

- add daily-spend storage to `AgentExecutionGuard`;
- extend `execute` with an optional approval signature parameter;
- add a dedicated EIP-712 approval type hash;
- expose a small read-only helper for current daily spend if useful to tooling;
- keep `PolicyRegistry`'s mandate fields and policy hash unchanged unless an
  implementation issue proves a storage/API change necessary.

No approval history array, queue, or iterable storage is permitted.

## Alternatives rejected

### A. Daily spend in PolicyRegistry

Rejected because PolicyRegistry is intentionally configuration-only and
immutable except for the coarse active bit. Execution accounting is mutable
state coupled to successful execution, so putting it in the registry would
blur the separation and make failed-call rollback semantics harder to audit.

### B. Approval stored on-chain as a mutable permit

Rejected. A mutable approval record introduces revocation, replay and stale
state semantics that are unnecessary for one exact execution. A typed owner
signature is deterministic and self-contained.

### C. Approval over policyHash + value only

Rejected. It is insufficiently bound to the exact execution and would permit
cross-target/calldata/nonce replay.

### D. Approval overrides dailyLimit

Rejected categorically. This turns an approval mechanism into an authority
escalation mechanism and makes `dailyLimit` advisory rather than deterministic.

## Implementation acceptance criteria

Gate 4B code may begin only when the implementation preserves all existing
Gate 1-4A invariants and adds tests proving I1-I10 plus the attack matrix.

Before merge, the hostile review must independently verify:

- the exact approval digest and domain separation;
- owner freshness at execution time;
- UTC bucket transitions;
- cumulative accounting across multiple calls;
- atomic rollback on failed external execution;
- no approval-based bypass of policy or daily limits;
- no nonce/approval replay;
- O(1) execution path;
- no unintended ERC-20 or argument-level authorization claims.
