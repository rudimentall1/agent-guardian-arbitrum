# ADR-0005: Paired (target, selector) authorization, native-transfer semantics, and maxTxValue enforcement

## Status

Accepted (Gate 4A).

## Context

Gate 3's `PolicyRegistry` authorized calls via two independent allow-lists:
`allowedTargets = {A, B}` and `allowedSelectors = {X, Y}`, checked
separately. This accidentally authorized the full Cartesian product —
`{A+X, A+Y, B+X, B+Y}` — even when an owner only ever intended `A+X` and
`B+Y`. An owner who meant "allow `transfer()` on token A and `approve()`
on token B" would unknowingly have also authorized `approve()` on token A
and `transfer()` on token B. This is a real privilege-escalation bug, not
a theoretical one, and closing it is Gate 4A's primary objective.

## Decision 1: paired authorization, not independent allow-lists

Every authorization is now a single tuple, stored as one flattened
mapping entry:

```
mapping(policyId => mapping(keccak256(abi.encode(target, selector)) => bool))
```

Only the exact `(target, selector)` pairs explicitly listed at policy
creation are ever authorized. There is no way to derive an authorized
pair from two independently-true facts.

### Alternatives considered

**`mapping(target => mapping(selector => bool))`, not flattened.** A
nested mapping expresses the same paired relationship and was seriously
considered. Rejected in favor of the flattened `keccak256(abi.encode(...))`
key for one concrete reason: `PolicyRegistry.checkAuthorization` (see
Decision 3) needs a *single* storage read to answer "is this pair
authorized," parameterized identically regardless of whether the check
is for a function call or (via a *separate* mapping — see Decision 2) a
native transfer. A flattened key makes both lookups syntactically
identical single-mapping reads; a nested mapping would need
target-then-selector two-level access for one authorization kind and a
different single-level structure for the other, which is a small but
real readability and consistency cost for no gas or security benefit —
both approaches are O(1) and equally collision-safe (per Part 2 below).

**A single mapping combining native-transfer into the same key-space
(e.g. `selector = 0x00000000` meaning "native transfer").** Rejected —
see Decision 2.

**Storing authorized pairs as an array + linear scan.** Rejected
immediately: violates the bounded-gas requirement (Part 12) outright —
`execute()`'s authorization check must be O(1), not O(n) in the number
of authorized pairs a policy happens to have.

## Decision 2: native transfers are a separate authorization dimension

`data.length == 0` (a plain ETH transfer) is tracked in its own mapping,
`mapping(policyId => mapping(target => bool))`, never through the
`(target, selector)` mapping.

Overloading selector `0x00000000` to mean "native transfer" was
considered and rejected: `0x00000000` is a real, reachable function
selector — any function whose 4-byte Keccak signature hash happens to be
all-zero bytes is a legitimate (if statistically rare) target. Conflating
it with "no calldata at all" creates a two-way collision:

- A policy authorizing that one unlucky real selector for a target would
  *also* silently authorize plain ETH transfers to that target.
- A policy authorizing native transfers to a target would *also* silently
  authorize calling that one specific selector with empty-looking
  arguments.

Neither direction is acceptable for an authorization boundary whose whole
point is "only exactly what was explicitly granted." Two independent
mappings make this collision structurally impossible rather than
merely statistically unlikely.

### Calldata classification and the "malformed" case

`AgentExecutionGuard.classifyCalldata` (not `PolicyRegistry`) classifies
every intent's calldata into exactly one of three kinds before asking
PolicyRegistry anything:

- **`NativeTransfer`** — `data.length == 0`.
- **`FunctionCall`** — `data.length >= 4`; the first 4 bytes are the
  selector.
- **`Malformed`** — `1 <= data.length <= 3`. Not empty (so not a native
  transfer), not long enough to contain a complete selector (so not
  meaningfully a function call either). This case is **never
  authorized, unconditionally** — `PolicyRegistry.checkAuthorization`
  returns `callAllowed = false` for `Malformed` without performing any
  mapping lookup at all.

The "without performing any mapping lookup" detail was a deliberate fix
made during this gate's own design review, not merely a convenient
default: an earlier draft classified 1–3 byte calldata by defaulting its
`selector` value to `bytes4(0)` and treating it like any other
`FunctionCall`. That would have meant a policy authorizing the real
selector `0x00000000` for some target would *also* authorize any
malformed 1-, 2-, or 3-byte calldata sent to that same target — a second
instance of exactly the collision Decision 2 exists to prevent, just at
a different boundary. `Malformed` is now a structurally distinct branch
with no fall-through path to a real authorization entry.

### Responsibility split

Classification (what *kind* of call is this, given the actual
calldata bytes) lives in `AgentExecutionGuard`, which already holds
`data` for `calldataHash` purposes. Authorization (is this specific,
already-classified `(target, kind, selector)` tuple *permitted*) lives
in `PolicyRegistry`, which remains the single source of truth for
mandate configuration. `AgentExecutionGuard` never accepts an
independently-suppliable `selector` parameter in its own public
interface — it is always derived from the same `data` that is
cryptographically bound into the signed intent's digest, so there is no
path for a caller to assert "this calldata means selector X" when the
calldata itself says otherwise.

## Decision 3: `checkAuthorization` is one combined external call

`PolicyRegistry.checkAuthorization(policyHash, target, callKind, selector, value)`
resolves everything `AgentExecutionGuard.execute` needs — policy-agent
binding, active/revoked state, time-window validity, `maxTxValue`
comparison, and target+selector (or native-transfer) authorization — in
a single external view call, returning five distinct booleans/values
rather than one opaque `bool`.

Returning granular results (`active`, `withinWindow`, `valueAllowed`,
`callAllowed` separately, not folded into one flag) was chosen over a
single aggregate boolean specifically so `AgentExecutionGuard` can raise
a distinct, specific custom error per failure reason
(`PolicyNotActive`, `PolicyOutsideTimeWindow`, `MaxTxValueExceeded`,
`CallNotAuthorized`) — auditability and debuggability matter as much as
the authorization decision itself for a contract whose entire job is
being reviewable.

Keeping this as one external call rather than several round trips (e.g.
a separate call for the agent-binding check, another for `maxTxValue`,
another for target/selector) is a direct response to the gas/DoS
requirement in Part 12: `execute()`'s authorization overhead stays
constant regardless of how many mandate dimensions this or a future gate
adds to the check, rather than growing linearly with the number of
things being verified.

## Decision 4: `maxTxValue` enforcement location

`maxTxValue` is stored in `PolicyRegistry` (the source of truth for
mandate configuration, unchanged since Gate 3) and *enforced* in
`AgentExecutionGuard` (the contract that actually knows the real
`msg.value`/`value` being spent and performs the external call).
`PolicyRegistry.checkAuthorization` computes `valueAllowed = (value <=
maxTxValue)` using the `value` the Guard passes it — the comparison
logic lives with the configuration, but the Guard is the one enforcing
it (reverting) since only the Guard is in a position to abort the
transaction before the external call happens. This mirrors the
`dailyLimit`/`approvalThreshold` design already established in Gate 3:
`PolicyRegistry` declares limits, whatever contract actually executes
transactions is responsible for enforcing them against real transaction
data.

## What this gate deliberately does NOT do

- **No argument-level authorization.** A policy authorizing
  `token.transfer(address,uint256)` on some target says nothing about
  which recipient or amount was passed — target+selector authorization
  answers "is this function callable," not "were these specific
  arguments approved." The signed `calldataHash` still cryptographically
  binds the *exact* calldata bytes used (this was already true since
  Gate 2 — a tampered argument invalidates the signature, tested
  extensively in the Gate 4A adversarial suite), but there is no
  allow-list over argument values themselves. Argument-level
  restrictions (e.g. "only this recipient," "only up to this amount
  regardless of `value`") remain a possible future gate, explicitly not
  implemented here — see `docs/gate-4a-call-authorization.md`,
  "remaining limitations."
- **No `dailyLimit`/`approvalThreshold` enforcement.** Unchanged from
  Gate 3 — still declared-only, not accounted for. Gate 4B.
- **No ERC-20 accounting of any kind.** `maxTxValue` and the whole
  mandate model in this gate concern native ETH `value` only.

## Security implications

- The Cartesian-product bug is closed structurally (a single flattened
  mapping cannot express "authorize A with X or Y independently of B" —
  every entry is one exact pair), not merely tested against. The
  mandatory regression test (`contracts-test/PolicyRegistry.test.ts`,
  "Cartesian-product regression", and the full-stack version in
  `contracts-test/AgentExecutionGuard.gate4a.test.ts`) proves the
  specific scenario the brief specifies: authorizing `A+X` and `B+Y`
  does not also authorize `A+Y` or `B+X`.
- `Malformed` calldata (1–3 bytes) can never be authorized by any policy
  configuration, which removes an entire class of "did the operator
  intend this" ambiguity at the boundary between native transfers and
  function calls.
- A failed policy, `maxTxValue`, or target/selector check never consumes
  a nonce — all of Gate 4A's new checks sit before nonce consumption in
  `execute()`'s check ordering (see the contract's own NatSpec for the
  full ordering rationale and its gas-griefing reasoning).

## Future migration considerations

If argument-level restrictions become a real requirement, they should be
a new, explicitly-versioned authorization dimension (e.g. an optional
per-pair calldata-argument matcher) layered on top of the existing
`(target, selector)` authorization, not a replacement for it — the
target+selector check is cheap and O(1) precisely because it does not
inspect argument bytes; adding argument matching should be an opt-in
cost, not a tax on every authorized call.
