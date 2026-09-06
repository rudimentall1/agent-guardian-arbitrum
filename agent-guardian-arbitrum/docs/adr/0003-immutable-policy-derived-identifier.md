# ADR-0003: Immutable policies, identifier derived from (owner, salt)

## Status

Accepted (Gate 3).

## Decision

`PolicyRegistry` policies are immutable once created: mandate values
(`maxTxValue`, `dailyLimit`, `approvalThreshold`, `validFrom`,
`validUntil`, allowed targets, allowed selectors) can never change after
`createPolicy`. The only lifecycle operations are `revokePolicy` and
`reactivatePolicy`, which flip a single `active` flag and touch nothing
else.

The on-chain policy identifier is not a caller-supplied raw value. It is
derived as `keccak256(abi.encode(owner, salt))`, where `owner` is always
`msg.sender` at creation time and `salt` is caller-chosen.

## Alternatives considered

**Mutable mandates with an `updatePolicy` function.** Rejected outright.
`docs/protocol-spec.md` section 4 already states the requirement this
gate must satisfy: "changing policy therefore does not silently change
the meaning of an already signed intent." An update-in-place function
directly violates that: an agent's operator signs an
`AgentExecutionGuard` intent committing to a specific `policyHash`; if
the owner could later widen `maxTxValue` or add targets under the same
`policyId` without changing that hash, the operator's earlier signature
would end up authorizing something they never agreed to. A new mandate
must be a new identifier with its own hash — no exceptions, no "minor
tweaks."

**Caller-supplied global `policyId` (no derivation).** This was the
first draft of this contract and was replaced during self-review, not
requested by any external brief. A raw caller-chosen `bytes32` identifier
in a single global namespace lets one owner front-run another's expected
identifier — observe a pending `createPolicy(policyId, ...)` transaction
in the mempool and submit their own `createPolicy` with the same
`policyId` first, permanently denying the original owner that slot. This
is a griefing vector, not present in `AgentRegistry`'s analogous
exactly-once identity model, because an agent address is itself a
cryptographic identity (squatting requires controlling the matching
private key) while a policy identifier is arbitrary data with no such
proof requirement. Deriving the identifier from `(msg.sender, salt)`
closes this off structurally: two different `msg.sender` values can never
produce the same identifier for any `salt`, so there is nothing to race.

**Owner-scoped mapping, e.g. `mapping(address => mapping(bytes32 =>
Mandate))`.** Functionally equivalent to the derived-identifier approach,
but every external reader (a future `AgentExecutionGuard` extension
checking a signed intent's `policyHash`) would need both `owner` and
`policyId` as separate parameters everywhere, and the two values could
independently be wrong in a way that's easy to typo in calling code
(passing the right `policyId` with the wrong `owner`). A single derived
`bytes32` handle is simpler to embed in a signed EIP-712 intent (one
field, not two) and structurally cannot be mismatched once computed
correctly.

## Security implications

- `computePolicyId` is a `pure` function callable by anyone off-chain
  before submitting `createPolicy`, so an owner can know their policy's
  future identifier in advance — useful for preparing a signed
  `AgentExecutionGuard` intent that references a `policyHash` before the
  policy transaction has even landed, without any coordination risk
  (nobody else can compute the same identifier for a different `salt`
  input yielding the same output, short of a `keccak256` preimage
  collision).
- Revocation is intentionally coarse: it disables the *entire* mandate,
  not individual targets/selectors within it. Finer-grained partial
  revocation was considered and rejected for this gate — it would require
  either mutability (rejected above) or a much larger set of
  identifiers (one per allowed target/selector pair), neither of which
  is justified yet by an actual product requirement.
- `dailyLimit` and `approvalThreshold` are stored but **not enforced** by
  this contract — see the contract's NatSpec point 3 and
  `docs/gate-3-policy-registry.md`. Anything integrating with
  `PolicyRegistry` must not assume cumulative spend is tracked here.

## Future migration considerations

If mandate values genuinely need to change without minting a new
identifier (e.g. a UX requirement to "edit" a policy rather than create a
new one), that should be a deliberate new contract version with its own
EIP-712-style versioning story for how `AgentExecutionGuard` intents
reference it — not a retrofit of `updatePolicy` onto this one. The
mandate-enforcement gate that consumes `isCallAllowedByPolicy` and adds
rolling daily-spend tracking is the next natural gate on top of this one.
