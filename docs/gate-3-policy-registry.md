# Gate 3 report: PolicyRegistry — financial mandate commitment

## 1. Files changed

- `contracts/PolicyRegistry.sol` (new)
- `contracts-test/PolicyRegistry.test.ts` (new — 26 tests)
- `docs/adr/0003-immutable-policy-derived-identifier.md` (new)
- `docs/protocol-spec.md` (updated: section 11, Gate 3 status)
- `docs/threat-model.md` (updated: Gate 3 status)
- `docs/gate-3-policy-registry.md` (this file)

Branched from `main` (Gate 1's `d841056`), not from Gate 2's branch —
`PolicyRegistry` has no dependency on `AgentExecutionGuard` or
`AgentRegistry`. See section 12 for why this gate and Gate 2 don't
integrate yet.

## 2. Context: no brief provided for this gate

Unlike Gate 1 and Gate 2, no detailed task brief was given for Gate 3.
The scope below was derived from what `docs/protocol-spec.md` (sections
4–5) already committed to before this gate started, plus this repository's
own established pattern (Gate 1/2's identity-and-lifecycle style,
adversarial-first testing, ADR for load-bearing decisions). This is
stated plainly because it changes how the "attack campaign" and
"self-audit" sections below should be read: they are this session's own
threat modeling, not a checklist handed down and verified against.

## 3. Contract added

`PolicyRegistry` — one state-changing surface for creation
(`createPolicy`), two for lifecycle (`revokePolicy`,
`reactivatePolicy`), and view functions for reading mandate state
(`getMandate`, `isPolicyActive`, `ownerOf`, `isTargetAllowed`,
`isSelectorAllowed`, `policyHashOf`, `computePolicyId`) plus one
composite static check (`isCallAllowedByPolicy`). No dependency on any
other contract in this repository.

## 4. Tests added

26 tests, all passing. Combined with Gate 1's unchanged 24, this branch's
full suite is **50 passing, 0 failing**.

- Happy path (4): deterministic identifier derivation, exact mandate
  storage, non-zero `policyHash` emission, two different owners using an
  identical `salt` without colliding.
- Identifier collision / squatting (2): confirms the front-run/squatting
  concern that motivated ADR-0003 is actually closed by the
  `(owner, salt)` derivation, plus standard exactly-once re-creation
  rejection.
- Immutability (2): revoke+reactivate round-trip leaves every mandate
  field and the `policyHash` byte-for-byte unchanged; "widening" a
  mandate requires an entirely new identifier and hash, the original is
  untouched.
- Access control (5): non-owner rejected on both lifecycle functions,
  redundant-state-transition rejection (double-revoke, double-reactivate),
  operating on a nonexistent policy.
- Creation-time validation (4): invalid time window, empty
  allowed-targets list, empty allowed-selectors list, zero address inside
  an allow-list.
- `isCallAllowedByPolicy` static checks (9): allowed call, disallowed
  target, disallowed selector, value over/at the exact `maxTxValue`
  boundary, revoked policy, before/after the valid time window, and a
  nonexistent policy returning `false` rather than reverting (a view
  function returning a safe default instead of reverting is a deliberate
  choice — see section 11).

## 5. Fuzzing performed

None. Given the smaller state space compared to Gate 2 (no nonce
sequencing, no reentrancy-relevant external calls, no signature
verification) and the absence of a real fuzzer in this sandbox (same
`foundry.paradigm.xyz` network restriction as Gates 1–2), hand-written
boundary tests were judged sufficient for this gate's actual attack
surface. **NOT PROVEN**: arbitrary combinations of `uint128` mandate
values, array lengths, and timestamps were not randomly explored. The
boundary that most benefits from fuzzing — `value == maxTxValue` exactly
— is covered by a hand-written test; adjacent `uint128` overflow
behavior in `maxTxValue`/`dailyLimit`/`approvalThreshold` was not
separately stress-tested (they are stored, not arithmetically combined,
anywhere in this contract, which limits — but does not eliminate — the
risk a fuzzer might otherwise catch).

## 6. Invariants tested

1. `computePolicyId(owner, salt)` is deterministic and collision-free
   across distinct `owner` values for identical `salt` input (tested
   directly; not proved as a `keccak256` property, which is out of scope
   for a test suite).
2. Mandate values and `policyHash` are immutable from the moment
   `createPolicy` succeeds — no code path changes them afterward.
3. `active` is the only lifecycle-mutable field, flip-able only by the
   recorded `owner`.
4. `isCallAllowedByPolicy` is fail-closed on every dimension: inactive,
   outside time window, disallowed target, disallowed selector, or
   over-limit value each independently produce `false`.

## 7. Attack scenarios attempted

- **Policy identifier squatting/front-running.** First draft of this
  contract used a raw caller-supplied global `policyId`. Recognized
  during design (not found by testing a shipped draft — see section 8)
  as a real griefing vector and redesigned before writing tests against
  it, per ADR-0003. Verified with a direct test that two owners sharing
  an identical `salt` produce different, non-colliding identifiers.
- **Silent mandate widening under an existing hash.** No `update`
  function exists at all — verified structurally (there is no such
  function to call) and behaviorally (revoke/reactivate round-trip
  leaves the stored mandate and its hash unchanged).
- **Unauthorized lifecycle transitions.** Non-owner revoke/reactivate
  attempts rejected for both directions.
- **Wildcard/implicit-allow bypass.** Empty allow-lists are rejected at
  creation rather than silently treated as "allow everything" — verified
  both that creation reverts and, separately, that a target/selector
  genuinely absent from a real list is rejected by
  `isCallAllowedByPolicy`.
- **Boundary value bypass.** `value == maxTxValue` (should pass) and
  `value == maxTxValue + 1` (should fail) both verified explicitly, not
  just one side of the boundary.
- **Time-window bypass.** Before `validFrom` and after `validUntil` both
  verified independently, plus the ordinary case using dynamically
  computed timestamps (not hardcoded ones — an earlier draft of the test
  file hardcoded absolute timestamps and failed against a real chain
  clock; fixed by deriving all test timestamps from the live block, same
  class of tooling mistake as Gate 2's, corrected the same way).

## 8. Vulnerabilities discovered

One design-time finding, not a shipped-and-then-found bug: the
caller-supplied global `policyId` in the first draft (see section 7,
first bullet) was identified and replaced before any test was written
against it, during the same design pass that produced the contract's
NatSpec. This is worth stating plainly rather than folding it silently
into "the design": it means the adversarial *testing* in this gate did
not itself surface a vulnerability in the shipped contract — the attack
campaign confirmed the chosen design holds, it did not discover a flaw
in a naive one. Treat "0 vulnerabilities found by testing" with that
context, not as evidence the design process itself is infallible.

## 9. Vulnerabilities fixed

The identifier-derivation redesign in section 8. No other changes were
required after the first fully-implemented version passed the full test
suite.

## 10. Regression tests added

Every scenario in section 7 has a dedicated test. The immutability
round-trip test and the "widening under a new salt is a genuinely
different identifier" test are the ones most likely to silently regress
if this contract is ever extended with an update path — they encode the
exact property ADR-0003 says must never be violated.

## 11. Important design decisions

- **Policies are immutable; only `active` is mutable.** Directly required
  by `docs/protocol-spec.md` section 4. Full reasoning in ADR-0003.
- **Identifier derived from `(owner, salt)`, not caller-supplied
  directly.** Closes a squatting/front-running vector structurally.
  Full reasoning in ADR-0003.
- **No wildcard allow-lists; empty lists are rejected outright**, not
  treated as "allow nothing" silently or "allow everything" dangerously
  — an explicit revert forces the caller to notice a missing list rather
  than accidentally deploying a mandate that permits nothing (which would
  fail closed but silently) or, worse, everything.
- **`isCallAllowedByPolicy` returns `false` for a nonexistent policy
  rather than reverting.** Chosen so a future caller (e.g. an
  `AgentExecutionGuard` extension checking a mandate before executing)
  can use it in a plain boolean condition without wrapping every call in
  try/catch — a nonexistent policy is just another way to fail the check,
  not an exceptional circumstance.
- **`dailyLimit`/`approvalThreshold` stored but not enforced here**,
  deliberately, per contract NatSpec point 3 — rolling spend needs
  execution-time state that belongs with whatever contract actually
  executes transactions, not duplicated here.
- **No integration with `AgentExecutionGuard` in this gate.** Both
  contracts exist independently on separate branches. Wiring them
  together (checking a signed intent's `policyHash` against
  `PolicyRegistry.policyHashOf`, and adding rolling-spend tracking) is
  left for a dedicated next gate so this one stays small and reviewable
  on its own, consistent with how Gates 1 and 2 were kept separate.

## 12. Remaining assumptions

- `msg.sender` at `createPolicy` time is trusted to be the legitimate
  wallet owner defining their own mandate — there is no cross-check
  against `AgentRegistry` ownership or any other identity source, by
  design (this contract has zero dependencies on Gate 1 or Gate 2).
- Off-chain tooling is trusted to compute the canonical off-chain policy
  document whose hash matches `policyHashOf[policyId]` — this contract
  only guarantees that the on-chain mandate fields are exactly what was
  hashed, not that the off-chain document (if one exists) matches.
- `uint128` is assumed sufficient range for `maxTxValue`, `dailyLimit`,
  and `approvalThreshold` (max ~3.4 × 10^38, far beyond any realistic
  wei-denominated value short of the entire token supply of anything).
  Not independently stress-tested at the `uint128` boundary since no
  arithmetic is performed on these fields in this contract — they are
  stored and compared, never added or multiplied.

## 13. Remaining risks

- **NOT PROVEN**: no fuzzing was run (section 5) — a bigger gap here than
  in Gates 1–2 relative to this gate's actual complexity, since none was
  attempted at all rather than attempted-but-limited.
- No static analysis tool was run (same sandbox network-access gap as
  every prior gate).
- `PolicyRegistry` currently has **zero effect** on what
  `AgentExecutionGuard` will execute — the two contracts are not wired
  together. Anyone deploying both must not assume creating or revoking a
  policy changes execution authority until that integration gate exists
  and is itself adversarially tested. Stated plainly so it cannot be
  missed: **`PolicyRegistry` alone enforces nothing about real
  transactions yet.**
- Coarse-grained revocation (entire mandate on/off) means there is no way
  to, for example, pull a single compromised target from an otherwise-
  trusted mandate without revoking the whole thing and creating a
  replacement. Acceptable for this gate; a real limitation for
  operational use.

## 14. Exact Git commit SHAs

See the branch's commit list (`git log feat/policy-registry ^main`) —
recorded in the assistant's final message in this conversation for this
gate, alongside the push confirmation.

## 15. Branch name

`feat/policy-registry`, branched from `main` (Gate 1 only — Gate 2's
`feat/execution-intent-nonce` is a sibling branch, not a parent of this
one).

## 16–17. Push status and verdict

Recorded in the assistant's final message alongside the commit SHAs.

## 18. Why (verdict rationale, to be read alongside section 16–17)

The core property this gate needed to guarantee — a mandate, once
committed to a `policyHash`, cannot be silently altered — is enforced
structurally (no update function exists) rather than merely tested for.
The identifier-collision risk that a naive design would have carried was
caught and redesigned before it reached the test suite, which is a
weaker form of assurance than "the attack campaign found and fixed a real
bug" and is described that way in section 8 rather than overstated. The
gate is scoped narrowly (commitment + static checks only, no spend
tracking, no execution integration) and every one of those exclusions is
stated in `docs/protocol-spec.md` section 11 and `docs/threat-model.md`
so nothing downstream can mistake this for more than it is.
