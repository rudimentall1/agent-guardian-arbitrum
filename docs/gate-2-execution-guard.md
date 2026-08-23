# Gate 2 report: AgentExecutionGuard — execution-intent & nonce foundation

## 1. Files changed

- `contracts/AgentExecutionGuard.sol` (new)
- `contracts/interfaces/IAgentRegistry.sol` (new)
- `contracts/mocks/MockAgentRegistry.sol` (new, test-only)
- `contracts/mocks/TestTargets.sol` (new, test-only — `RecordingTarget`, `AlwaysRevertingTarget`)
- `contracts/mocks/ReentrantAttacker.sol` (new, test-only)
- `contracts-test/AgentExecutionGuard.test.ts` (new — 35 tests)
- `contracts-test/AgentExecutionGuard.integration.test.ts` (new — 6 tests, real `AgentRegistry`)
- `contracts-test/AgentExecutionGuard.fuzz.test.ts` (new — 2 seeded property tests)
- `docs/adr/0002-monotonic-per-agent-nonce.md` (new)
- `docs/protocol-spec.md` (updated: section 11, Gate 2 status)
- `docs/threat-model.md` (updated: Gate 2 status, new trust assumption)
- `docs/gate-2-execution-guard.md` (this file)

## 2. Contracts added/modified

`AgentExecutionGuard` — see full NatSpec in the contract source. One
public state-changing entry point (`execute`), one public view
(`hashIntent`), one immutable dependency (`AgentRegistry`, via the
`IAgentRegistry` interface only — no dependency on AgentRegistry's
concrete implementation). No contract from Gate 1 was modified.

## 3. Tests added

43 new tests (35 + 6 + 2), on top of Gate 1's 24. Full suite: **67
passing, 0 failing.**

## 4. Number/type of tests executed

- Happy-path (5): sequential execution, per-agent nonce independence,
  exact calldata/value forwarding, relayer-submitted transactions.
- Adversarial, hand-written (30 across the two main test files): the
  full 13-scenario attack campaign from the task brief, plus zero-address
  and deadline-boundary cases.
- Integration (6): real `AgentRegistry` registration flow, unregistered
  agent, live deactivation, and the ownership-transfer lifecycle edge
  case (3 tests specifically on that).
- Property/seeded-random (2): a 60-iteration randomized nonce-attempt
  loop checking the three core invariants every iteration, plus a
  15-iteration randomized calldata/value forwarding check.

## 5. Fuzzing performed

**NOT Foundry fuzzing.** Foundry could not be installed in this sandbox
— network egress to `foundry.paradigm.xyz` is blocked by this
environment's allowlist (documented already in the Gate 1 report). What
was actually run: a seeded pseudo-random JS loop (`mulberry32`,
deterministic, reproducible) driving 60 randomized `execute()` attempts
against a real Hardhat-network contract instance, checking after every
single attempt that:

- a call that should succeed by the model *did* succeed and advanced the
  nonce by exactly 1;
- a call that should fail by the model *did* revert and left the nonce
  completely unchanged.

This is a meaningfully weaker guarantee than Foundry's fuzzer: no
shrinking, no coverage-guided input generation, a fixed seed rather than
CI-varied seeds, and 60 iterations rather than the thousands Foundry
would run by default. **NOT PROVEN**: that no adversarial nonce/deadline
combination outside this seed's exploration breaks an invariant. The
hand-written adversarial tests (section 4) cover the specific boundary
cases a real fuzzer would likely find fastest (0, current, current±1,
current+huge, `type(uint256).max`), which mitigates but does not
eliminate this gap.

## 6. Invariants tested

1. Exactly one nonce value is ever accepted per agent at a given time
   (hand-written + property test).
2. A successful `execute()` advances `nextNonce[agent]` by exactly 1,
   never more, never less (hand-written + property test).
3. A failed `execute()` — wrong nonce, bad signature, expired deadline,
   inactive agent, or reverting target — leaves `nextNonce[agent]`
   completely unchanged (hand-written + property test, including the
   `type(uint256).max` boundary).
4. A signature is valid only for the exact (agent, wallet, target, value,
   calldata, nonce, deadline, policyHash) tuple it was produced for —
   changing any single field independently invalidates it (7 hand-written
   tests, one per field).
5. `AgentRegistry.isActiveAgent` is consulted live, not cached — a
   signature produced while active is rejected the instant the agent is
   deactivated, and accepted again if reactivated with the nonce state
   untouched throughout (hand-written + integration tests).

## 7. Attack scenarios attempted

All 13 scenarios from the task brief were attempted; all 13 behave as
specified (revert, or explicitly-justified success). See the "attack N"
`describe` blocks in `contracts-test/AgentExecutionGuard.test.ts` for the
exact test code — summarized:

1. Same-nonce replay → `InvalidNonce`. ✔
2. Stale nonce after advancing → `InvalidNonce`. ✔
3–4. Future nonce (+1, +100, +1,000,000) → `InvalidNonce`. ✔
5. Cross-agent confusion (both directions: wrong signer, and
   post-signing field swap) → `InvalidSignature`. ✔
6. Cross-chain replay → `InvalidSignature` (EIP-712 `chainId`). ✔
7. Cross-contract replay → `InvalidSignature` on the wrong guard,
   confirmed the *same* signature *is* valid on the guard it was actually
   signed for (positive control, not just a negative test). ✔
8. Modified field after signing (wallet, target, value, calldata,
   deadline, policyHash, and the nonce-rewrite-down variant) →
   `InvalidSignature` or `InvalidNonce` depending on which check the
   tamper collides with first — both are correct rejections. ✔
9. Failed external call → whole transaction reverts
   (`ExecutionFailed`), nonce provably unchanged, same intent succeeds
   later against a working target. ✔
10. Reentrancy — same-nonce, next-nonce (same agent), and a completely
    independent, otherwise-valid different-agent intent — all three
    blocked by `nonReentrant`; the independent agent's nonce is
    untouched and it can still execute normally as a fresh top-level
    transaction afterward. ✔
11. `uint256` nonce boundary at `type(uint256).max` → reverts (checked
    arithmetic), does not wrap to 0. Storage was set directly via
    `hardhat_setStorageAt` (found by brute-force slot scan, verified
    empirically rather than assumed) since reaching this nonce through
    real executions is not feasible to set up. ✔
12. Disabled agent — both "already inactive when signed" and "signed
    while active, deactivated before submission" → `AgentNotActive` in
    both cases; nonce untouched, so reactivation restores full authority
    without needing to re-sign. ✔
13. Ownership/lifecycle edge cases — covered in integration tests: a
    pending signature becomes unusable the instant ownership transfers
    (Gate 1's forced-inactive-on-transfer does the work; Gate 2 needed no
    extra revocation logic), the *same* signature works again once the
    new owner reactivates (explicitly documented as a disclosed trust
    boundary, not silently assumed), and nonce state survives ownership
    transfer/reactivation unchanged. ✔

## 8. Vulnerabilities discovered

None in the contract logic. One tooling bug during test development: an
early version of a test in `attack 8` asserted the wrong error (expected
`InvalidSignature`, contract correctly reverted with `InvalidNonce`
because the nonce check runs first and the tampered value happened to
collide with it) — this was a test-authoring mistake, not a contract bug.
Fixed by rewriting the test to target a case that actually isolates the
signature check (rewriting a *future*-nonce intent's nonce down to the
current counter, which passes the nonce check but must still fail
signature verification).

One disclosed-but-not-fixed gas-griefing consideration identified during
self-audit: `execute`'s low-level `target.call` copies all returndata
into memory before the success check, so a malicious `target` that
reverts with a very large return payload inflates the caller's gas cost
for that specific call. This is **self-griefing only** — the caller
(whoever submits the `execute` transaction) pays for their own call's
memory expansion; it does not let an attacker drain funds, corrupt state,
bypass authorization, or grief *other* users' transactions. Deferred
rather than fixed now: the standard mitigation (a bounded-returndata /
"excessively safe call" assembly pattern) adds real complexity for a
low-severity, self-limited issue, which conflicts with this gate's
explicit "minimal attack surface, no fake sophistication" instruction.
Recorded here so it isn't rediscovered as if new in a later gate.

## 9. Vulnerabilities fixed

None required beyond the test-authoring fix in section 8 — the
first working implementation passed the full attack campaign. As with
Gate 1, this should be read with appropriate skepticism: the design
decisions (nonReentrant blocking *all* nested calls regardless of
agent/nonce, checked-arithmetic nonce increment, whole-transaction revert
on call failure, live registry check) were made *in response to* the
brief's threat questions before writing code, not discovered by attacking
a naive first draft. Only the gas-griefing note in section 8 was found
this way.

## 10. Regression tests added

Every attack scenario in section 7 has a dedicated, named regression
test (see file list in section 1). The `type(uint256).max` boundary test
and the three reentrancy variants are the ones most likely to silently
regress if the contract is ever refactored, since they test properties
that are easy to accidentally weaken (e.g. switching to `unchecked`
arithmetic for gas savings, or narrowing `nonReentrant` to only guard
part of the function).

## 11. Important design decisions

- **Monotonic per-agent nonce, not a bitmap** — mandated by the brief;
  full reasoning in `docs/adr/0002-monotonic-per-agent-nonce.md`.
- **`nonReentrant` blocks ALL nested `execute` calls**, not just
  same-nonce or same-agent ones. A legitimate independent intent
  triggered from within another intent's external call must be submitted
  as its own top-level transaction instead. Chosen over a narrower guard
  because it removes an entire class of "what interleaved state is safe"
  reasoning for this gate and everything built on top of it (mandate
  accounting, daily caps, etc. in later gates would each need to
  re-justify their own reentrancy safety otherwise).
- **Whole-transaction revert on failed external call**, nonce not
  consumed. Chosen over "catch the failure, still consume the nonce" so
  that the contract can never end up in either of the two states the
  brief calls out as specifically unacceptable (success with a reusable
  nonce, or failure with a permanently burned one) — full atomicity
  makes both structurally impossible rather than requiring a proof that
  they don't co-occur.
- **Checked (not unchecked) arithmetic for nonce increment.** Reverts at
  `type(uint256).max` instead of wrapping to 0. A wraparound would be a
  genuine replay bypass (re-permits nonce 0), not merely an unreachable
  edge case not worth guarding.
- **No custody, no mandate/policy enforcement yet** — `value` is
  forwarded from the caller's own `msg.value` for that transaction only;
  `policyHash` is bound into the signature (can't be forged or altered)
  but not yet checked against anything. Both are explicitly out of scope
  per the brief and are called out in `docs/protocol-spec.md` section 11
  so nothing downstream assumes they're enforced.

## 12. Remaining assumptions

- Agent signing keys are EOAs (inherited from Gate 1's same limitation;
  `AgentExecutionGuard` also uses plain `ECDSA.recover`). See
  `docs/threat-model.md`.
- `AgentRegistry.transferAgentOwnership` does not rotate the agent's
  signing key, so a previous operator who retains that key can still
  produce valid intents after a transfer, once the new owner reactivates
  without also re-registering under a fresh key. This is a disclosed
  business-process trust boundary, not a code defect — see
  `docs/threat-model.md`, "Gate 2 status".
- Off-chain infrastructure (whoever holds the agent's private key and
  decides what to sign) is trusted to construct honest intents in the
  first place; this contract only enforces that a submitted intent is
  the one that was actually signed, by an active agent, exactly once —
  it has no opinion on whether the intent itself was a good idea. That's
  what PolicyRegistry/mandate enforcement (a later gate) is for.
- Signature malleability protection is inherited from OpenZeppelin's
  `ECDSA.recover` (v5.6.1) and was not independently re-tested here — the
  same posture as Gate 1's report, treated as OZ's tested guarantee.

## 13. Remaining risks

- **NOT PROVEN** beyond the 60-iteration seeded property test and the
  hand-written boundary cases: no true fuzzing (Foundry) has been run.
  See section 5.
- No static analysis tool was run (same network-access gap as Gate 1;
  Slither etc. were not reachable in this sandbox).
- The gas-griefing consideration in section 8 is unresolved by design
  choice, not by oversight, but it is unresolved.
- Gate 2 alone authorizes execution of *arbitrary* calldata to *arbitrary*
  targets for *any* active agent, with no spending limit and no allowed-
  target restriction. This is expected and safe only because nothing
  should deploy `AgentExecutionGuard` with real funds reachable through
  it until PolicyRegistry/mandate enforcement (a later gate) exists. This
  is stated plainly so it cannot be missed: **do not fund or connect this
  contract to a real wallet yet.**

## 14. Exact Git commit SHAs

On branch `feat/execution-intent-nonce`, based on Gate 1's `d841056` on `main`:

- `bc2582b` — Implement per-agent execution nonce + EIP-712 intent hashing
- `3b866ce` — Add test-only mock contracts for Gate 2 adversarial testing
- `572962c` — Add adversarial nonce/replay/reentrancy tests for AgentExecutionGuard
- `0d4c8e6` — Add real AgentRegistry integration tests, incl. ownership-transfer edge case
- `2de2d05` — Add seeded property tests for nonce invariants (Foundry unavailable)
- one further commit adds this documentation set (ADR-0002, protocol-spec
  and threat-model updates, this report) — see the branch's most recent
  commit for its exact SHA.

## 15. Branch name

`feat/execution-intent-nonce`

## 16. Whether the branch was pushed successfully

Yes — pushed to `origin/feat/execution-intent-nonce`. **Not merged into
`main`**, per the brief's explicit instruction not to auto-merge.

## 17. Whether Gate 2 should be considered PASS or FAIL

**PASS for its stated, narrow scope**: nonce and execution-intent
foundation, replay protection, reentrancy safety, and correct integration
with Gate 1's live agent-lifecycle state. All 13 brief-mandated attack
scenarios behave as specified; 67/67 tests pass including Gate 1's suite
unchanged.

This is explicitly **not** a claim that `AgentExecutionGuard` is safe to
deploy with real funds — it authorizes arbitrary calldata/targets with no
spending limits, has not been fuzzed with a real fuzzer, and has not had
static analysis run against it. Those are accurately scoped to later
gates (PolicyRegistry, mandate enforcement) and to tooling this sandbox
could not reach, respectively — not silently dropped.

## 18. Why

The three properties the brief identifies as most important —
"successful execution + reusable nonce never happens", "failed execution
+ permanently consumed nonce never happens unless justified", and
"reentrancy cannot bypass nonce consumption" — are each guaranteed
structurally (by atomic whole-transaction revert semantics and a
blanket reentrancy guard) rather than merely tested-and-hoped-not-broken,
which is why the design decisions in section 11 are trusted over the
absence of a fuzzer-found counterexample. The remaining gaps (fuzzing
depth, static analysis, gas-griefing hardening) are real and are stated
as such rather than glossed over, which is why this is a scoped PASS and
not a claim of "secure" or "production-ready" — neither of those words
apply to a single-agent-authorization gate with no fund-custody model
yet.
