# Gate 4A report: call authorization (target+selector, maxTxValue)

## 1. Architecture chosen

- **Paired `(target, selector)` authorization**: a single mapping keyed
  by `keccak256(abi.encode(target, selector))`, replacing Gate 3's two
  independent allow-lists.
- **Native transfers as a structurally separate authorization
  dimension**: `mapping(policyId => target => bool)`, never sharing a
  key-space with function-call selectors.
- **Calldata classification in `AgentExecutionGuard`** (not
  `PolicyRegistry`): every intent's `data` is classified into
  `NativeTransfer` (length 0), `FunctionCall` (length ≥4, selector =
  first 4 bytes), or `Malformed` (length 1–3, never authorized,
  unconditionally, no mapping lookup performed).
- **One combined external call**, `PolicyRegistry.checkAuthorization`,
  resolving agent-binding, active/time-window state, `maxTxValue`, and
  target+selector authorization together, returning five distinct
  values so `AgentExecutionGuard` can raise a specific error per failure
  reason.
- **`maxTxValue` enforced in `AgentExecutionGuard`**, configured in
  `PolicyRegistry` — same configuration/enforcement split as
  `dailyLimit` will need in Gate 4B.

## 2. Why it was chosen

Full reasoning in `docs/adr/0005-paired-target-selector-authorization.md`.
Summary: the paired mapping closes the Cartesian-product bug
structurally (there is no representation in which "A+X and B+Y are
authorized" can be misread as "A+Y or B+X are also authorized" — every
entry is one exact tuple). Native transfers as a separate dimension
closes a second, related collision risk (selector `0x00000000` is a
real, reachable selector; overloading it to also mean "no calldata"
would create exactly the same class of accidental cross-authorization
the Cartesian-product fix exists to prevent). The single combined
`checkAuthorization` call keeps authorization overhead at O(1) regardless
of how many mandate dimensions this or a future gate adds, per the
brief's bounded-gas requirement (Part 12).

## 3. Files changed

- `contracts/PolicyRegistry.sol` (rewritten: paired authorization,
  `CallKind`, `checkAuthorization`)
- `contracts/AgentExecutionGuard.sol` (rewritten: calldata
  classification, `maxTxValue`/target-selector checks, new errors)
- `contracts/interfaces/IPolicyRegistry.sol` (rewritten: `CallKind`,
  `checkAuthorization`)
- `contracts/mocks/MockPolicyRegistry.sol` (rewritten to match)
- `contracts/mocks/TestTargets.sol` (added `SelectorTarget`; `foo` made
  `payable` to support the `maxTxValue` boundary test)
- `contracts-test/PolicyRegistry.test.ts` (rewritten for the new model,
  including the Cartesian-product regression at the registry level)
- `contracts-test/AgentExecutionGuard.test.ts`,
  `.integration.test.ts`, `.fuzz.test.ts`, `.remediation.test.ts`
  (adapted: authorize native-transfer/function-call pairs the existing
  tests rely on, since authorization is now actually enforced)
- `contracts-test/AgentExecutionGuard.gate4a.test.ts` (new — the
  dedicated 25-scenario attack campaign, mandatory Cartesian-product
  regression end-to-end, and seeded property tests)
- `docs/adr/0005-paired-target-selector-authorization.md` (new)
- `docs/protocol-spec.md`, `docs/threat-model.md` (updated)
- `docs/gate-4a-call-authorization.md` (this file)

## 4. Contracts changed

`PolicyRegistry` and `AgentExecutionGuard` (both rewritten in place, no
new production contracts). Gate 1's `AgentRegistry` untouched.

## 5. Tests added

- `PolicyRegistry.test.ts`: 37 tests (rewritten from Gate 3's 30 —
  net +7, but effectively a full replacement given the structural model
  change).
- `AgentExecutionGuard.gate4a.test.ts`: 25 tests — the full attack
  campaign (Part 9), the mandatory Cartesian-product regression
  end-to-end (Part 10), and 2 seeded property tests (Part 11).
- Existing Gate 2/3/remediation test files: adapted, not net-new, but
  every adaptation required either authorizing a specific
  target/selector or native-transfer pair, or fixing a test that had
  been (unintentionally) exercising the new `Malformed` rejection path.

**Total suite: 141 passing, 0 failing** (up from 116 pre-Gate-4A).

## 6. Existing tests result

All pre-Gate-4A tests (Gate 1: 24, Gate 2: 36+6+2, remediation: 11,
Gate 3/PolicyRegistry: 37 post-rewrite) pass after adaptation. Two test
bugs were found and fixed during adaptation, not contract bugs:

- `AgentExecutionGuard.test.ts`'s calldata-tamper test originally used
  1-byte calldata (`"0x01"`/`"0x02"`), which is `Malformed` under the new
  classification and therefore unconditionally rejected regardless of
  signature validity — the test would have "passed" for the wrong
  reason (always failing at the authorization check, never actually
  exercising signature verification). Fixed to use real 4-byte selectors.
- The Gate 4A fuzz-style random-calldata test in
  `AgentExecutionGuard.fuzz.test.ts` generated calldata of random length
  0–63 bytes without regard for the new 1–3-byte `Malformed` band;
  iterations landing in that band would now revert unexpectedly. Fixed
  by rounding any 1–3 byte draw up to 4 bytes (that specific fuzz test's
  purpose is calldata-forwarding fidelity, not `Malformed` rejection,
  which has its own dedicated, deliberate coverage elsewhere).

## 7. New adversarial tests result

25/25 in `AgentExecutionGuard.gate4a.test.ts`, all passing after two bugs
were found and fixed during test authoring itself (see section 8) —
neither was a contract bug.

## 8. Fuzzing result

Two seeded property tests (not Foundry — same sandbox network
restriction as every prior gate):

1. Randomized `(target, selector)` lookups against a policy authorizing
   only the "diagonal" of a 4×4 target/selector grid — 30 iterations
   confirming `authorized(target, selector)` matches the expected
   diagonal-only pattern, not the full grid.
2. Randomized calldata-argument tampering (same selector, different
   argument value) across 10 iterations, confirming every tampered
   variant is rejected via `InvalidSignature`.

Two bugs were found and fixed while authoring this file, both test
bugs, not contract bugs:

- `SelectorTarget.foo(uint256)` was not `payable`; the `maxTxValue`
  exact-boundary test attempted to send `value` to it and reverted with
  an EVM-level non-payable rejection, surfaced through
  `AgentExecutionGuard`'s `ExecutionFailed` wrapping. Fixed by marking
  `foo` `payable`.
- The calldata-tamper property test initially used an incrementing
  nonce (`BigInt(i)`) across iterations that never actually succeed
  (every iteration's tampered call is expected to revert). Since a
  reverted call never consumes a nonce, `nextNonce[agent]` stayed at 0
  throughout, so every iteration after the first attempted a stale
  nonce (`InvalidNonce`) instead of exercising the intended signature
  check. Fixed by keeping `nonce: 0n` fixed across all iterations,
  matching the fact that no iteration ever successfully advances it.

## 9. Cartesian-product regression result

**PASS**, proven at two levels:

- `PolicyRegistry.test.ts`, "Cartesian-product regression" describe
  block: direct `isCallAuthorized`/`checkAuthorization` calls against a
  policy authorizing `(A, X)` and `(B, Y)` confirm `(A, Y)` and `(B, X)`
  both return `false`.
- `AgentExecutionGuard.gate4a.test.ts`, "Cartesian-product regression —
  end to end through execute()": the same scenario driven through
  actual signed intents and real `execute()` calls — `A+X` and `B+Y`
  both succeed, `A+Y` and `B+X` both revert with `CallNotAuthorized`.

## 10. Empty-calldata semantics

Chosen: **Option B** from the brief — native transfer is a separate
authorization type (`mapping(policyId => target => bool)`), not an
overload of selector `0x00000000`. Full rationale in ADR-0005, Decision
2. Proven by dedicated tests: authorizing a native transfer for a target
does not authorize any function call on it (`PolicyRegistry.test.ts`),
and vice versa; `Malformed` (1–3 byte) calldata is never authorized even
when both a native-transfer permission AND a `0x00000000`-selector
function-call permission exist simultaneously for the same target
(`PolicyRegistry.test.ts`, "checkAuthorization: CallKind.Malformed is
never authorized regardless of any stored entry").

## 11. maxTxValue enforcement

Enforced in `AgentExecutionGuard.execute`, configured in
`PolicyRegistry`, checked before nonce consumption and before the
external call. Exact boundary (`value == maxTxValue`) passes;
`maxTxValue + 1` reverts with `MaxTxValueExceeded`; `value == 0` behaves
correctly (trivially within any non-negative `maxTxValue`); the
`type(uint256).max` boundary is inherited from the remediation gate's
`msg.value == value` check, which itself relies on Solidity 0.8 checked
arithmetic elsewhere in the contract (nonce increment) — no new overflow
surface was introduced by this gate's `uint128`-vs-`uint256` comparison
(`value` is `uint256`, `maxTxValue` is `uint128`; Solidity implicitly
widens `maxTxValue` to `uint256` for the comparison, which is safe and
exact, not truncating).

## 12. Remaining limitations

- **No `dailyLimit`/`approvalThreshold` enforcement** — Gate 4B.
- **No argument-level authorization** — a policy authorizes calling a
  function, not any particular argument values; `calldataHash` still
  binds the exact bytes used, but there is no allow-list over argument
  content. Explicitly out of scope for this gate, not silently assumed
  otherwise — see ADR-0005, "what this gate deliberately does NOT do."
- **No ERC-20 accounting** — `maxTxValue` and this entire gate concern
  native ETH `value` only.
- **No on-chain enumeration** of a policy's full set of authorized
  `(target, selector)` pairs or native-transfer targets — only
  point-lookups (`isCallAuthorized`, `isNativeTransferAuthorized`).
  Enumerability, if needed by off-chain tooling, is available via the
  `CallAuthorized`/`NativeTransferAuthorized` events emitted at creation,
  not via on-chain storage iteration (which would violate the
  bounded-gas requirement).
- **No static analysis tool was run** — same sandbox network-access gap
  as every prior gate (Slither etc. unreachable).
- **No true Foundry fuzzing** — same sandbox network-access gap; the
  seeded JS property tests in section 8 are a strictly weaker substitute
  (no shrinking, no coverage-guided generation, fixed iteration counts).

## 13. Security findings

Two collision risks were identified and closed during this gate's own
design process, before any test was written against a naive version —
this is stated precisely, not rounded up to "found by testing":

1. The Cartesian-product bug itself (Gate 3's actual shipped design) —
   this one *was* a real bug in already-existing, already-tested code,
   not a design-time catch. It is the entire reason this gate exists.
2. The `Malformed`-calldata-defaulting-to-`bytes4(0)` collision (an
   early draft of this gate's own code, caught during design review
   before being tested, let alone shipped) — see ADR-0005, Decision 2.

No vulnerabilities were found by the adversarial test campaign itself
(section 7) that required a contract-code fix — every failure
encountered while authoring `AgentExecutionGuard.gate4a.test.ts` (section
8) was a test bug, not a contract bug. As with every prior gate's report,
this is stated with the same caveat: it reflects one reviewer working
within a single session, not an independent audit, and the absence of a
real fuzzer (section 12) means the state space actually explored is
smaller than the brief's "where practical, fuzz" instruction ideally
calls for.

## 14. Git commits

See the assistant's final message in this conversation for exact commit
SHAs (commits are made immediately after this report, in logical order:
contract redesign, test adaptation, new adversarial suite, documentation).

## 15. Branch

`feat/gate4-call-authorization`

## 16. Push status

Confirmed after commits — see the assistant's final message.

## 17. PASS / FAIL

**PASS for Gate 4A's stated, narrow scope**: paired target+selector
authorization (Cartesian-product bug closed, proven at two levels),
explicit native-transfer semantics (collision-free by construction, not
merely by convention), and `maxTxValue` enforcement, all integrated into
`AgentExecutionGuard.execute` with a documented, gas-conscious check
ordering that guarantees a failed authorization check never burns a
nonce. 141/141 tests pass across the full suite, including every
pre-existing test from Gates 1–3 and the remediation gate, unmodified in
intent (only adapted to explicitly authorize what they were always
implicitly relying on being allowed).

This is **not** a claim that the protocol is safe to deploy with real
funds: `dailyLimit`/approval accounting (Gate 4B) is still entirely
unenforced, no static analysis has been run, and fuzzing coverage is a
seeded JS substitute rather than a real fuzzer. Per the brief: Gate 4B is
not started, target/selector redesign is complete (not deferred), and
this branch has not been merged.
