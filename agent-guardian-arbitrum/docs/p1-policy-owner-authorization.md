# P1 report: policy-owner authorization

## 1. Is the Codex P1 exploitable?

**Yes, confirmed exploitable pre-fix.** Not assumed — proven by a real
adversarial test (`contracts-test/P1PolicyOwnerAuthorization.poc.test.ts`)
against the actual, non-mocked `AgentRegistry` + `PolicyRegistry` +
`AgentExecutionGuard` stack, run against the code as it existed on `main`
before this branch's fix. The test passed (i.e., the exploit succeeded)
before the fix, and now fails with a specific, expected revert
(`PolicyOwnerMismatch`) after it.

## 2. Exact attack path

1. Legitimate owner registers Agent A via `AgentRegistry.register`
   (requires Agent A's own EIP-712 signature — this step is genuine and
   not attacker-controlled).
2. Legitimate owner creates a restrictive Policy A via
   `PolicyRegistry.createPolicy` (small `maxTxValue`, narrow target
   authorization).
3. Agent A's own key — the exact same key that legitimately signs
   `ExecutionIntent`s, and which nothing prevented from also calling
   `PolicyRegistry` directly — calls `createPolicy` itself, naming
   itself as `agent` (becoming `owner` automatically, since `owner:
   msg.sender`), with an arbitrarily permissive `maxTxValue` and
   authorizing whatever target it wants.
4. Agent A signs a valid `ExecutionIntent` referencing this new
   self-created `policyHash`, not the legitimate owner's Policy A.
5. `AgentExecutionGuard.execute()` is called. Every check in the
   pre-fix implementation passes:
   - `isActiveAgent(agent)` — true (legitimate owner hasn't deactivated).
   - `boundAgent == agent` (`PolicyAgentMismatch` check) — true (the
     attacker set `agent = agentA` in its own `createPolicy` call).
   - `policy.active` — true (freshly created, active by default).
   - `withinWindow`, `valueAllowed`, `callAllowed` — all true (the
     attacker set these permissively in its own policy).
   - nonce — valid (the agent's own sequential nonce).
   - signature — valid (genuinely signed by the agent's own key).
6. Execution succeeds, transferring far more value to a far broader set
   of targets than the legitimate owner's actual Policy A ever
   authorized.

## 3. Exact vulnerable function/file/line

`contracts/PolicyRegistry.sol`, `createPolicy` (pre-fix lines ~156–207 on
`main`'s Gate-4A version): takes `agent` as a raw parameter with only a
non-zero check, and sets `owner: msg.sender` with no verification
whatsoever that `msg.sender` has any relationship to the named `agent`
in `AgentRegistry`.

Compounding this, `contracts/AgentExecutionGuard.sol`'s `execute()`
(pre-fix): checked `boundAgent == agent` but never consulted
`AgentRegistry.ownerOf(agent)` or compared it to anything from
`PolicyRegistry` — the policy's `owner` field was stored by
`PolicyRegistry` but never read by `AgentExecutionGuard` at all before
this fix.

## 4. Root cause

`policyHash -> agent` binding (established by the remediation gate,
ADR-0004) proves a policy is *for* a given agent. It does not, and was
never designed to, prove the policy's *content* reflects what that
agent's legitimate controller actually authorized.
`PolicyRegistry`'s deliberate architectural independence from
`AgentRegistry` (ADR-0003/0004) meant no contract anywhere ever checked
this second, distinct relationship.

## 5. Security invariant that was missing

> A policy referenced by an execution intent must not only be bound to
> the correct agent — it must have been authorized by the legitimate
> owner/controller of that agent, verified against AgentRegistry's
> *current* state, not a snapshot or self-assertion.

## 6. Chosen remediation architecture

**Option B**: `PolicyRegistry` is unchanged (creation remains
permissionless); `AgentExecutionGuard.execute` additionally requires
`PolicyRegistry`'s recorded policy `owner` to equal
`AgentRegistry.ownerOf(intent.agent)`, checked live via one additional
external view call per execution. Full analysis in
`docs/adr/0006-policy-owner-authorization.md`.

## 7. Why alternative fixes were rejected

- **Option A** (check ownership only at `createPolicy` time, inside
  `PolicyRegistry`): rejected — a creation-time-only check has the same
  staleness problem the remediation gate already fixed for
  `isActiveAgent`. A policy created under an old owner would remain
  validly executable forever even after ownership transfers to someone
  who never approved it.
- **Naive fix rejected explicitly, per the brief's own instruction**:
  simply adding `policy.owner == agent` was not implemented — that
  conflates "who created the policy" with "who controls the agent",
  which are only the same thing by coincidence, not by any enforced
  relationship; it would not have closed the actual gap at all (the
  attacker in the PoC *is* `policy.owner == agent`, trivially, since it
  named itself as both).
- **Option C** (owner signs an EIP-712 authorization over policy
  creation): rejected as unnecessarily large — a creation-time
  signature has the identical staleness problem as Option A and would
  still need Option B's live check to correctly handle ownership
  transfer, making the extra signature scheme mostly redundant for what
  it would add.

## 8. Ownership-transfer semantics

**Explicitly defined, not silently chosen** (see ADR-0006 for full
detail): if Agent X's ownership transfers from Owner A to Owner B after
Owner A created Policy X, **Policy X becomes permanently unusable**,
including after Owner B reactivates the agent — Owner B must create
their own fresh policy. This falls directly out of policy immutability
(ADR-0003) combined with live ownership verification, requiring zero
additional code in `AgentRegistry` or `PolicyRegistry`. The agent's
signing key itself is entirely unaffected by the transfer — a policy the
new owner establishes works immediately with the same key, no
re-registration or key rotation needed. Both halves are proven by
dedicated tests in `contracts-test/AgentExecutionGuard.integration.test.ts`.

## 9. Tests added

- `contracts-test/P1PolicyOwnerAuthorization.poc.test.ts` (new, 4
  tests): the Phase 2 PoC itself (now proving the exploit is blocked,
  with a comment trail documenting it previously succeeded pre-fix), a
  positive control (legitimate policy still works), a total-stranger
  variant, and a structural test confirming `owner` is unconditionally
  `msg.sender` (no parameter exists to spoof it).
- `contracts-test/AgentExecutionGuard.integration.test.ts` (rewritten
  ownership-transfer section, 6→7 tests net): two of the three original
  "ownership transfer lifecycle edge case" tests were rewritten to
  reflect the new, correct invariant (old policy permanently dead after
  transfer; new owner's fresh policy works immediately with the same
  agent key) rather than the pre-fix behavior they previously asserted.
- `contracts/mocks/MockAgentRegistry.sol` / `MockPolicyRegistry.sol`:
  extended (not net-new test files, but necessary infrastructure) to
  model the owner relationship the P1 fix introduces —
  `MockAgentRegistry.ownerOf`/`setOwner`, `MockPolicyRegistry`'s
  `Binding.owner` field and `setFullBinding`.

### Security test matrix coverage

| # | Scenario | Result | Where |
|---|---|---|---|
| 1 | legitimate owner creates policy | PASS | `P1...poc.test.ts`, positive control |
| 2 | unrelated attacker creates policy for another agent | creation succeeds (permissionless by design); **execution REVERTs** | `P1...poc.test.ts`, "total stranger" |
| 3 | agent itself attempts unauthorized policy creation | creation succeeds (permissionless by design); **execution REVERTs** | `P1...poc.test.ts`, main PoC |
| 4 | attacker copies legitimate owner's address into calldata | REVERT (structurally impossible to construct — no `owner` parameter exists to spoof; `owner` is unconditionally `msg.sender`) | `P1...poc.test.ts`, "spoof" test |
| 5 | legitimate policy executes | PASS | `P1...poc.test.ts`, positive control |
| 6 | attacker-created permissive policy | REVERT (`PolicyOwnerMismatch`) | `P1...poc.test.ts`, main PoC |
| 7 | Policy A cannot authorize Agent B | REVERT (`PolicyAgentMismatch`, pre-existing, unaffected) | `AgentExecutionGuard.gate4a.test.ts` #18 |
| 8 | revoked policy | REVERT (`PolicyNotActive`, pre-existing, unaffected) | `AgentExecutionGuard.gate4a.test.ts` #19 |
| 9 | inactive agent | REVERT (`AgentNotActive`, pre-existing, unaffected) | `AgentExecutionGuard.gate4a.test.ts` #20 |
| 10 | ownership transfer behavior | explicitly tested (both directions: old policy dies, new policy works) | `AgentExecutionGuard.integration.test.ts` |
| 11 | replay of policy authorization | no new signature scheme was introduced, so no new replay surface exists; `createPolicy`'s pre-existing exactly-once semantics (unaffected) already prevent policy re-creation replay | `PolicyRegistry.test.ts` (pre-existing) |
| 12 | modified policy parameters after signing | impossible by construction — policies are immutable (ADR-0003), unaffected by this fix | `PolicyRegistry.test.ts` (pre-existing) |
| 13 | cross-chain/domain replay | N/A — no new EIP-712 domain was introduced; existing chainId/verifyingContract protections untouched | Gate 1/2 suites (pre-existing) |
| 14 | existing Gate 4A authorization tests | ALL PASS | full suite, see below |

## 10. Full test result

**148/148 passing, 0 failing.**

## 11. Existing Gate 4A tests result

All 25 attack-campaign tests, the Cartesian-product regression (both
levels), and the property tests in
`contracts-test/AgentExecutionGuard.gate4a.test.ts` pass unmodified —
this fix added a check that happens after the existing target/selector
and maxTxValue checks in every code path those tests exercise, and none
of those tests' policies were ever created by anyone other than the
correctly-registered owner, so the new check is transparent to them.

## 12. Remaining limitations

- `dailyLimit`/`approvalThreshold` — still entirely unenforced, Gate 4B.
- After ANY ownership transfer, the new owner must recreate every policy
  they want to keep using (immutability means no "reassign owner" path
  exists) — a real operational cost of the safe default, documented in
  ADR-0006, not hidden.
- No static analysis or true Foundry fuzzing was run against this fix —
  same sandbox network-access constraint as every prior gate.
- This fix does not address whether `AgentRegistry` itself could have an
  analogous "who is allowed to register on behalf of whom" gap —
  `AgentRegistry.register` already requires the agent's own signature
  (closing a comparable but structurally different gap at a different
  layer, per Gate 1's design) and was out of scope for this P1, which
  was specifically about `PolicyRegistry`.

## 13. Commit SHA

See the assistant's final message in this conversation for exact commit
SHAs on this branch.

## 14. Branch

`fix/policy-owner-authorization`, branched from `main` (post-Gate-4A-merge,
commit `19efeb2`). The first commit on this branch is a cherry-pick of
`bb7e00d` (the post-hostile-review `uint128`/`uint256` boundary
regression tests requested in the prior conversation turn, which did not
make it into the Gate 4A PR merge — see the note in the assistant's
message immediately preceding this report).

## 15. Push status

Confirmed after commits — see the assistant's final message.
