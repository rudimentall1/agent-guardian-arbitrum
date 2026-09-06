# Remediation gate report: msg.value binding + policy ownership binding

Pre-Gate-4 security remediation, addressing two architectural gaps found
by reviewing Gate 2 (`AgentExecutionGuard`) and Gate 3 (`PolicyRegistry`)
together rather than in isolation. Full ExecutionGuard/PolicyRegistry
integration (mandate content, daily spend, approval flow) is explicitly
NOT part of this gate — see "Remaining Gate 4 requirements" below.

## 1. Files changed

**Contracts:**
- `contracts/AgentExecutionGuard.sol` (modified) — `ValueMismatch` check,
  `PolicyAgentMismatch`/`PolicyNotActive` checks, new `IPolicyRegistry`
  dependency, updated constructor (now takes `policyRegistry` address),
  updated NatSpec.
- `contracts/PolicyRegistry.sol` (modified) — `agent` field on `Mandate`,
  `agent` parameter on `createPolicy`, `policyIdOfHash` reverse mapping,
  `resolvePolicyBinding` and `agentOf` view functions, updated NatSpec.
- `contracts/interfaces/IPolicyRegistry.sol` (new) — the single function
  `AgentExecutionGuard` depends on.
- `contracts/mocks/MockPolicyRegistry.sol` (new, test-only).

**Tests:**
- `contracts-test/AgentExecutionGuard.remediation.test.ts` (new) — the
  dedicated test matrix this gate's brief required, run against real
  `AgentRegistry` + real `PolicyRegistry` (not mocks).
- `contracts-test/AgentExecutionGuard.test.ts`, `.integration.test.ts`,
  `.fuzz.test.ts` (modified) — adapted to the new constructor signature
  and the new checks; two pre-existing tests' expected revert reason
  changed (see section 8).
- `contracts-test/PolicyRegistry.test.ts` (modified) — adapted to the new
  `agent` parameter; added coverage for `resolvePolicyBinding`/`agentOf`.

**Docs:**
- `docs/adr/0004-msg-value-and-policy-agent-binding.md` (new).
- `docs/protocol-spec.md`, `docs/threat-model.md` (updated).
- This file.

Also present on this branch, copied (not merged via `git merge`) from
the still-separate Gate 2 and Gate 3 branches so this remediation could
be implemented against both contracts together: all Gate 1/2/3 contracts,
tests, and docs. See section 12 for the git mechanics.

## 2. Tests added

11 new tests in `AgentExecutionGuard.remediation.test.ts`:

- **Fix 2 matrix (5):** Agent A + Policy A → PASS; Agent A + Policy B →
  REVERT; Agent B + Policy A → REVERT; a revoked policy rejected even
  with correct agent binding; an unknown `policyHash` rejected rather
  than silently treated as "no policy."
- **Fix 1 scenarios (5):** all four scenarios required by the brief
  (signed 0/sent ETH, signed 1/sent 2, signed-max/modified-value,
  replay-with-modified-value), plus one positive-control test confirming
  a correctly value-matched call succeeds and leaves the guard's balance
  at exactly 0.
- **Combined (1):** a correctly value-matched intent still fails on
  `PolicyAgentMismatch` if it references the wrong agent's policy —
  confirms the two fixes are independent, not accidentally
  order-dependent or mutually masking.

Plus adaptation of 67 pre-existing tests (Gate 2: 43, Gate 3: 26 —
actually 24+43+26 across all three prior gates once combined; see section
9's exact count) to the new constructor/check surface, two of which now
assert a different (but still correct) revert reason — detailed in
section 8.

**Full suite on this branch: 109 passing, 0 failing.**

## 3. Attacks prevented

- **Stuck-value accumulation / cross-call fund leakage.** Before this
  fix: send more ETH than signed → excess has no withdrawal path, stuck
  in the contract; a later, unrelated `execute` call whose signed
  `value` happened to be ≤ the stuck balance could succeed using funds
  nobody signed for moving in that call. Closed by requiring
  `msg.value == value` exactly, verified by a positive-control test
  confirming the guard's balance is always exactly 0 after any
  successful call.
- **Underpayment silently succeeding off stale balance.** Same root
  cause as above, opposite direction: send less ETH than signed, relying
  on the contract already holding enough from a previous mismatched
  call. Also closed by the same equality check.
- **Cross-agent policy reference.** Before this fix: an intent for Agent
  A could reference any `policyHash` that resolves to *any* active
  policy, regardless of which agent that policy was actually meant for,
  because nothing checked the relationship — `policyHash` was accepted
  and signed over, but never looked up against anything. Closed by
  requiring the resolved policy's recorded `agent` to equal the intent's
  own `agent`, proven directly by the three-cell test matrix the brief
  required.
- **Referencing a revoked or never-created policy.** Not explicitly
  named in the brief's two fixes, but a natural extension of implementing
  Fix 2 correctly: a `policyHash` that resolves to an inactive or
  nonexistent policy is rejected (`PolicyNotActive` /
  `PolicyAgentMismatch` respectively), rather than the binding check only
  covering the "wrong agent" case and accidentally leaving "no agent" or
  "revoked" as silent passes.

## 4. Remaining Gate 4 requirements

Explicitly not implemented by this remediation gate, per the brief's own
scope limits:

- **Mandate content enforcement.** `PolicyRegistry.isCallAllowedByPolicy`
  (from Gate 3) checks `maxTxValue`/allowed target/allowed selector, but
  `AgentExecutionGuard.execute` does not call it. An intent can currently
  reference a correctly-bound, active policy and still send an amount, to
  a target, or via a selector the policy's mandate would reject if
  actually checked.
- **`dailyLimit` accounting.** Stored in `PolicyRegistry`, not tracked or
  enforced anywhere.
- **Approval system.** No approval flow exists in any contract in this
  repository.
- **Full ExecutionGuard/PolicyRegistry integration** beyond the identity
  binding this gate adds — e.g., a `PolicyRegistry` call site inside
  `execute` that actually gates the transaction on mandate content, not
  merely on "does this policy belong to this agent."

## 5. Design decisions

See `docs/adr/0004-msg-value-and-policy-agent-binding.md` for full
reasoning on both fixes, the alternatives considered and rejected for
each, and why `AgentExecutionGuard` — not `PolicyRegistry`, not off-chain
tooling — is the correct place to enforce both invariants.

One additional implementation decision worth surfacing here: both new
checks (`ValueMismatch`, `PolicyAgentMismatch`/`PolicyNotActive`) were
placed *before* nonce and signature verification in `execute`'s check
ordering, for the same reason Gate 2's original checks were ordered the
way they were — cheap, state-independent checks fail fast and save gas
on malformed calls, and neither new check grants any privilege on its
own (both are read-only until the point nonce consumption happens). One
side effect of this ordering, caught while adapting existing tests (see
section 8): a `policyHash`-tampering attack that used to surface as
`InvalidSignature` now more often surfaces as `PolicyAgentMismatch`
instead, since an attacker-substituted hash rarely happens to resolve to
the correct agent. Both outcomes are correct rejections; only the
specific error name differs.

## 6. Remaining assumptions

- Everything already listed in `docs/threat-model.md`'s Gate 1/2/3
  sections still applies unchanged (EOA-only agent keys, agent-key
  persistence across `AgentRegistry` ownership transfer, off-chain trust
  in intent construction, etc.) — this remediation gate did not revisit
  those.
- `PolicyRegistry.createPolicy`'s `agent` parameter is trusted input from
  `msg.sender` (the policy owner) — nothing cross-checks that the named
  `agent` is actually registered in `AgentRegistry` at policy-creation
  time. A policy can be created naming an agent address that doesn't
  exist yet, or is currently inactive; `AgentExecutionGuard.execute`
  would still correctly reject execution for that agent via its own live
  `isActiveAgent` check, so this isn't an authorization bypass — just
  worth naming so a future integration doesn't assume `PolicyRegistry`
  validates agent existence.

## 7. Remaining risks

- **NOT PROVEN** beyond the specific scenarios tested: no fuzzing was run
  against the new checks specifically (same sandbox network-access gap
  as every prior gate — no Foundry, no Slither). The existing Gate 2
  seeded property tests (`AgentExecutionGuard.fuzz.test.ts`) were adapted
  to keep passing but were not extended to randomize `policyHash`
  bindings or value-mismatch scenarios.
- As stated in section 4, this gate deliberately leaves mandate-content
  enforcement, daily-spend accounting, and approval flow unimplemented —
  do not deploy with real funds reachable through `AgentExecutionGuard`
  until Gate 4 closes those gaps, exactly as stated in the Gate 2 and
  Gate 3 reports.

## 8. Test-authoring notes (honesty check on section 2's "0 vulnerabilities in new code" framing)

Two pre-existing Gate 2 tests needed their expected revert reason updated
after this remediation, not because the remediation broke anything, but
because the new checks legitimately intercept those specific attacks
earlier than before:

- "rejects an intent validly signed by A when the agent field is swapped
  to B after signing" — previously expected `InvalidSignature`; the
  (unchanged) `policyHash` in that test is bound to agent A, so swapping
  the `agent` field to B now trips `PolicyAgentMismatch` first. Both are
  correct rejections of the same attack; only the specific error changed.
- "rejects a signed intent with only the policyHash changed" — previously
  expected `InvalidSignature`; the substituted hash was never registered
  with any binding, so it now trips `PolicyAgentMismatch`
  (`boundAgent == address(0)`) before signature verification is reached.

Both changes are documented inline in the test file comments at the
point of change, not silently adjusted.

## 9. Test count reconciliation

Exact counts by file (not estimated):

- `AgentRegistry.test.ts` (Gate 1): 24
- `AgentExecutionGuard.test.ts` (Gate 2, adapted): 36
- `AgentExecutionGuard.integration.test.ts` (Gate 2, adapted): 6
- `AgentExecutionGuard.fuzz.test.ts` (Gate 2, adapted): 2
- `PolicyRegistry.test.ts` (Gate 3, adapted + 4 new: `resolvePolicyBinding`
  ×3, `agentOf` coverage, zero-agent-address validation): 30
- `AgentExecutionGuard.remediation.test.ts` (this gate, new): 11

**Total: 24 + 36 + 6 + 2 + 30 + 11 = 109 — matches the test runner's
reported "109 passing, 0 failing" exactly.**

## 10. Commit SHAs

See the assistant's final message in this conversation for the exact
commit list and push confirmation.

## 11. Branch

`fix/security-binding-msg-value-policy-owner`, containing (via file
copies, not `git merge`) the full Gate 1/2/3 contract and test surface
plus this gate's changes on top. Not merged into `main` or into either
feature branch.

## 12. Git mechanics note

This branch needed code from both `feat/execution-intent-nonce` (Gate 2:
`AgentRegistry` + `AgentExecutionGuard`) and `feat/policy-registry` (Gate
3: `PolicyRegistry`) to implement a fix spanning both contracts. Per the
instruction not to merge branches, no `git merge` command was used
anywhere in producing this branch: it was created from
`feat/execution-intent-nonce`, and Gate 3's files were brought in via
`git checkout feat/policy-registry -- <paths>` (a file-content checkout,
not a merge commit — no merge commit exists in this branch's history).
`docs/protocol-spec.md` and `docs/threat-model.md`, which had diverged
independently on the two source branches, were reconciled by hand
(reading both versions and manually writing the combined section) rather
than via any git merge tooling.
