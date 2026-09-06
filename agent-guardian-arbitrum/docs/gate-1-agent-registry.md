# Gate 1 report: AgentRegistry

## A. What was implemented

`contracts/AgentRegistry.sol` — a single, non-upgradeable contract
establishing agent identity and lifecycle:

- `register(agent, owner, metadataHash, signature)` — one-time,
  EIP-712-signed-by-the-agent registration. Callable by anyone (owner is
  fixed inside the signed digest, not `msg.sender`).
- `deactivate` / `reactivate` — owner-only.
- `transferAgentOwnership` — owner-only, forces `active = false` on the
  new owner until they explicitly `reactivate`.
- `isActiveAgent(address) -> bool` — the single read downstream contracts
  should use.
- `getAgent`, `ownerOf` — plain view accessors.

## B. What was tested

24 tests in `contracts-test/AgentRegistry.test.ts`, all passing. Coverage
includes every happy path and, per invariant:

- unregistered agent reads as inactive with no special-casing
- signature/owner-field hijack and mempool front-run attempts
- exactly-once registration, including an attacker who has fully
  compromised the agent's private key, against both an active and a
  deactivated prior registration
- access control on every state-changing function (non-owner rejected)
- redundant-state-transition rejection (double-deactivate, double-reactivate)
- zero-address and self-transfer edge cases
- EIP-712 domain separation: wrong verifying contract, wrong chain id,
  tampered signed field

## C. What attacks were attempted

Walked the threat-model list (see original task Phase 2) against this
contract's actual scope:

1. Unauthorized registration — mitigated by required agent signature; tested.
2. Compromised agent key rebinding an existing identity — mitigated by
   exactly-once registration; tested against both active and inactive
   states.
3. Signature replay across owners (front-run) — mitigated by owner being
   inside the signed digest; tested.
4. Cross-chain replay — mitigated by EIP-712 domain's `chainId`; tested.
5. Cross-contract replay (same bytecode, different deployment) — mitigated
   by EIP-712 domain's `verifyingContract`; tested.
6. Stale authorization after ownership change — mitigated by forcing
   `active = false` on transfer; tested.
7. Reentrancy — no external calls exist in this contract; not applicable.
8. Storage collision / initialization bugs — no proxy, single constructor
   call, no `initialize()` pattern; not applicable (see ADR-0001).
9. Denial of service — no loops, no unbounded storage, no external calls
   that could revert and block state; not applicable.
10. Signature malleability — delegated to OpenZeppelin's `ECDSA.recover`
    (v5.6.1), which already rejects malleable (high-`s`) signatures. Not
    independently re-tested here; treated as OZ's tested guarantee, not
    this repository's.
11. ERC-1271 / smart-account agent signers — **not supported**. See finding D.4.

## D. Findings

1. Initial artifact-generation bug in the sandbox compile workaround
   (`scripts/compile.js`) omitted `evm.deployedBytecode.linkReferences`
   from the solc output selection, silently producing artifacts missing
   the `deployedLinkReferences` field. This is a tooling bug in this
   repository's sandbox build script, not a contract bug — but it's
   recorded because it initially masked contract testing entirely (every
   test failed at the `getContractFactory` step with an unhelpful error).
   Fixed; regression is implicitly covered by every passing test now
   depending on a correctly-shaped artifact.
2. No contract-logic vulnerabilities were found that required a code fix
   after the initial implementation — the adversarial tests in section B
   passed against the first working version. This should be read with
   appropriate skepticism: it reflects one reviewer working within a
   single session, not an independent audit.
3. Confirmed as *not* a vulnerability, but worth stating precisely:
   `withdrawLiquidity`-style fund-draining is not applicable to this
   contract — `AgentRegistry` holds no funds and calls no other contracts.
4. **Open limitation, not fixed in this gate:** agent and owner addresses
   are assumed to be EOAs. `ECDSA.recover` cannot validate signatures
   "signed" by a smart-contract wallet (ERC-1271), so such a wallet can
   never successfully call `register` as an agent identity, nor can a
   smart-contract-wallet owner be bound by anyone else's signature in a
   way that consults its own validation logic. This is now documented in
   `docs/threat-model.md` under "Gate 1 status" rather than left for a
   later discovery.

## E. What was fixed

- The `deployedLinkReferences` artifact bug (tooling, described above).
- No Solidity-level fix was required beyond the design decisions baked
  into the first implementation (signature-bound owner field,
  exactly-once registration, forced deactivation on ownership transfer).
  These were designed in response to the threat-model questions in Phase
  1/2 of the task brief *before* writing code, not discovered by
  attacking a naive first draft — worth being explicit about, since
  "found zero bugs" is a much weaker claim when the design was reactive
  rather than adversarially tested after the fact. Only the ERC-1271 gap
  (D.4) was identified this way.

## F. Assumptions that remain

- Agent and owner addresses are EOAs (see D.4).
- The off-chain party coordinating agent-key generation and the
  `register` transaction is trusted to associate the correct `owner`
  address with the correct `agent` key before submission — this contract
  cannot verify real-world identity, only key possession.
- No mechanism exists yet to "free" a permanently abandoned agent address
  for reuse under a new, uncooperative owner. This is a disclosed,
  deliberate scope limit (see contract NatSpec point 3), not an
  oversight — but it means a lost agent key with no cooperating owner is
  a genuinely dead registry slot forever.
- `metadataHash` is unenforced by this contract. Nothing currently
  prevents a downstream component from mistakenly treating it as
  security-relevant; that discipline has to be maintained in the
  Execution Guard's design (Gate 2), not enforced here.

## G. What remains unsafe / out of scope for Gate 1

- There is no Execution Guard yet. `AgentRegistry` on its own authorizes
  nothing financially — it only answers an identity/lifecycle question.
  Nothing in this repository should be treated as safe to hold funds or
  gate real transactions until Gate 2 exists and is itself adversarially
  tested.
- No static-analysis tool (Slither, Mythril, etc.) was run — this
  sandbox's network egress allowlist does not include package sources
  those tools would need, and none were pre-installed. This is a real gap
  in Phase 8 verification, not a completed-and-clean result.
- No fuzz/invariant tests (Foundry-style) were written. Foundry itself
  could not be installed in this sandbox (network egress blocked to
  `foundry.paradigm.xyz`). The 24 tests are unit/property-style
  hand-written adversarial cases, not property-based fuzzing.
- Gas costs have not been profiled or optimized (correctly deprioritized
  per the task brief, but noting it wasn't measured at all).

## H. What should NOT yet be deployed

Nothing in this repository should be deployed to any network holding
real funds. This gate delivers identity/lifecycle only, has not had
independent (non-self) review, has no fuzz coverage, and has not been
run through static analysis.

## I. Recommended next gate

Gate 2: Execution Guard — the deterministic on-chain authorization
boundary (signed intent verification, nonce, deadline, exact
target/value/calldata, financial mandate, policy commitment) that
actually consumes `AgentRegistry.isActiveAgent`. Recommended
prerequisites before starting Gate 2:

1. Resolve or explicitly ratify the ERC-1271 limitation (D.4) — Gate 2's
   intent-signing design will hit the same question and should not
   re-decide it inconsistently.
2. Get real network access to a static analyzer (Slither at minimum) run
   against both gates together before either is considered for testnet
   deployment.
3. If Foundry becomes available in a less restricted environment, port
   the adversarial test suite to Foundry and add fuzz tests for the
   nonce/deadline/replay logic Gate 2 introduces — that logic has a much
   larger state space than Gate 1's and benefits more from property-based
   testing than Gate 1 did.

No claim of "production ready" is made anywhere in this report, and none
should be inferred from tests passing.
