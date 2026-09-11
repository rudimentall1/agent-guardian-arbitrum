# Agent Guardian — remediation patch

Apply to a clean clone of your repo:

    git checkout -b remediation/gate-7
    git apply agent-guardian-remediation.patch
    npm install
    npm test          # 174 passing

## What this patch actually fixes (code, not just docs)

1. **Critical — wallet custody wired up.** `AgentSmartWallet` was deployed
   but never called by `AgentExecutionGuard`; all funds moved via
   `msg.value` from whoever submitted the transaction. Added
   `executeFromWallet` / `executeWithApprovalFromWallet`, which pull value
   from the wallet's own balance and fail closed if the wallet isn't
   bound to that specific Guard. 4 new tests prove it (fund movement,
   wrong-guard rejection, no-attached-ETH enforcement, insufficient
   balance).
2. **ERC-1271 agent identity.** Both `AgentRegistry.register` and
   `AgentExecutionGuard`'s intent-signature check used raw
   `ECDSA.recover`, so an agent could never be a contract/AA/TEE signer —
   only a bare EOA key, which is the exact weakness the project claims to
   protect against. Switched both to `SignatureChecker`. 2 new tests
   prove it (valid contract-agent signature accepted, wrong-key signature
   still rejected).
3. **Policy-creation footgun.** `createPolicy` used to accept
   `nativeTransferTargets` paired with `maxTxValue = 0`, silently
   producing a native-transfer authorization that could never actually
   move any ETH. Now reverts at creation with
   `UnreachableNativeTransferAuthorization`. 2 new tests.
4. **Stale/misleading NatSpec** in `PolicyRegistry.sol` claiming
   `dailyLimit`/`approvalThreshold` were unenforced — they are (in
   `AgentExecutionGuard`, since Gate 4B). Comment corrected.
5. **`scripts/deploy.ts`** now deploys and wires an example
   `AgentSmartWallet`, and writes `deployments.json` automatically
   (network-keyed) instead of leaving it hand-maintained — the root
   cause of the address mismatch between `deployments.json` and
   `docs/hackathon/*.md`.

174 tests pass (166 pre-existing + 8 new); nothing was removed or
weakened to make old tests pass.

## Docs / repo hygiene

- `README.md`: fixed an unclosed ` ```bash ` fence that made ~half the
  file (including the "Vision" and "Demo" headers) render as one grey
  code block on GitHub. Removed duplicated Demo/Architecture/Deployment
  sections — one copy had a **truncated, invalid** contract address (39
  hex chars instead of 40). Added an explicit "What this repo does NOT
  contain" section (off-chain AI layer, Robinhood Chain, SDK — marked as
  roadmap, not shipped).
- `docs/hackathon/submission.md` and `FINAL_CHECKLIST.md`: both had
  **escaped markdown** (`\#`, `\-`, `\[`) that renders literally on
  GitHub instead of as headers/lists — same corruption present (and
  fixed) in `demo-flow.md`, `security-model.md`, `threat-analysis.md`,
  `video-script.md`, `screenshots/README.md`. `submission.md` additionally
  had its entire intro **duplicated verbatim** (broken copy + clean copy
  back to back) — deduplicated. Both files hardcoded a *third*,
  different address set than `deployments.json` — now point at that file
  instead. `FINAL_CHECKLIST.md` was describing an old pre-Gate-4A version
  of the project (no policy enforcement, no daily limits, no wallet
  custody) — rewritten to match current state.
- `docs/hackathon/screenshots/README.md`: was silently listing "expected
  files" as if they existed; now explicitly flagged as NOT YET PROVIDED
  with instructions on what to add.
- `docs/protocol-spec.md` / `docs/project-lineage.md`: "Guardian
  intelligence" (off-chain AI risk layer) and "Robinhood Chain" claims
  marked explicitly as planned/unimplemented, not delivered.
- Removed from git tracking: a stray Word lock file (`~$https.docx`),
  the generated `typechain-types/` directory (was committed despite
  being gitignored), and three `.bak` files.
- `package.json` / new `LICENSE` file: license was `ISC` in
  `package.json` but every contract's SPDX header says `MIT`, and no
  `LICENSE` file existed at all. Now consistently MIT.
- `.github/workflows/`: two workflows doing the exact same thing merged
  into one `ci.yml` with three jobs (test, coverage, Slither static
  analysis — Slither wasn't run in CI before).

## What I could NOT do for you (needs your keys/decisions)

- **Re-deploy and verify on Arbitrum Sepolia.** I don't have your
  deployer key or RPC access. `deployments.json` currently keeps the
  old addresses but flags them as unverified — run
  `npx hardhat run scripts/deploy.ts --network arbitrumSepolia` with a
  funded key; it will now also deploy `AgentSmartWallet` and overwrite
  `deployments.json` automatically.
- **Real screenshots/video** of the deployed contracts and a live run.
- **Slither / coverage output review.** Both are wired into CI now but
  need to actually run on GitHub Actions (blocked by network in this
  sandbox) and have their findings triaged.
- **A real off-chain AI/risk-scoring service**, if you want the
  "Guardian intelligence" claim to be true rather than roadmap — this is
  a design decision (what risk signals, what API/model) I can't make
  for you, but I can help build it once you decide the scope.
- **Robinhood Chain deployment**, if you want to keep that claim —
  needs their RPC/chain ID and a funded deployer key there too.

## Honest correction to my first-pass audit

I initially said the README "sells Robinhood Chain / Guardian
Intelligence / fuzz testing as delivered." That was imprecise — those
claims actually lived in `docs/protocol-spec.md`,
`docs/project-lineage.md`, and `package.json`, not in `README.md`
itself. All of those are now fixed regardless, but wanted to flag the
correction rather than let a slightly-wrong claim stand.
