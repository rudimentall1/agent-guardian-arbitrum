# Agent Guardian

## Autonomous Agent Security Layer for Arbitrum

**[Watch the demo video](https://youtu.be/z7_GXu9Phwc)** — architecture walkthrough + live run on Arbitrum Sepolia.

Agent Guardian is a security framework for autonomous AI agents operating on-chain.

The protocol allows AI agents to execute transactions while enforcing strict security boundaries:
- agent identity verification
- programmable spending policies
- transaction authorization
- replay protection
- emergency recovery controls

Built for the future of autonomous wallets and AI-driven Web3 applications.

**Scope note:** everything in this repository is a deterministic, on-chain
enforcement layer (identity, policy, execution, recovery). There is no
off-chain risk-scoring or AI-advisory service implemented here yet — see
"What this repo does NOT contain" below before relying on this in
production.

---

# Problem

AI agents will increasingly control wallets, execute trades, manage assets and interact with smart contracts.

Current wallet systems have a critical limitation:

> If an AI agent key is compromised, there is no native security layer between the agent and user funds.

Agent Guardian introduces a programmable security boundary between AI agents and blockchain execution.

---

# Solution

Agent Guardian separates identity, policy, and execution into three contracts:

```
AI Agent
   |
   v
AgentExecutionGuard  <-- every transaction passes through here
   |
   +------------------+
   |                  |
   v                  v
AgentRegistry    PolicyRegistry
   |
   v
Recovery Guardian (owner-controlled emergency disable)
```

The agent never receives unrestricted wallet control. Every execution is checked against:

- registered agent identity
- active status
- owner authorization
- policy permissions
- spending limits
- nonce protection
- emergency recovery state

---

# Core Components

## AgentRegistry

Responsible for:
- agent identity lifecycle
- registration
- activation/deactivation
- ownership transfer
- recovery guardian controls

Security properties:
- EIP-712 signed registration
- anti-front-running protection
- immutable agent identity binding
- accepts both EOA and ERC-1271 (contract/AA/TEE-signer) agent identities

## PolicyRegistry

Defines what an agent is allowed to do. Policies include:
- allowed contracts
- allowed function selectors
- maximum transaction value
- daily spending limit
- owner-approval threshold
- validity period
- native transfer permissions

Example:

```
Agent can:
  call Uniswap router
  spend max 0.1 ETH per transaction
  spend max 1 ETH per day
  only during the policy's active period

Agent cannot:
  transfer unlimited funds
  call unauthorized contracts
  bypass daily limits or owner-approval thresholds
```

## AgentExecutionGuard

The execution firewall. Before every transaction it:

1. verifies the agent's signature (EOA or ERC-1271)
2. checks the nonce and deadline
3. verifies the agent is active and not paused
4. verifies policy ownership and authorization for the exact (target, selector) pair
5. checks the daily spending limit and, above the policy's approval threshold, requires a fresh owner-signed approval
6. executes the transaction

The Guard never accepts `msg.value` under any circumstance (`GuardMustNotReceiveValue`) and has no `receive`/`fallback` — it never holds a balance of its own. This gives two distinct entry points, not two interchangeable "funding models":
- **Function-call-only** (`execute` / `executeWithApproval`): `value` must be `0`. Any attempt to pass `value > 0` reverts explicitly with `NativeTransferRequiresWalletCustody` — these exist for calling functions that don't move native ETH.
- **Wallet-custody** (`executeFromWallet` / `executeWithApprovalFromWallet`): the only way to move native value. It is drawn from an `AgentSmartWallet` the owner deploys and funds ahead of time. `AgentSmartWallet.execute` only accepts calls from the specific Guard it was deployed with — a wallet pointed at a different Guard fails closed.

Protection against:
- replay attacks
- modified calldata
- unauthorized targets/selectors
- unauthorized policies
- cross-chain and cross-contract replay
- reentrancy

---

# Recovery Guardian

Gate 6 introduces emergency recovery controls. A trusted guardian can disable a compromised agent immediately, independent of the agent's own key.

---

# Security Testing

Current test suite: **178 passing** (`npx hardhat test`), including adversarial scenarios (replay, cross-chain/cross-contract replay, reentrancy, nonce boundaries, privilege-escalation regressions, ERC-1271 owner and agent signatures, wallet-custody fund movement, daily-limit and approval-threshold enforcement).

Implemented security gates:
- Gate 4A — Call authorization
- Gate 4B — Spending limits and owner approvals
- Gate 5 — Emergency pause controls
- Gate 6 — Recovery Guardian controls
- Gate 7 — AgentSmartWallet custody wiring + ERC-1271 agent identity

**Honest limitations, not yet closed:**
- No Foundry/Echidna property-based fuzzing has been run — the `*.fuzz.test.ts` files are seeded pseudo-random JS loops, not a real fuzzer. See `docs/gate-2-execution-guard.md` section 5 for why, and the CI `static-analysis`/`coverage` jobs for where a real fuzzer would plug in.
- Static analysis (Slither) is wired into CI (`.github/workflows/ci.yml`) but has not yet been run against this exact commit and reviewed.
- Coverage (`npm run coverage`) is wired into CI but the resulting percentage has not yet been reviewed for gaps.

---

# What this repo does NOT contain

To be direct about scope, since it matters for anyone evaluating this for production use:
- **No off-chain AI/risk-scoring service.** `docs/protocol-spec.md` describes a planned "Guardian intelligence" advisory layer (risk, reputation, simulation, threat intelligence); it is not implemented in this repository. Every enforcement decision made by the contracts here is deterministic, not AI-derived.
- **No Robinhood Chain deployment.** Mentioned as a planned target in `docs/protocol-spec.md` / `docs/project-lineage.md`; there is no network configuration, deployment, or address for it yet. The only live deployment is Arbitrum Sepolia.
- **No SDK, monitoring dashboard, or agent connectors.** These are Phase 2 items, not built.

---

# Deployment

Network: Arbitrum Sepolia (chain ID 421614).

Addresses are tracked in a single place, [`deployments.json`](./deployments.json), generated by `scripts/deploy.ts` — not copy-pasted into this README or into `docs/hackathon/`, so it can't silently drift out of sync the way it has in the past. Check that file for the current, network-keyed record; if you find a different address anywhere else in this repo's docs, `deployments.json` is the one to trust, and the other one should be reported as a bug.

---

# Local Development

Install:

```bash
npm install
```

Compile:

```bash
npm run compile
```

Run tests:

```bash
npm test
```

Run coverage:

```bash
npm run coverage
```

Deploy (also deploys and wires an example `AgentSmartWallet`, and writes `deployments.json`):

```bash
npx hardhat run scripts/deploy.ts --network arbitrumSepolia
```

---

# Vision

Agent Guardian is designed as a security layer for the next generation of autonomous agents. As AI agents become financial actors, they need identity, permissions, limits, and recovery mechanisms. This repository is the deterministic on-chain half of that; the off-chain risk-advisory half is future work (see "What this repo does NOT contain").
