# Agent Guardian

## Autonomous AI Agent Security Layer for Web3

### Overview

AI agents are becoming capable of performing real blockchain operations:
- managing wallets,
- executing transactions,
- interacting with DeFi protocols,
- controlling digital assets.

However, autonomous agents introduce a new security problem:

> How do we allow AI agents to act autonomously while keeping human-level control, limits, and emergency protection?

Agent Guardian is an on-chain security framework that creates a controlled execution boundary between autonomous agents and blockchain assets.

---

# The Problem

Traditional wallets were designed for humans.

Autonomous agents require different security assumptions:

- AI agents can make mistakes
- private keys can be compromised
- automated systems can execute unintended actions
- unlimited permissions create catastrophic risk

A simple private key is not enough for autonomous financial agents.

---

# The Solution

Agent Guardian introduces four security layers:

## 1. Agent Identity Layer

AgentRegistry provides:

- unique agent identity (EOA or ERC-1271 contract/AA/TEE-signer)
- ownership binding
- lifecycle management
- emergency guardian mechanism

Every agent has a verifiable on-chain identity.

---

## 2. Policy Authorization Layer

PolicyRegistry creates financial mandates:

- allowed (contract, function) pairs, authorized as exact paired combinations, not independent allow-lists
- allowed native-transfer targets
- per-transaction value limit
- daily spending limit
- owner-approval threshold above which a fresh owner signature is required
- validity windows

The owner defines exactly what the agent can do, and a mandate is immutable once created — changing it means creating a new one, never silently widening an existing signed intent's meaning.

---

## 3. Execution Security Layer

AgentExecutionGuard validates every action before it executes:

- agent identity and active status
- policy authorization for the exact (target, selector) pair
- transaction value against both the per-transaction and daily limits
- nonce and deadline
- signature validity (EOA or ERC-1271)
- owner-approval requirement, when the policy's threshold is exceeded

Only permitted actions can execute.

## 4. Custody Layer

AgentSmartWallet holds an owner's funds and only accepts calls from the specific AgentExecutionGuard it was deployed with. Execution can be funded two ways: the caller attaches value directly (`execute`/`executeWithApproval`), or value is drawn from the owner's AgentSmartWallet balance (`executeFromWallet`/`executeWithApprovalFromWallet`) — the Guard itself never holds a balance in the wallet-custody model.

---

# Live Deployment

Network: Arbitrum Sepolia, chain ID 421614.

**Contract addresses: see [`deployments.json`](../../deployments.json).**
An earlier version of this file hardcoded a different, stale address set
here that had drifted out of sync with the actual deployment record and
did not match the current contract source. Rather than hand-copy
addresses into two places that can silently disagree, this section now
points at the one generated, network-keyed file `scripts/deploy.ts`
writes. As of this update those addresses have not yet been re-verified
against Arbiscan for the current contract set — do that before citing
them to judges.

---

# Demonstrated Scenario

The test suite (`npx hardhat test`, 174 passing) exercises the full
flow end to end:

1. Owner registers an agent (EIP-712 signed registration).
2. Owner creates a policy: authorized (target, selector) pairs and/or
   native-transfer targets, a per-transaction cap, a daily limit, and
   an approval threshold.
3. Agent signs an execution intent bound to that exact policy, nonce,
   and deadline.
4. A relayer submits the intent. The Guard verifies everything above
   and, for wallet-custody executions, pulls value from the owner's
   `AgentSmartWallet` rather than from the relayer.
5. If the value exceeds the policy's approval threshold, the Guard
   requires and verifies a separate, fresh owner-signed approval before
   executing.
6. At any point, the owner or a designated recovery guardian can pause
   the agent or trigger emergency recovery — independent of whether the
   agent's own key is still under the owner's control.

---

# Security Features

Implemented and covered by automated tests:

- EIP-712 typed signatures (agent identity, execution intent, owner approval)
- EOA and ERC-1271 (contract/AA/TEE-signer) agent and owner identities
- replay protection (nonce-based, plus cross-chain and cross-contract replay tests)
- paired (target, selector) authorization — not independent allow-lists
- per-transaction and daily spending limits
- owner-approval flow above a configurable threshold
- wallet-custody execution via AgentSmartWallet
- emergency pause and guardian recovery
- immutable policy identifiers
- reentrancy protection
- adversarial/hostile test scenarios (166 pre-existing + 8 added in this remediation pass)

Not yet done — see `README.md`, "Honest limitations":
- Real (Foundry/Echidna) fuzzing
- Reviewed Slither/coverage output for this exact commit
- Independent third-party security review

---

# Why Arbitrum

Arbitrum provides:

- Ethereum security model
- low transaction costs
- fast execution
- scalable environment for autonomous agents

Agent Guardian can become a security primitive for the next generation of AI-powered Web3 applications.

---

# Vision

The future will contain millions of autonomous agents.

They will manage:

- wallets
- payments
- investments
- organizations
- digital economies

Agent Guardian provides the missing security layer:

> Autonomous execution with human-controlled safety boundaries.

---

# Roadmap

## Phase 1 — Completed (this repository)

- Agent identity (EOA + ERC-1271)
- Policy engine (paired authorization, daily limits, approval threshold)
- Execution guard (both direct-funding and wallet-custody models)
- Guardian recovery
- Arbitrum Sepolia deployment (pending re-verification, see "Live Deployment" above)

## Phase 2 — Not started

- Off-chain risk-scoring / AI advisory layer ("Guardian intelligence" in `docs/protocol-spec.md`)
- Agent SDK
- Developer integrations
- Monitoring dashboard

## Phase 3 — Not started

- Multi-chain support (including Robinhood Chain)
- Enterprise agent security
- DAO agent governance
- Autonomous financial infrastructure
