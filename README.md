# Agent Guardian

## Autonomous Agent Security Layer for Arbitrum

Agent Guardian is a security framework for autonomous AI agents operating on-chain.

The protocol allows AI agents to execute transactions while enforcing strict security boundaries:
- agent identity verification
- programmable spending policies
- transaction authorization
- replay protection
- emergency recovery controls

Built for the future of autonomous wallets and AI-driven Web3 applications.

---

# Problem

AI agents will increasingly control wallets, execute trades, manage assets and interact with smart contracts.

Current wallet systems have a critical limitation:

> If an AI agent key is compromised, there is no native security layer between the agent and user funds.

Agent Guardian introduces a programmable security boundary between AI agents and blockchain execution.

---

# Solution

Agent Guardian separates:


AI Agent
|
|
v
AgentExecutionGuard
|
+----------------+
| |
v v
AgentRegistry PolicyRegistry
|
|
Recovery Guardian


The agent never receives unrestricted wallet control.

Every execution is checked against:

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
- anti-front running protection
- immutable agent identity binding

---

## PolicyRegistry

Defines what an agent is allowed to do.

Policies include:

- allowed contracts
- allowed function selectors
- maximum transaction value
- validity period
- native transfer permissions

Example:


Agent can:

✓ call Uniswap router
✓ spend max 0.1 ETH
✓ only during active period

Agent cannot:

✗ transfer unlimited funds
✗ call unknown contracts
✗ bypass policy rules


---

## AgentExecutionGuard

The execution firewall.

Before every transaction:

Verify agent signature
Check nonce
Check deadline
Verify active agent
Verify policy ownership
Validate target + calldata
Execute transaction

Protection against:

- replay attacks
- modified calldata
- unauthorized targets
- unauthorized policies
- cross-chain replay
- reentrancy attacks

---

# Recovery Guardian

Gate 6 introduces emergency recovery controls.

A trusted guardian can disable a compromised agent.

Example:


AI agent compromised

    |
    v

Recovery Guardian

    |
    v

Agent disabled immediately


This provides a human-controlled emergency brake for autonomous systems.

---

# Security Testing

Current test coverage:


166 passing


Implemented security gates:

✅ Gate 4A - Call authorization  
✅ Gate 4B - Spending limits and owner approvals  
✅ Gate 5 - Emergency pause controls  
✅ Gate 6 - Recovery Guardian Controls  

Test categories:

- replay attacks
- signature manipulation
- ownership attacks
- policy abuse
- unauthorized execution
- reentrancy attempts
- cross-agent confusion
- cross-chain replay

---

# Deployment

Network:


Arbitrum Sepolia
Chain ID: 421614


Contracts:

## AgentRegistry


0x249761b2F52258e74C91F5CD345Bd9C447aD18F3


## PolicyRegistry


0x77Af1625CC230dB6BAA25c40d629A225b1BFCf87


## AgentExecutionGuard


0x8845f20D83dAD3a494073F1AE1aEB6F9f85146AD


---

# Local Development

Install:

```bash
npm install

Run tests:

npm test

Deploy:

npx hardhat run scripts/deploy.ts --network arbitrumSepolia
Vision

Agent Guardian is designed as a security layer for the next generation of autonomous agents.

As AI agents become financial actors, they need:

identity
permissions
limits
recovery mechanisms

Agent Guardian provides the missing security infrastructure between autonomous intelligence and blockchain assets

## Demo

Run:

``bash
npx hardhat run scripts/demo.ts
``n
Output:
Agent registered
Guardian assigned
Agent active: false
