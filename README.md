# Agent Guardian

## Autonomous Agent Security Layer for Arbitrum

Agent Guardian is an on-chain security framework designed for autonomous AI agents.

The protocol creates a programmable security boundary between AI agents and blockchain execution.

AI agents will control wallets, execute transactions, manage assets and interact with smart contracts.

Agent Guardian provides the missing security infrastructure:

- agent identity
- programmable permissions
- execution validation
- spending limits
- emergency recovery

---

# The Problem

Autonomous AI agents introduce a new security challenge.

If an AI agent wallet key is compromised, traditional wallets provide no native protection layer.

Current systems lack:

- agent identity verification
- transaction boundaries
- automated permission control
- emergency shutdown mechanisms

Agent Guardian solves this by introducing a security firewall between autonomous software and blockchain assets.

---

# Architecture

             AI Agent

                |
                v

      AgentExecutionGuard

                |
    +-----------+-----------+

    v                       v

AgentRegistry PolicyRegistry

(identity + owner) (permissions + limits)

                |

                v

         Blockchain Execution

---

# Core Components


## AgentRegistry

Handles autonomous agent identity.

Features:

- agent registration
- ownership binding
- lifecycle management
- guardian recovery controls

Security:

- EIP-712 signed registration
- ownership verification
- replay protection


---

## PolicyRegistry

Defines what an agent is allowed to do.

Policies control:

- allowed contracts
- allowed functions
- spending limits
- execution permissions


Example:

Allowed:

✓ Uniswap router interaction  
✓ maximum spending amount  
✓ limited execution window  


Blocked:

✗ unlimited transfers  
✗ unknown contracts  
✗ unauthorized actions  


---

## AgentExecutionGuard

The execution security firewall.

Every action is validated through:

- agent identity
- owner authorization
- nonce protection
- policy validation
- target verification


Protection against:

- replay attacks
- unauthorized execution
- calldata modification
- policy abuse
- reentrancy


---

# Recovery Guardian

Autonomous systems require an emergency control layer.

A trusted guardian can disable a compromised agent.

Flow:


Agent compromised

    |

Recovery Guardian

    |

Agent disabled


This creates a human-controlled emergency brake for autonomous systems.

---

# Security Testing

Current test coverage:


166 passing


Implemented security gates:

✅ Gate 4A - Call Authorization  
✅ Gate 4B - Spending Limits and Owner Approvals  
✅ Gate 5 - Emergency Security Controls  
✅ Gate 6 - Recovery Guardian Controls  


Testing includes:

- signature attacks
- replay attacks
- ownership attacks
- policy abuse
- unauthorized execution
- reentrancy attempts
- cross-agent confusion


---

# Live Deployment

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

# Demo

Run:

```bash
npx hardhat run scripts/demo.ts --network arbitrumSepolia

Demo result:

Agent registered

Guardian assigned

Agent active before: true

Emergency recovery executed

Agent active after: false
Roadmap
Phase 1 — Hackathon MVP

Completed:

✅ Agent identity
✅ Policy system
✅ Execution guard
✅ Recovery guardian
✅ Arbitrum deployment

Phase 2 — Advanced Security

Future:

multi guardian recovery
advanced spending controls
risk scoring
automated threat detection
Phase 3 — Autonomous Economy Infrastructure

Future:

AI treasury security
enterprise agents
wallet integrations
zero knowledge authorization
Vision

Agent Guardian aims to become a security standard for autonomous AI agents operating on blockchain networks.

As AI agents become economic actors, they need:

Identity.

Permissions.

Limits.

Recovery.

Agent Guardian provides the security layer between autonomous intelligence and blockchain assets.