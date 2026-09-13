# Agent Guardian — Hackathon Demo Script

## Duration

3-4 minutes.

## Before recording

Run the demo once so you know what it prints and how long each part
takes:

```
npx hardhat run scripts/demo.ts
```

It runs against the local Hardhat network — no testnet ETH, no
waiting for confirmations, finishes in a couple of seconds. You can
either record this scripted run directly (fastest, zero risk of a
live mistake), or narrate over it while re-running it on screen.

## How to record (no extra software needed)

Windows has a built-in screen recorder:

- Press **Win + G** to open Xbox Game Bar, then the record button
  (or **Win + Alt + R** to start/stop recording directly), OR
- Use **Snipping Tool** (Windows 11) — it has a video-recording mode.

Record your terminal window running the command above, narrating
over it (see script below). Upload the result to YouTube (unlisted
is fine) or Loom, and link it in your submission.

## Script

**[0:00 – Introduction]**

"This is Agent Guardian — an on-chain security layer for autonomous
AI agents on Arbitrum. It sits between an AI agent and the funds it's
allowed to move, and enforces policy limits deterministically, in the
contract itself — not by trusting the agent to behave."

**[0:20 – Run the demo]**

Run `npx hardhat run scripts/demo.ts` on screen and narrate along
with its output, section by section:

- **Setup**: "We deploy the four contracts — identity registry,
  policy registry, the execution guard, and a smart wallet that
  actually custodies the funds."
- **Step 1 (register)**: "The agent has its own signing key, and the
  owner registers it on-chain with an EIP-712 signature."
- **Step 2 (create policy)**: "The owner defines exactly what this
  agent can do: a 0.5 ETH per-transaction cap, a 0.6 ETH daily limit,
  and anything above 0.3 ETH needs a fresh owner approval."
- **Step 3 (fund the wallet)**: "Funds live in the agent's own smart
  wallet — never in the Guard contract itself, which always holds
  zero."
- **Step 4 (small transfer)**: "A 0.1 ETH transfer, signed by the
  agent, executes immediately — no human in the loop needed for
  small amounts."
- **Step 5 (blocked without approval)**: "A 0.4 ETH transfer is
  above the threshold — rejected, `ApprovalRequired`, until the
  owner co-signs it."
- **Step 6 (approved)**: "Same transfer, now with the owner's
  signature attached — executes."
- **Step 7 (daily limit)**: "A further, individually-small transfer
  is rejected anyway — `DailyLimitExceeded` — because the running
  total for today would cross the daily cap."
- **Step 8 (pause)**: "If the owner suspects the agent's key is
  compromised, they can pause it directly — even a tiny, otherwise
  perfectly valid transfer is rejected instantly."
- **Step 9 (guardian recovery)**: "Separately, a recovery guardian —
  not the owner's own key — can deactivate the agent's identity
  entirely. That's the emergency shutdown path if the owner's own
  access is also compromised."

**[3:00 – Closing]**

"All of this is enforced by the contracts themselves, not by an
off-chain service the agent could route around. It's deployed and
verified on Arbitrum Sepolia — links in the README — with 178
passing tests covering these paths and the adversarial cases around
them: replay, reentrancy, cross-chain signature reuse, and
ownership-transfer edge cases."

## What NOT to claim in the video

Don't say or imply any of the following — none of it exists in this
repository yet (see `README.md`, "What this repo does NOT contain"):

- an off-chain AI/risk-scoring layer ("Guardian intelligence" is
  design language for future work, not a running service)
- Robinhood Chain support
- an SDK, dashboard, or agent connectors

If asked, say these are roadmap items, not shipped functionality.
