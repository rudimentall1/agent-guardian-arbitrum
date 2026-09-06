# Agent Guardian Arbitrum - next steps

Current state:
- AgentRegistry deployed
- PolicyRegistry deployed
- AgentExecutionGuard deployed
- Gate 4A authorization fixes merged

Before final hackathon demo:
1. Put test wallets in .env:
PRIVATE_KEY=
AGENT_PRIVATE_KEY=
GUARDIAN_PRIVATE_KEY=

2. Run:
npx hardhat compile
npx hardhat test

3. Create final demo flow:
owner -> register agent -> create policy -> sign intent -> execute guarded call -> emergency recovery

Goal:
Show Agent Guardian as a security layer for autonomous financial agents on Arbitrum.
