\# Agent Guardian Demo Flow



\## Live Demo Scenario



Network:



Arbitrum Sepolia



Chain ID:



421614





\---



\# Step 1 — Agent Identity Creation



Owner creates an autonomous agent.



Result:





Agent registered





The agent receives an on-chain identity.



\---



\# Step 2 — Guardian Assignment



Owner assigns a recovery guardian.



Result:





Guardian assigned





The guardian becomes the emergency security authority.



\---



\# Step 3 — Normal Operation



Agent is active.



Example:





Agent active before recovery: true





\---



\# Step 4 — Security Incident



Simulation:



The autonomous agent is considered compromised.



\---



\# Step 5 — Emergency Recovery



Guardian executes recovery.



Transaction:





executeRecovery(agent)





\---



\# Step 6 — Protected State



The agent is disabled.



Result:





Agent active after recovery: false





\---



\# Conclusion



Agent Guardian demonstrates a new security primitive:



Autonomous agents can operate independently while maintaining a human-controlled emergency safety mechanism.

