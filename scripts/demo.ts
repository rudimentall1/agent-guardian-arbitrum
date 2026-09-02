import { ethers } from "hardhat";

async function main() {
  const [owner, agent, guardian] = await ethers.getSigners();

  console.log("=== Agent Guardian Demo ===");

  console.log("\nOwner:");
  console.log(owner.address);

  console.log("\nAgent:");
  console.log(agent.address);

  console.log("\nGuardian:");
  console.log(guardian.address);


  const AgentRegistry =
    await ethers.getContractFactory("AgentRegistry");

  const registry = await AgentRegistry.deploy();
  await registry.waitForDeployment();

  console.log(
    "\nAgentRegistry:",
    await registry.getAddress()
  );


  console.log("\n1. Register agent");

  const metadataHash =
    ethers.keccak256(
      ethers.toUtf8Bytes("demo-agent")
    );


  const domain = {
    name: "AgentRegistry",
    version: "1",
    chainId: 31337,
    verifyingContract: await registry.getAddress()
  };


  const types = {
    AgentRegistration: [
      { name: "agent", type: "address" },
      { name: "owner", type: "address" },
      { name: "metadataHash", type: "bytes32" }
    ]
  };


  const signature =
    await agent.signTypedData(
      domain,
      types,
      {
        agent: agent.address,
        owner: owner.address,
        metadataHash
      }
    );


  await registry.register(
    agent.address,
    owner.address,
    metadataHash,
    signature
  );


  console.log("Agent registered");


  console.log("\n2. Set recovery guardian");


  await registry
    .connect(owner)
    .setRecoveryGuardian(
      agent.address,
      guardian.address
    );


  console.log("Guardian assigned");


  console.log("\n3. Guardian emergency disable");


  await registry
    .connect(guardian)
    .executeRecovery(
      agent.address
    );


  const active =
    await registry.isActiveAgent(agent.address);


  console.log(
    "Agent active:",
    active
  );


  console.log("\n=== Demo complete ===");
}


main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});