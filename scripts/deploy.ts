import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying from:", deployer.address);

  const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
  const agentRegistry = await AgentRegistry.deploy();
  await agentRegistry.waitForDeployment();

  console.log(
    "AgentRegistry:",
    await agentRegistry.getAddress()
  );

  const PolicyRegistry = await ethers.getContractFactory("PolicyRegistry");
  const policyRegistry = await PolicyRegistry.deploy();
  await policyRegistry.waitForDeployment();

  console.log(
    "PolicyRegistry:",
    await policyRegistry.getAddress()
  );

  const AgentExecutionGuard =
    await ethers.getContractFactory("AgentExecutionGuard");

  const guard = await AgentExecutionGuard.deploy(
    await agentRegistry.getAddress(),
    await policyRegistry.getAddress()
  );

  await guard.waitForDeployment();

  console.log(
    "AgentExecutionGuard:",
    await guard.getAddress()
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});