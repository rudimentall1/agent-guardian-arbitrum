import { ethers } from "hardhat";
import fs from "node:fs";

async function waitDeploy(contract: any, name: string) {
  for (let i = 1; i <= 5; i++) {
    try {
      await contract.waitForDeployment();
      const addr = await contract.getAddress();
      console.log(`${name}: ${addr}`);
      return addr;
    } catch (e) {
      console.log(`${name} deploy retry ${i}/5`);
      await new Promise(r => setTimeout(r, 5000));
    }
  }

  throw new Error(`${name} deployment failed`);
}

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("=== Agent Guardian Deployment ===");
  console.log("Network:", (await ethers.provider.getNetwork()).name);
  console.log("Chain:", (await ethers.provider.getNetwork()).chainId);
  console.log("Deployer:", deployer.address);

  const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
  const agentRegistry = await AgentRegistry.deploy();

  const agentRegistryAddress =
    await waitDeploy(agentRegistry, "AgentRegistry");


  const PolicyRegistry =
    await ethers.getContractFactory("PolicyRegistry");

  const policyRegistry = await PolicyRegistry.deploy();

  const policyRegistryAddress =
    await waitDeploy(policyRegistry, "PolicyRegistry");


  const Guard =
    await ethers.getContractFactory("AgentExecutionGuard");

  const guard = await Guard.deploy(
    agentRegistryAddress,
    policyRegistryAddress
  );

  const guardAddress =
    await waitDeploy(guard, "AgentExecutionGuard");


  const deployment = {
    network: "arbitrumSepolia",
    chainId: 421614,
    deployer: deployer.address,
    contracts: {
      AgentRegistry: agentRegistryAddress,
      PolicyRegistry: policyRegistryAddress,
      AgentExecutionGuard: guardAddress
    },
    timestamp: new Date().toISOString()
  };


  fs.writeFileSync(
    "deployments.json",
    JSON.stringify(deployment, null, 2)
  );


  console.log("\n=== SAVED deployments.json ===");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});