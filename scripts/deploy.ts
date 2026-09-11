import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

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
  const guardAddress = await guard.getAddress();

  console.log(
    "AgentExecutionGuard:",
    guardAddress
  );

  // AgentSmartWallet is the actual custody layer executeFromWallet /
  // executeWithApprovalFromWallet route funds through. It is deployed
  // and wired to this Guard here so a fresh deployment is immediately
  // usable end-to-end, not a set of disconnected contracts that need
  // manual post-deploy wiring. One example wallet is deployed for the
  // deployer address; in production each owner gets their own.
  const AgentSmartWallet = await ethers.getContractFactory("AgentSmartWallet");
  const exampleWallet = await AgentSmartWallet.deploy(deployer.address, guardAddress);
  await exampleWallet.waitForDeployment();

  console.log(
    "AgentSmartWallet (example, owner = deployer):",
    await exampleWallet.getAddress()
  );

  const result = {
    agentRegistry: await agentRegistry.getAddress(),
    policyRegistry: await policyRegistry.getAddress(),
    agentExecutionGuard: guardAddress,
    exampleAgentSmartWallet: await exampleWallet.getAddress(),
  };

  // Single source of truth for "what is actually deployed where" — keyed
  // by network so a testnet run never silently overwrites another
  // network's record, and so docs/hackathon/*.md can be regenerated from
  // this file instead of hand-copied (the prior workaround: manually
  // maintaining deployments.json AND docs/hackathon/submission.md
  // separately let the two drift out of sync with each other).
  const deploymentsPath = path.join(__dirname, "..", "deployments.json");
  let deployments: Record<string, unknown> = {};
  if (fs.existsSync(deploymentsPath)) {
    deployments = JSON.parse(fs.readFileSync(deploymentsPath, "utf8"));
  }
  deployments[network.name] = {
    ...result,
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
  };
  fs.writeFileSync(deploymentsPath, JSON.stringify(deployments, null, 2) + "\n");
  console.log(`\nWrote deployment record for network "${network.name}" to deployments.json`);

  return result;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});