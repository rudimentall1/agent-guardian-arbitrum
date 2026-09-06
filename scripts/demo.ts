import { ethers } from "hardhat";
import fs from "node:fs";

async function main() {

  console.log("=== Agent Guardian Arbitrum Sepolia Demo ===");

  const [owner, agent, guardian] =
    await ethers.getSigners();

  console.log("\nOwner:");
  console.log(owner.address);

  console.log("\nAgent:");
  console.log(agent.address);

  console.log("\nGuardian:");
  console.log(guardian.address);


  const deployment =
    JSON.parse(
      fs.readFileSync(
        "deployments.json",
        "utf8"
      )
    );


  const registry =
    await ethers.getContractAt(
      "AgentRegistry",
      deployment.contracts.AgentRegistry
    );


  const metadataHash =
    ethers.keccak256(
      ethers.toUtf8Bytes(
        "agent-guardian-production-demo"
      )
    );


  const network =
    await ethers.provider.getNetwork();


  /*
   * 1. REGISTER AGENT
   */

  console.log("\n1. Checking agent registration...");

  let existing =
    await registry.getAgent(agent.address);


  if (existing.owner === ethers.ZeroAddress) {

    const domain = {
      name: "AgentRegistry",
      version: "1",
      chainId: network.chainId,
      verifyingContract:
        deployment.contracts.AgentRegistry
    };


    const types = {
      AgentRegistration: [
        {
          name: "agent",
          type: "address"
        },
        {
          name: "owner",
          type: "address"
        },
        {
          name: "metadataHash",
          type: "bytes32"
        }
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


    console.log("✅ Agent registered");


  } else {

    console.log("ℹ️ Agent already registered");

  }


  /*
   * refresh data after registration
   */

  existing =
    await registry.getAgent(agent.address);


  /*
   * 2. GUARDIAN
   */

  console.log("\n2. Checking guardian...");


  if (existing.recoveryAgent !== guardian.address) {

    await registry
      .connect(owner)
      .setRecoveryGuardian(
        agent.address,
        guardian.address
      );


    console.log("✅ Guardian assigned");


  } else {

    console.log("ℹ️ Guardian already assigned");

  }


  /*
   * 3. RECOVERY
   */

  console.log("\n3. Recovery status");


  const before =
    await registry.isActiveAgent(
      agent.address
    );


  console.log(
    "Agent active before:",
    before
  );


  if (before) {

    await registry
      .connect(guardian)
      .executeRecovery(
        agent.address
      );


    console.log(
      "✅ Emergency recovery executed"
    );


  } else {

    console.log(
      "ℹ️ Agent already disabled"
    );

  }


  console.log(
    "Agent active after:",
    await registry.isActiveAgent(
      agent.address
    )
  );


  console.log("\n=== Demo Complete ===");

}


main().catch((e)=>{
 console.error(e);
 process.exitCode = 1;
});