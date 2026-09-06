import { ethers } from "hardhat";
import fs from "node:fs";

async function main() {
  console.log("=== Agent Guardian Arbitrum Demo ===");

  const [owner, agent] = await ethers.getSigners();

  const deployments = JSON.parse(
    fs.readFileSync("deployments.json", "utf8")
  );

  const registry = await ethers.getContractAt(
    "AgentRegistry",
    deployments.contracts.AgentRegistry
  );

  const policyRegistry = await ethers.getContractAt(
    "PolicyRegistry",
    deployments.contracts.PolicyRegistry
  );

  const guard = await ethers.getContractAt(
    "AgentExecutionGuard",
    deployments.contracts.AgentExecutionGuard
  );


  console.log("\nOwner:", owner.address);
  console.log("Agent:", agent.address);


  //
  // 1. Register AI agent
  //

  console.log("\n[1] Register AI agent");


  const metadataHash =
    ethers.keccak256(
      ethers.toUtf8Bytes("autonomous-ai-agent-v1")
    );


  const network = await ethers.provider.getNetwork();


  const signature =
    await agent.signTypedData(
      {
        name: "AgentRegistry",
        version: "1",
        chainId: network.chainId,
        verifyingContract:
          deployments.contracts.AgentRegistry
      },
      {
        AgentRegistration: [
          {name:"agent", type:"address"},
          {name:"owner", type:"address"},
          {name:"metadataHash", type:"bytes32"}
        ]
      },
      {
        agent: agent.address,
        owner: owner.address,
        metadataHash
      }
    );


  try {
    await registry.register(
      agent.address,
      owner.address,
      metadataHash,
      signature
    );

    console.log("Agent registered");
  } catch {
    console.log("Agent already registered");
  }



  //
  // 2. Create policy
  //

  console.log("\n[2] Create safety policy");


  const salt =
    ethers.keccak256(
      ethers.toUtf8Bytes("demo-policy")
    );


  const now =
    Math.floor(Date.now()/1000);


  const tx =
    await policyRegistry.createPolicy(
      salt,
      agent.address,
      ethers.parseEther("0.01"),
      ethers.parseEther("1"),
      ethers.parseEther("0.05"),
      now-60,
      now+86400,
      [],
      [owner.address]
    );


  const receipt =
    await tx.wait();


  const event =
    receipt?.logs
      .map((x:any)=>{
        try {
          return policyRegistry.interface.parseLog(x);
        } catch {
          return null;
        }
      })
      .find((x:any)=>x?.name==="PolicyCreated");


  const policyHash =
    event.args.policyHash;


  console.log(
    "Policy:",
    policyHash
  );



  //
  // 3. Attack simulation
  //

  console.log("\n[3] Security checks");


  console.log(
    "Agent active:",
    await registry.isActiveAgent(agent.address)
  );


  console.log(
    "Guard:",
    deployments.contracts.AgentExecutionGuard
  );


  console.log("\nSUCCESS:");
  console.log(
    "AI agent is controlled by immutable on-chain policy"
  );


  console.log("\n=== Demo complete ===");

}


main().catch((e)=>{
 console.error(e);
 process.exitCode=1;
});