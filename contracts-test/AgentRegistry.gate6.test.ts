import { expect } from "chai";
import { ethers } from "hardhat";

describe("Gate 6: agent recovery guardian", function () {
  it("owner can configure recovery guardian and guardian can emergency disable agent", async function () {
    const [owner, guardian] = await ethers.getSigners();

    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    const registry = await AgentRegistry.deploy();
    await registry.waitForDeployment();

    const agent = ethers.Wallet.createRandom();

    const metadataHash = ethers.keccak256(
      ethers.toUtf8Bytes("agent")
    );

    const domain = {
      name: "AgentRegistry",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await registry.getAddress(),
    };

    const types = {
      AgentRegistration: [
        { name: "agent", type: "address" },
        { name: "owner", type: "address" },
        { name: "metadataHash", type: "bytes32" },
      ],
    };

    const signature = await agent.signTypedData(
      domain,
      types,
      {
        agent: agent.address,
        owner: owner.address,
        metadataHash,
      }
    );

    await registry.register(
      agent.address,
      owner.address,
      metadataHash,
      signature
    );

    await registry
      .connect(owner)
      .setRecoveryGuardian(agent.address, guardian.address);

    expect(
      (await registry.getAgent(agent.address)).recoveryAgent
    ).to.equal(guardian.address);

    await registry
      .connect(guardian)
      .executeRecovery(agent.address);

    expect(
      await registry.isActiveAgent(agent.address)
    ).to.equal(false);
  });


  it("non guardian cannot execute recovery", async function () {
    const [owner, attacker] = await ethers.getSigners();

    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    const registry = await AgentRegistry.deploy();
    await registry.waitForDeployment();

    const agent = ethers.Wallet.createRandom();

    const metadataHash = ethers.keccak256(
      ethers.toUtf8Bytes("agent")
    );

    const domain = {
      name: "AgentRegistry",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await registry.getAddress(),
    };

    const types = {
      AgentRegistration: [
        { name: "agent", type: "address" },
        { name: "owner", type: "address" },
        { name: "metadataHash", type: "bytes32" },
      ],
    };

    const signature = await agent.signTypedData(
      domain,
      types,
      {
        agent: agent.address,
        owner: owner.address,
        metadataHash,
      }
    );

    await registry.register(
      agent.address,
      owner.address,
      metadataHash,
      signature
    );

    await registry
      .connect(owner)
      .setRecoveryGuardian(agent.address, attacker.address);

    await expect(
      registry
        .connect(owner)
        .executeRecovery(agent.address)
    ).to.be.reverted;
  });
});