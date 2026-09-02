import { expect } from "chai";
import { ethers } from "hardhat";

describe("Gate 5: emergency pause controls", function () {
  let registry: any;
  let policyRegistry: any;
  let guard: any;
  let owner: any;
  let attacker: any;
  let agentAddress: string;

  beforeEach(async function () {
    [owner, attacker] = await ethers.getSigners();

    const Registry = await ethers.getContractFactory("AgentRegistry");
    registry = await Registry.deploy();

    const PolicyRegistry = await ethers.getContractFactory("PolicyRegistry");
    policyRegistry = await PolicyRegistry.deploy();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    guard = await Guard.deploy(
      await registry.getAddress(),
      await policyRegistry.getAddress()
    );

    const wallet = ethers.Wallet.createRandom();
    agentAddress = wallet.address;

    const metadataHash = ethers.keccak256(
      ethers.toUtf8Bytes("gate5-test")
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

    const signature = await wallet.signTypedData(
      domain,
      types,
      {
        agent: agentAddress,
        owner: owner.address,
        metadataHash,
      }
    );

    await registry.register(
      agentAddress,
      owner.address,
      metadataHash,
      signature
    );
  });


  it("owner can pause and block agent execution", async function () {
    await guard.connect(owner).pauseAgent(agentAddress);

    expect(
      await guard.pausedAgents(agentAddress)
    ).to.equal(true);
  });


  it("non-owner cannot pause another agent", async function () {
    await expect(
      guard.connect(attacker).pauseAgent(agentAddress)
    )
      .to.be.revertedWithCustomError(
        guard,
        "NotPolicyOwner"
      );
  });


  it("owner can unpause agent", async function () {
    await guard.connect(owner).pauseAgent(agentAddress);

    expect(
      await guard.pausedAgents(agentAddress)
    ).to.equal(true);

    await guard.connect(owner).unpauseAgent(agentAddress);

    expect(
      await guard.pausedAgents(agentAddress)
    ).to.equal(false);
  });
});