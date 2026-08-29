import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("P1: PolicyRegistry policy-owner authorization", function () {
  async function deployFixture() {
    const [owner, attacker] = await ethers.getSigners();
    const agentWallet = ethers.Wallet.createRandom().connect(ethers.provider);

    const Registry = await ethers.getContractFactory("AgentRegistry");
    const registry = await Registry.deploy();

    const Policy = await ethers.getContractFactory("PolicyRegistry");
    const policyRegistry = await Policy.deploy(await registry.getAddress());

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    const guard = await Guard.deploy(await registry.getAddress(), await policyRegistry.getAddress());

    return { registry, policyRegistry, guard, owner, attacker, agentWallet };
  }

  it("attacker cannot create policy for someone else's agent", async function () {
    const { registry, policyRegistry, owner, attacker, agentWallet } = await loadFixture(deployFixture);

    // Регистрируем агента
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
    const sig = await agentWallet.signTypedData(domain, types, {
      agent: agentWallet.address,
      owner: owner.address,
      metadataHash: ethers.keccak256(ethers.toUtf8Bytes("v1")),
    });
    await registry.register(agentWallet.address, owner.address, ethers.keccak256(ethers.toUtf8Bytes("v1")), sig);

    // Атакующий пытается создать политику
    await expect(
      policyRegistry.connect(attacker).createPolicy(
        agentWallet.address,
        ethers.hexlify(ethers.randomBytes(32)),
        [attacker.address],
        ["0x00000000"],
        [],
        ethers.parseEther("1000"),
        ethers.parseEther("100"),
        ethers.parseEther("10"),
        0,
        ethers.MaxUint256
      )
    ).to.be.revertedWithCustomError(policyRegistry, "NotAuthorized");
  });

  it("legitimate owner can create and use policy", async function () {
    const { registry, policyRegistry, guard, owner, agentWallet } = await loadFixture(deployFixture);

    // Регистрируем агента
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
    const sig = await agentWallet.signTypedData(domain, types, {
      agent: agentWallet.address,
      owner: owner.address,
      metadataHash: ethers.keccak256(ethers.toUtf8Bytes("v1")),
    });
    await registry.register(agentWallet.address, owner.address, ethers.keccak256(ethers.toUtf8Bytes("v1")), sig);

    // Владелец создает политику
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const targets = [guard.target];
    const selectors = ["0x00000000"];
    const maxTxValue = ethers.parseEther("1");
    const dailyLimit = ethers.parseEther("100");
    const approvalThreshold = ethers.parseEther("0.1");

    await policyRegistry.connect(owner).createPolicy(
      agentWallet.address,
      salt,
      targets,
      selectors,
      [],
      maxTxValue,
      dailyLimit,
      approvalThreshold,
      0,
      ethers.MaxUint256
    );

    const policyHash = await policyRegistry.getPolicyHash(
      agentWallet.address,
      salt,
      targets,
      selectors,
      [],
      maxTxValue,
      dailyLimit,
      approvalThreshold,
      0,
      ethers.MaxUint256
    );

    // Подписываем и исполняем
    const intentDomain = {
      name: "AgentExecutionGuard",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await guard.getAddress(),
    };
    const intentTypes = {
      ExecutionIntent: [
        { name: "agent", type: "address" },
        { name: "wallet", type: "address" },
        { name: "target", type: "address" },
        { name: "value", type: "uint256" },
        { name: "calldataHash", type: "bytes32" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
        { name: "policyHash", type: "bytes32" },
      ],
    };
    const intentSig = await agentWallet.signTypedData(intentDomain, intentTypes, {
      agent: agentWallet.address,
      wallet: owner.address,
      target: guard.target,
      value: 0,
      calldataHash: ethers.keccak256("0x"),
      nonce: 0,
      deadline: ethers.MaxUint256,
      policyHash,
    });

    await expect(
      guard.connect(owner).execute(
        agentWallet.address,
        owner.address,
        guard.target,
        0,
        "0x",
        0,
        ethers.MaxUint256,
        policyHash,
        intentSig,
        { value: 0 }
      )
    ).to.not.be.reverted;
  });
});