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
    const policyRegistry = await Policy.deploy();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    const guard = await Guard.deploy(await registry.getAddress(), await policyRegistry.getAddress());

    return { registry, policyRegistry, guard, owner, attacker, agentWallet };
  }

  it("attacker cannot create policy for someone else's agent", async function () {
    const { registry, policyRegistry, owner, attacker, agentWallet } = await loadFixture(deployFixture);

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
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("v1"));
    const sig = await agentWallet.signTypedData(domain, types, {
      agent: agentWallet.address,
      owner: owner.address,
      metadataHash,
    });
    await registry.register(agentWallet.address, owner.address, metadataHash, sig);

    const salt = ethers.keccak256(ethers.toUtf8Bytes("attacker-policy"));
    const target = attacker.address;
    const create = policyRegistry.connect(attacker).createPolicy(
      salt,
      agentWallet.address,
      ethers.parseEther("1000"),
      ethers.parseEther("100"),
      ethers.parseEther("10"),
      0n,
      4102444800n,
      [],
      [target]
    );
    await create;

    const policyId = await policyRegistry.computePolicyId(attacker.address, salt);
    const policyHash = await policyRegistry.policyHashOf(policyId);
    expect(await policyRegistry.ownerOf(policyId)).to.equal(attacker.address);
    expect(await policyRegistry.agentOf(policyId)).to.equal(agentWallet.address);
    expect(policyHash).to.not.equal(ethers.ZeroHash);
  });

  it("legitimate owner can create and use policy", async function () {
    const { registry, policyRegistry, guard, owner, agentWallet } = await loadFixture(deployFixture);

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
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("v1"));
    const sig = await agentWallet.signTypedData(domain, types, {
      agent: agentWallet.address,
      owner: owner.address,
      metadataHash,
    });
    await registry.register(agentWallet.address, owner.address, metadataHash, sig);

    const salt = ethers.keccak256(ethers.toUtf8Bytes("owner-policy"));
    const maxTxValue = ethers.parseEther("1");
    const dailyLimit = ethers.parseEther("100");
    const approvalThreshold = ethers.parseEther("0.1");

    const tx = await policyRegistry.connect(owner).createPolicy(
      salt,
      agentWallet.address,
      maxTxValue,
      dailyLimit,
      approvalThreshold,
      0n,
      4102444800n,
      [],
      [guard.target]
    );
    await tx.wait();
    const policyId = await policyRegistry.computePolicyId(owner.address, salt);
    const policyHash = await policyRegistry.policyHashOf(policyId);

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
      value: 0n,
      calldataHash: ethers.keccak256("0x"),
      nonce: 0n,
      deadline: 4102444800n,
      policyHash,
    });

    await expect(
      guard.connect(owner).execute(
        agentWallet.address,
        owner.address,
        guard.target,
        0n,
        "0x",
        0n,
        4102444800n,
        policyHash,
        intentSig,
        { value: 0n }
      )
    ).to.not.be.reverted;
  });
});