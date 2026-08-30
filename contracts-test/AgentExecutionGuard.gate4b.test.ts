import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("Gate 4B: daily limits and owner approvals — full stack", function () {
  let registry: any, policyRegistry: any, guard: any, target: any;
  let owner: HardhatEthersSigner, wallet: HardhatEthersSigner;
  let agent: ReturnType<typeof ethers.Wallet.createRandom>;
  let agentAddress: string, targetAddress: string, guardAddress: string;
  const DEADLINE = 4102444800n;
  const ZERO_SELECTOR = "0x00000000";
  const regTypes = { AgentRegistration: [
    { name: "agent", type: "address" }, { name: "owner", type: "address" }, { name: "metadataHash", type: "bytes32" },
  ] };
  const intentTypes = { ExecutionIntent: [
    { name: "agent", type: "address" }, { name: "wallet", type: "address" }, { name: "target", type: "address" },
    { name: "value", type: "uint256" }, { name: "calldataHash", type: "bytes32" }, { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }, { name: "policyHash", type: "bytes32" },
  ] };
  const approvalTypes = { ExecutionApproval: [
    { name: "agent", type: "address" }, { name: "wallet", type: "address" }, { name: "target", type: "address" },
    { name: "value", type: "uint256" }, { name: "calldataHash", type: "bytes32" }, { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }, { name: "policyHash", type: "bytes32" }, { name: "approvalDeadline", type: "uint256" },
  ] };

  const CREATE_POLICY_SELECTOR = ethers.id("createPolicy(bytes32,address,uint128,uint128,uint128,uint64,uint64,(address,bytes4)[],address[])").slice(0,10);
  const coder = ethers.AbiCoder.defaultAbiCoder();

  async function createPolicy(dailyLimit: bigint, approvalThreshold: bigint, maxTxValue = ethers.parseEther("100")) {
    const salt = ethers.keccak256(ethers.toUtf8Bytes(`${dailyLimit}-${approvalThreshold}-${maxTxValue}-${Date.now()}-${Math.random()}`));
    const payload = coder.encode(
      ["bytes32","address","uint128","uint128","uint128","uint64","uint64","tuple(address,bytes4)[]","address[]"],
      [salt, agentAddress, maxTxValue, dailyLimit, approvalThreshold, 0n, DEADLINE, [[targetAddress, ZERO_SELECTOR]], [targetAddress]]
    );
    await owner.sendTransaction({ to: await policyRegistry.getAddress(), data: ethers.concat([CREATE_POLICY_SELECTOR, payload]) });
    return policyRegistry.policyHashOf(await policyRegistry.computePolicyId(owner.address, salt));
  }

  async function signIntent(policyHash: string, value: bigint, nonce: bigint, deadline = DEADLINE) {
    const net = await ethers.provider.getNetwork();
    return agent.signTypedData({ name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress }, intentTypes,
      { agent: agentAddress, wallet: wallet.address, target: targetAddress, value, calldataHash: ethers.keccak256("0x"), nonce, deadline, policyHash });
  }
  async function signApproval(policyHash: string, value: bigint, nonce: bigint, approvalDeadline: bigint, deadline = DEADLINE) {
    const net = await ethers.provider.getNetwork();
    return owner.signTypedData({ name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress }, approvalTypes,
      { agent: agentAddress, wallet: wallet.address, target: targetAddress, value, calldataHash: ethers.keccak256("0x"), nonce, deadline, policyHash, approvalDeadline });
  }
  async function execute(policyHash: string, value: bigint, nonce: bigint, deadline = DEADLINE) {
    const sig = await signIntent(policyHash, value, nonce, deadline);
    return guard.execute(agentAddress, wallet.address, targetAddress, value, "0x", nonce, deadline, policyHash, sig, { value });
  }
  async function executeWithApproval(policyHash: string, value: bigint, nonce: bigint, approvalDeadline: bigint, intentDeadline = DEADLINE) {
    const sig = await signIntent(policyHash, value, nonce, intentDeadline);
    const approval = await signApproval(policyHash, value, nonce, approvalDeadline, intentDeadline);
    return guard.executeWithApproval(agentAddress, wallet.address, targetAddress, value, "0x", nonce, intentDeadline, policyHash, sig, approvalDeadline, approval, { value });
  }

  beforeEach(async function () {
    [owner, wallet] = await ethers.getSigners();
    agent = ethers.Wallet.createRandom().connect(ethers.provider);
    agentAddress = agent.address;
    registry = await (await ethers.getContractFactory("AgentRegistry")).deploy();
    await registry.waitForDeployment();
    const net = await ethers.provider.getNetwork();
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("gate4b"));
    const sig = await agent.signTypedData({ name: "AgentRegistry", version: "1", chainId: net.chainId, verifyingContract: await registry.getAddress() }, regTypes,
      { agent: agentAddress, owner: owner.address, metadataHash });
    await registry.register(agentAddress, owner.address, metadataHash, sig);
    policyRegistry = await (await ethers.getContractFactory("PolicyRegistry")).deploy();
    await policyRegistry.waitForDeployment();
    guard = await (await ethers.getContractFactory("AgentExecutionGuard")).deploy(await registry.getAddress(), await policyRegistry.getAddress());
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();
    target = await (await ethers.getContractFactory("RecordingTarget")).deploy();
    await target.waitForDeployment();
    targetAddress = await target.getAddress();
  });

  describe("daily-limit accounting", function () {
    it("allows exactly dailyLimit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, limit, 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
    });
    it("rejects dailyLimit + 1 wei", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await expect(execute(policy, limit + 1n, 0n)).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });
    it("aggregates sequential spends under one policy", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.4"), 0n);
      await execute(policy, ethers.parseEther("0.6"), 1n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
      await expect(execute(policy, 1n, 2n)).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });
    it("does not consume allowance or nonce when target reverts", async function () {
      const reverter = await (await ethers.getContractFactory("AlwaysRevertingTarget")).deploy();
      await reverter.waitForDeployment();
      const ra = await reverter.getAddress();
      const salt = ethers.keccak256(ethers.toUtf8Bytes("reverter"));
      const payload = coder.encode(["bytes32","address","uint128","uint128","uint128","uint64","uint64","tuple(address,bytes4)[]","address[]"],
        [salt,agentAddress,ethers.parseEther("1"),ethers.parseEther("1"),ethers.MaxUint128,0n,DEADLINE,[[ra,ZERO_SELECTOR]],[ra]]);
      await owner.sendTransaction({to: await policyRegistry.getAddress(), data: ethers.concat([CREATE_POLICY_SELECTOR,payload])});
      const policy = await policyRegistry.policyHashOf(await policyRegistry.computePolicyId(owner.address,salt));
      const net = await ethers.provider.getNetwork();
      const sig = await agent.signTypedData({name:"AgentExecutionGuard",version:"1",chainId:net.chainId,verifyingContract:guardAddress},intentTypes,
        {agent:agentAddress,wallet:wallet.address,target:ra,value:ethers.parseEther("0.5"),calldataHash:ethers.keccak256("0x"),nonce:0n,deadline:DEADLINE,policyHash:policy});
      await expect(guard.execute(agentAddress,wallet.address,ra,ethers.parseEther("0.5"),"0x",0n,DEADLINE,policy,sig,{value:ethers.parseEther("0.5")})).to.be.revertedWithCustomError(guard,"ExecutionFailed");
      expect((await guard.dailySpend(policy)).spent).to.equal(0n);
      expect(await guard.nextNonce(agentAddress)).to.equal(0n);
    });
    it("zero dailyLimit rejects positive value", async function () {
      const policy = await createPolicy(0n, ethers.MaxUint128);
      await expect(execute(policy, 1n, 0n)).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });
  });

  describe("owner approval", function () {
    it("does not require approval at threshold", async function () {
      const threshold = ethers.parseEther("1");
      const policy = await createPolicy(ethers.parseEther("10"), threshold);
      await execute(policy, threshold, 0n);
    });
    it("requires approval one wei above threshold", async function () {
      const threshold = ethers.parseEther("1");
      const value = threshold + 1n;
      const policy = await createPolicy(ethers.parseEther("10"), threshold);
      await expect(execute(policy, value, 0n)).to.be.revertedWithCustomError(guard, "ApprovalRequired");
      await executeWithApproval(policy, value, 0n, DEADLINE);
    });
    it("rejects a nonce-mismatched owner approval", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const approval = await signApproval(policy, 1n, 1n, DEADLINE);
      const intent = await signIntent(policy, 1n, 0n);
      await expect(guard.executeWithApproval(agentAddress,wallet.address,targetAddress,1n,"0x",0n,DEADLINE,policy,intent,DEADLINE,approval,{value:1n})).to.be.revertedWithCustomError(guard,"InvalidApprovalSignature");
    });
    it("rejects approval signed by a non-owner", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const attacker = ethers.Wallet.createRandom().connect(ethers.provider);
      const net = await ethers.provider.getNetwork();
      const approval = await attacker.signTypedData({name:"AgentExecutionGuard",version:"1",chainId:net.chainId,verifyingContract:guardAddress},approvalTypes,
        {agent:agentAddress,wallet:wallet.address,target:targetAddress,value:1n,calldataHash:ethers.keccak256("0x"),nonce:0n,deadline:DEADLINE,policyHash:policy,approvalDeadline:DEADLINE});
      const intent = await signIntent(policy,1n,0n);
      await expect(guard.executeWithApproval(agentAddress,wallet.address,targetAddress,1n,"0x",0n,DEADLINE,policy,intent,DEADLINE,approval,{value:1n})).to.be.revertedWithCustomError(guard,"InvalidApprovalSignature");
    });
    it("rejects approvalDeadline after intent deadline", async function () {
      const policy = await createPolicy(ethers.parseEther("10"),0n);
      const intentDeadline = 4102440000n;
      const approvalDeadline = intentDeadline + 1n;
      const intent = await signIntent(policy,1n,0n,intentDeadline);
      const approval = await signApproval(policy,1n,0n,approvalDeadline,intentDeadline);
      await expect(guard.executeWithApproval(agentAddress,wallet.address,targetAddress,1n,"0x",0n,intentDeadline,policy,intent,approvalDeadline,approval,{value:1n})).to.be.revertedWithCustomError(guard,"ApprovalDeadlineAfterIntent");
    });
    it("expired approval cannot authorize execution", async function () {
      const policy = await createPolicy(ethers.parseEther("10"),0n);
      const block = (await ethers.provider.getBlock("latest"))!.timestamp;
      const approvalDeadline = BigInt(block + 10);
      const intentDeadline = BigInt(block + 1000);
      const intent = await signIntent(policy,1n,0n,intentDeadline);
      const approval = await signApproval(policy,1n,0n,approvalDeadline,intentDeadline);
      await ethers.provider.send("evm_setNextBlockTimestamp", [block + 11]);
      await expect(guard.executeWithApproval(agentAddress,wallet.address,targetAddress,1n,"0x",0n,intentDeadline,policy,intent,approvalDeadline,approval,{value:1n})).to.be.revertedWithCustomError(guard,"ApprovalExpired");
    });
    it("approval cannot bypass maxTxValue or dailyLimit", async function () {
      const capped = await createPolicy(10n,0n,1n);
      const intent = await signIntent(capped,2n,0n);
      const approval = await signApproval(capped,2n,0n,DEADLINE);
      await expect(guard.executeWithApproval(agentAddress,wallet.address,targetAddress,2n,"0x",0n,DEADLINE,capped,intent,DEADLINE,approval,{value:2n})).to.be.revertedWithCustomError(guard,"MaxTxValueExceeded");
      const limited = await createPolicy(1n,0n);
      await executeWithApproval(limited,1n,0n,DEADLINE);
      const intent2 = await signIntent(limited,1n,1n);
      const approval2 = await signApproval(limited,1n,1n,DEADLINE);
      await expect(guard.executeWithApproval(agentAddress,wallet.address,targetAddress,1n,"0x",1n,DEADLINE,limited,intent2,DEADLINE,approval2,{value:1n})).to.be.revertedWithCustomError(guard,"DailyLimitExceeded");
    });
  });
});
