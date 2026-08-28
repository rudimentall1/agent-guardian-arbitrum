import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * Gate 4B hostile campaign on the real AgentRegistry + PolicyRegistry +
 * AgentExecutionGuard stack. Scope: native ETH daily accounting and owner
 * approval. ERC-20 and argument-level authorization remain explicitly out
 * of scope.
 */
describe("Gate 4B: daily limits and owner approvals — full stack", function () {
  let agentRegistry: any;
  let policyRegistry: any;
  let guard: any;
  let target: any;
  let targetAddress: string;
  let reverter: any;
  let reverterAddress: string;
  let owner: HardhatEthersSigner;
  let wallet: HardhatEthersSigner;
  let agent: ReturnType<typeof ethers.Wallet.createRandom>;

  const FAR_DEADLINE = 4102444800n;
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
  const approvalTypes = {
    ExecutionApproval: [
      { name: "agent", type: "address" },
      { name: "wallet", type: "address" },
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "calldataHash", type: "bytes32" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "policyHash", type: "bytes32" },
      { name: "approvalDeadline", type: "uint256" },
    ],
  };
  const registrationTypes = {
    AgentRegistration: [
      { name: "agent", type: "address" },
      { name: "owner", type: "address" },
      { name: "metadataHash", type: "bytes32" },
    ],
  };

  async function guardDomain() {
    const net = await ethers.provider.getNetwork();
    return { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: await guard.getAddress() };
  }

  async function registerAgent() {
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("gate4b-agent"));
    const net = await ethers.provider.getNetwork();
    const domain = { name: "AgentRegistry", version: "1", chainId: net.chainId, verifyingContract: await agentRegistry.getAddress() };
    const sig = await agent.signTypedData(domain, registrationTypes, {
      agent: agent.address,
      owner: owner.address,
      metadataHash,
    });
    await agentRegistry.register(agent.address, owner.address, metadataHash, sig);
  }

  async function createPolicy(
    dailyLimit: bigint,
    approvalThreshold: bigint,
    targetAddressForPolicy = targetAddress,
    maxTxValue = ethers.parseEther("100")
  ) {
    const salt = ethers.keccak256(ethers.toUtf8Bytes(`${dailyLimit}-${approvalThreshold}-${targetAddressForPolicy}-${Date.now()}-${Math.random()}`));
    await policyRegistry.connect(owner).createPolicy(
      salt,
      agent.address,
      maxTxValue,
      dailyLimit,
      approvalThreshold,
      0n,
      FAR_DEADLINE,
      [],
      [targetAddressForPolicy]
    );
    const policyId = await policyRegistry.computePolicyId(owner.address, salt);
    return await policyRegistry.policyHashOf(policyId);
  }

  async function signIntent(policyHash: string, value: bigint, nonce: bigint, target = targetAddress, data = "0x", deadline = FAR_DEADLINE) {
    const domain = await guardDomain();
    return agent.signTypedData(domain, intentTypes, {
      agent: agent.address,
      wallet: wallet.address,
      target,
      value,
      calldataHash: ethers.keccak256(data),
      nonce,
      deadline,
      policyHash,
    });
  }

  async function signApproval(
    policyHash: string,
    value: bigint,
    nonce: bigint,
    approvalDeadline: bigint,
    target = targetAddress,
    data = "0x",
    deadline = FAR_DEADLINE
  ) {
    const domain = await guardDomain();
    return owner.signTypedData(domain, approvalTypes, {
      agent: agent.address,
      wallet: wallet.address,
      target,
      value,
      calldataHash: ethers.keccak256(data),
      nonce,
      deadline,
      policyHash,
      approvalDeadline,
    });
  }

  async function execute(policyHash: string, value: bigint, nonce: bigint, targetForCall = targetAddress, data = "0x") {
    const sig = await signIntent(policyHash, value, nonce, targetForCall, data);
    return guard.execute(agent.address, wallet.address, targetForCall, value, data, nonce, FAR_DEADLINE, policyHash, sig, { value });
  }

  async function executeWithApproval(policyHash: string, value: bigint, nonce: bigint, approvalDeadline: bigint, targetForCall = targetAddress, data = "0x") {
    const sig = await signIntent(policyHash, value, nonce, targetForCall, data);
    const approval = await signApproval(policyHash, value, nonce, approvalDeadline, targetForCall, data);
    return guard.executeWithApproval(agent.address, wallet.address, targetForCall, value, data, nonce, FAR_DEADLINE, policyHash, sig, approvalDeadline, approval, { value });
  }

  beforeEach(async function () {
    [owner, wallet] = await ethers.getSigners();
    agent = ethers.Wallet.createRandom().connect(ethers.provider);

    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    agentRegistry = await AgentRegistry.deploy();
    await agentRegistry.waitForDeployment();
    await registerAgent();

    const PolicyRegistry = await ethers.getContractFactory("PolicyRegistry");
    policyRegistry = await PolicyRegistry.deploy();
    await policyRegistry.waitForDeployment();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    guard = await Guard.deploy(await agentRegistry.getAddress(), await policyRegistry.getAddress());
    await guard.waitForDeployment();

    const Target = await ethers.getContractFactory("RecordingTarget");
    target = await Target.deploy();
    await target.waitForDeployment();
    targetAddress = await target.getAddress();

    const Reverter = await ethers.getContractFactory("AlwaysRevertingTarget");
    reverter = await Reverter.deploy();
    await reverter.waitForDeployment();
    reverterAddress = await reverter.getAddress();
  });

  describe("daily-limit accounting", function () {
    it("allows a first spend exactly equal to dailyLimit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, limit, 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
    });

    it("rejects dailyLimit + 1 wei through the daily ledger", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await expect(execute(policy, limit + 1n, 0n)).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("allows two spends whose sum exactly equals the limit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.4"), 0n);
      await execute(policy, ethers.parseEther("0.6"), 1n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
    });

    it("rejects the second spend when the cumulative total exceeds the limit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.7"), 0n);
      await expect(execute(policy, ethers.parseEther("0.300000000000000001"), 1n)).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("shares one ledger across wallets and relayers because the key is policyHash", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.8"), 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(ethers.parseEther("0.8"));
      const second = await signIntent(policy, ethers.parseEther("0.3"), 1n);
      await expect(guard.connect(wallet).execute(agent.address, owner.address, targetAddress, ethers.parseEther("0.3"), "0x", 1n, FAR_DEADLINE, policy, second, { value: ethers.parseEther("0.3") }))
        .to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("does not consume daily allowance when the external call reverts", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128, reverterAddress);
      const sig = await signIntent(policy, ethers.parseEther("0.5"), 0n, reverterAddress);
      await expect(guard.execute(agent.address, wallet.address, reverterAddress, ethers.parseEther("0.5"), "0x", 0n, FAR_DEADLINE, policy, sig, { value: ethers.parseEther("0.5") }))
        .to.be.revertedWithCustomError(guard, "ExecutionFailed");
      expect((await guard.dailySpend(policy)).spent).to.equal(0n);
      expect(await guard.nextNonce(agent.address)).to.equal(0n);
    });

    it("zero-value execution does not increase daily spend", async function () {
      const policy = await createPolicy(0n, ethers.MaxUint128);
      await execute(policy, 0n, 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(0n);
    });

    it("dailyLimit zero rejects positive-value execution", async function () {
      const policy = await createPolicy(0n, ethers.MaxUint128);
      await expect(execute(policy, 1n, 0n)).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("starts a fresh bucket after UTC midnight without a reset transaction", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      const now = (await ethers.provider.getBlock("latest"))!.timestamp;
      const nextDay = BigInt(Math.floor(now / 86400) + 1) * 86400n;
      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(nextDay - 1n)]);
      await execute(policy, limit, 0n);
      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(nextDay + 1n)]);
      await execute(policy, limit, 1n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
      expect((await guard.dailySpend(policy)).day).to.equal(nextDay / 86400n);
    });

    it("handles the maximum uint128 daily limit at the exact representable boundary", async function () {
      await ethers.provider.send("hardhat_setBalance", [owner.address, ethers.toBeHex(ethers.MaxUint256)]);
      const policy = await createPolicy(ethers.MaxUint128, ethers.MaxUint128, targetAddress, ethers.MaxUint128);
      await execute(policy, ethers.MaxUint128, 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(ethers.MaxUint128);
    });
  });

  describe("approval semantics", function () {
    it("does not require approval at exactly approvalThreshold", async function () {
      const threshold = ethers.parseEther("1");
      const policy = await createPolicy(ethers.parseEther("10"), threshold);
      await execute(policy, threshold, 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(threshold);
    });

    it("requires approval one wei above threshold", async function () {
      const threshold = ethers.parseEther("1");
      const value = threshold + 1n;
      const policy = await createPolicy(ethers.parseEther("10"), threshold);
      await expect(execute(policy, value, 0n)).to.be.revertedWithCustomError(guard, "ApprovalRequired");
      await executeWithApproval(policy, value, 0n, FAR_DEADLINE);
      expect((await guard.dailySpend(policy)).spent).to.equal(value);
    });

    it("threshold zero requires approval for every positive-value execution", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      await expect(execute(policy, 1n, 0n)).to.be.revertedWithCustomError(guard, "ApprovalRequired");
      await executeWithApproval(policy, 1n, 0n, FAR_DEADLINE);
    });

    it("rejects an approval signed for a different nonce", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const approval = await signApproval(policy, 1n, 0n, FAR_DEADLINE);
      const intent = await signIntent(policy, 1n, 1n);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 1n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
    });

    it("rejects an approval replayed with different calldata", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const approval = await signApproval(policy, 1n, 0n, FAR_DEADLINE, targetAddress, "0x");
      const data = "0xdeadbeef";
      const intent = await signIntent(policy, 1n, 0n, targetAddress, data);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, data, 0n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
    });

    it("rejects an approval signed by a non-owner", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const attacker = ethers.Wallet.createRandom().connect(ethers.provider);
      const approval = await attacker.signTypedData(await guardDomain(), approvalTypes, {
        agent: agent.address, wallet: wallet.address, target: targetAddress, value: 1n,
        calldataHash: ethers.keccak256("0x"), nonce: 0n, deadline: FAR_DEADLINE,
        policyHash: policy, approvalDeadline: FAR_DEADLINE,
      });
      const intent = await signIntent(policy, 1n, 0n);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
    });

    it("rejects approvalDeadline after intent deadline", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const intentDeadline = 4102440000n;
      const approvalDeadline = intentDeadline + 1n;
      const intent = await signIntent(policy, 1n, 0n, targetAddress, "0x", intentDeadline);
      const approval = await signApproval(policy, 1n, 0n, approvalDeadline, targetAddress, "0x", intentDeadline);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, intentDeadline, policy, intent, approvalDeadline, approval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "ApprovalDeadlineAfterIntent");
    });

    it("expired approval cannot authorize execution", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const block = (await ethers.provider.getBlock("latest"))!.timestamp;
      const approvalDeadline = BigInt(block + 10);
      const intentDeadline = BigInt(block + 1000);
      const intent = await signIntent(policy, 1n, 0n, targetAddress, "0x", intentDeadline);
      const approval = await signApproval(policy, 1n, 0n, approvalDeadline, targetAddress, "0x", intentDeadline);
      await ethers.provider.send("evm_setNextBlockTimestamp", [block + 11]);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, intentDeadline, policy, intent, approvalDeadline, approval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "ApprovalExpired");
    });

    it("approval cannot bypass maxTxValue", async function () {
      const policy = await createPolicy(1n, 0n, targetAddress, 1n);
      const value = 2n;
      const intent = await signIntent(policy, value, 0n);
      const approval = await signApproval(policy, value, 0n, FAR_DEADLINE);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, value, "0x", 0n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value }))
        .to.be.revertedWithCustomError(guard, "MaxTxValueExceeded");
    });

    it("approval cannot bypass the daily limit", async function () {
      const policy = await createPolicy(1n, 0n);
      await executeWithApproval(policy, 1n, 0n, FAR_DEADLINE);
      const intent = await signIntent(policy, 1n, 1n);
      const approval = await signApproval(policy, 1n, 1n, FAR_DEADLINE);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 1n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("failed approval checks do not mutate spend or nonce", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const badApproval = await owner.signTypedData(await guardDomain(), approvalTypes, {
        agent: agent.address, wallet: wallet.address, target: targetAddress, value: 1n,
        calldataHash: ethers.keccak256("0x"), nonce: 0n, deadline: FAR_DEADLINE,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("wrong")), approvalDeadline: FAR_DEADLINE,
      });
      const intent = await signIntent(policy, 1n, 0n);
      await expect(guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, badApproval, { value: 1n }))
        .to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
      expect((await guard.dailySpend(policy)).spent).to.equal(0n);
      expect(await guard.nextNonce(agent.address)).to.equal(0n);
    });
  });
});
