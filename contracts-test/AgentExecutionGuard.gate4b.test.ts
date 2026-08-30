import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("Gate 4B: daily limits and owner approvals — full stack", function () {
  let agentRegistry: any;
  let policyRegistry: any;
  let guard: any;
  let target: any;
  let targetAddress: string;
  let owner: HardhatEthersSigner;
  let wallet: HardhatEthersSigner;
  let agent: ReturnType<typeof ethers.Wallet.createRandom>;
  let guardAddress: string;

  const FAR_DEADLINE = 4102444800n;
  const ZERO_SELECTOR = "0x00000000";

  const registrationTypes = {
    AgentRegistration: [
      { name: "agent", type: "address" },
      { name: "owner", type: "address" },
      { name: "metadataHash", type: "bytes32" },
    ],
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

  async function registerAgent() {
    const net = await ethers.provider.getNetwork();
    const domain = {
      name: "AgentRegistry",
      version: "1",
      chainId: net.chainId,
      verifyingContract: await agentRegistry.getAddress(),
    };
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("gate4b-agent"));
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
    maxTxValue = ethers.parseEther("100")
  ) {
    const salt = ethers.keccak256(
      ethers.toUtf8Bytes(`${dailyLimit}-${approvalThreshold}-${maxTxValue}-${Date.now()}-${Math.random()}`)
    );
    await policyRegistry.connect(owner).createPolicy(
      salt,
      agent.address,
      maxTxValue,
      dailyLimit,
      approvalThreshold,
      0n,
      FAR_DEADLINE,
      [{ target: targetAddress, selector: ZERO_SELECTOR }],
      [targetAddress]
    );
    const policyId = await policyRegistry.computePolicyId(owner.address, salt);
    return await policyRegistry.policyHashOf(policyId);
  }

  async function signIntent(
    policyHash: string,
    value: bigint,
    nonce: bigint,
    deadline = FAR_DEADLINE
  ) {
    const net = await ethers.provider.getNetwork();
    return agent.signTypedData(
      { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress },
      intentTypes,
      {
        agent: agent.address,
        wallet: wallet.address,
        target: targetAddress,
        value,
        calldataHash: ethers.keccak256("0x"),
        nonce,
        deadline,
        policyHash,
      }
    );
  }

  async function signApproval(
    policyHash: string,
    value: bigint,
    nonce: bigint,
    approvalDeadline: bigint,
    deadline = FAR_DEADLINE
  ) {
    const net = await ethers.provider.getNetwork();
    return owner.signTypedData(
      { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress },
      approvalTypes,
      {
        agent: agent.address,
        wallet: wallet.address,
        target: targetAddress,
        value,
        calldataHash: ethers.keccak256("0x"),
        nonce,
        deadline,
        policyHash,
        approvalDeadline,
      }
    );
  }

  async function execute(policyHash: string, value: bigint, nonce: bigint) {
    const sig = await signIntent(policyHash, value, nonce);
    return guard.execute(
      agent.address,
      wallet.address,
      targetAddress,
      value,
      "0x",
      nonce,
      FAR_DEADLINE,
      policyHash,
      sig,
      { value }
    );
  }

  async function executeWithApproval(
    policyHash: string,
    value: bigint,
    nonce: bigint,
    approvalDeadline: bigint,
    approvalDeadlineForIntent = FAR_DEADLINE
  ) {
    const sig = await signIntent(policyHash, value, nonce);
    const approval = await signApproval(policyHash, value, nonce, approvalDeadline, approvalDeadlineForIntent);
    return guard.executeWithApproval(
      agent.address,
      wallet.address,
      targetAddress,
      value,
      "0x",
      nonce,
      FAR_DEADLINE,
      policyHash,
      sig,
      approvalDeadline,
      approval,
      { value }
    );
  }

  beforeEach(async function () {
    [owner, wallet] = await ethers.getSigners();
    agent = ethers.Wallet.createRandom().connect(ethers.provider);

    agentRegistry = await (await ethers.getContractFactory("AgentRegistry")).deploy();
    await agentRegistry.waitForDeployment();
    await registerAgent();

    policyRegistry = await (await ethers.getContractFactory("PolicyRegistry")).deploy();
    await policyRegistry.waitForDeployment();

    guard = await (await ethers.getContractFactory("AgentExecutionGuard")).deploy(
      await agentRegistry.getAddress(),
      await policyRegistry.getAddress()
    );
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();

    target = await (await ethers.getContractFactory("RecordingTarget")).deploy();
    await target.waitForDeployment();
    targetAddress = await target.getAddress();
  });

  describe("daily-limit accounting", function () {
    it("allows a first spend exactly equal to dailyLimit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, limit, 0n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
    });

    it("rejects dailyLimit + 1 wei", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await expect(execute(policy, limit + 1n, 0n))
        .to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("allows two spends whose sum exactly equals the limit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.4"), 0n);
      await execute(policy, ethers.parseEther("0.6"), 1n);
      expect((await guard.dailySpend(policy)).spent).to.equal(limit);
    });

    it("rejects a cumulative total above the limit", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.7"), 0n);
      await expect(execute(policy, ethers.parseEther("0.300000000000000001"), 1n))
        .to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("shares allowance by policyHash across relayers", async function () {
      const limit = ethers.parseEther("1");
      const policy = await createPolicy(limit, ethers.MaxUint128);
      await execute(policy, ethers.parseEther("0.8"), 0n);
      const sig = await signIntent(policy, ethers.parseEther("0.3"), 1n);
      await expect(
        guard.connect(wallet).execute(
          agent.address, owner.address, targetAddress,
          ethers.parseEther("0.3"), "0x", 1n, FAR_DEADLINE, policy, sig,
          { value: ethers.parseEther("0.3") }
        )
      ).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });

    it("does not consume spend or nonce when the external call reverts", async function () {
      const reverter = await (await ethers.getContractFactory("AlwaysRevertingTarget")).deploy();
      await reverter.waitForDeployment();
      const reverterAddress = await reverter.getAddress();

      const salt = ethers.keccak256(ethers.toUtf8Bytes("reverter-policy"));
      await policyRegistry.connect(owner).createPolicy(
        salt, agent.address, ethers.parseEther("1"), ethers.parseEther("1"), ethers.MaxUint128,
        0n, FAR_DEADLINE,
        [{ target: reverterAddress, selector: ZERO_SELECTOR }],
        [reverterAddress]
      );
      const policy = await policyRegistry.policyHashOf(await policyRegistry.computePolicyId(owner.address, salt));
      const sig = await agent.signTypedData(
        { name: "AgentExecutionGuard", version: "1", chainId: (await ethers.provider.getNetwork()).chainId, verifyingContract: guardAddress },
        intentTypes,
        { agent: agent.address, wallet: wallet.address, target: reverterAddress, value: ethers.parseEther("0.5"), calldataHash: ethers.keccak256("0x"), nonce: 0n, deadline: FAR_DEADLINE, policyHash: policy }
      );
      await expect(guard.execute(agent.address, wallet.address, reverterAddress, ethers.parseEther("0.5"), "0x", 0n, FAR_DEADLINE, policy, sig, { value: ethers.parseEther("0.5") }))
        .to.be.revertedWithCustomError(guard, "ExecutionFailed");
      expect((await guard.dailySpend(policy)).spent).to.equal(0n);
      expect(await guard.nextNonce(agent.address)).to.equal(0n);
    });

    it("zero dailyLimit rejects positive value", async function () {
      const policy = await createPolicy(0n, ethers.MaxUint128);
      await expect(execute(policy, 1n, 0n))
        .to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });
  });

  describe("approval semantics", function () {
    it("does not require approval at exactly approvalThreshold", async function () {
      const threshold = ethers.parseEther("1");
      const policy = await createPolicy(ethers.parseEther("10"), threshold);
      await execute(policy, threshold, 0n);
    });

    it("requires approval one wei above threshold and accepts a valid owner approval", async function () {
      const threshold = ethers.parseEther("1");
      const value = threshold + 1n;
      const policy = await createPolicy(ethers.parseEther("10"), threshold);
      await expect(execute(policy, value, 0n))
        .to.be.revertedWithCustomError(guard, "ApprovalRequired");
      await executeWithApproval(policy, value, 0n, FAR_DEADLINE);
      expect((await guard.dailySpend(policy)).spent).to.equal(value);
    });

    it("threshold zero requires approval for every positive-value execution", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      await expect(execute(policy, 1n, 0n))
        .to.be.revertedWithCustomError(guard, "ApprovalRequired");
      await executeWithApproval(policy, 1n, 0n, FAR_DEADLINE);
    });

    it("rejects approval signed for a different nonce", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const approval = await signApproval(policy, 1n, 1n, FAR_DEADLINE);
      const intent = await signIntent(policy, 1n, 0n);
      await expect(
        guard.executeWithApproval(
          agent.address, wallet.address, targetAddress, 1n, "0x", 0n, FAR_DEADLINE,
          policy, intent, FAR_DEADLINE, approval, { value: 1n }
        )
      ).to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
    });

    it("rejects approval with an altered approvalDeadline", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const signedDeadline = FAR_DEADLINE - 1n;
      const approval = await signApproval(policy, 1n, 0n, signedDeadline);
      const intent = await signIntent(policy, 1n, 0n);
      await expect(
        guard.executeWithApproval(
          agent.address, wallet.address, targetAddress, 1n, "0x", 0n, FAR_DEADLINE,
          policy, intent, FAR_DEADLINE, approval, { value: 1n }
        )
      ).to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
    });

    it("rejects approval signed by a non-owner", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const attacker = ethers.Wallet.createRandom().connect(ethers.provider);
      const net = await ethers.provider.getNetwork();
      const approval = await attacker.signTypedData(
        { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress },
        approvalTypes,
        { agent: agent.address, wallet: wallet.address, target: targetAddress, value: 1n, calldataHash: ethers.keccak256("0x"), nonce: 0n, deadline: FAR_DEADLINE, policyHash: policy, approvalDeadline: FAR_DEADLINE }
      );
      const intent = await signIntent(policy, 1n, 0n);
      await expect(
        guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 1n })
      ).to.be.revertedWithCustomError(guard, "InvalidApprovalSignature");
    });

    it("rejects approvalDeadline after the intent deadline", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const intentDeadline = 4102440000n;
      const approvalDeadline = intentDeadline + 1n;
      const intent = await signIntent(policy, 1n, 0n, intentDeadline);
      const approval = await signApproval(policy, 1n, 0n, approvalDeadline, intentDeadline);
      await expect(
        guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, intentDeadline, policy, intent, approvalDeadline, approval, { value: 1n })
      ).to.be.revertedWithCustomError(guard, "ApprovalDeadlineAfterIntent");
    });

    it("rejects an expired approval", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n);
      const block = (await ethers.provider.getBlock("latest"))!.timestamp;
      const approvalDeadline = BigInt(block + 10);
      const intentDeadline = BigInt(block + 1000);
      const intent = await signIntent(policy, 1n, 0n, intentDeadline);
      const approval = await signApproval(policy, 1n, 0n, approvalDeadline, intentDeadline);
      await ethers.provider.send("evm_setNextBlockTimestamp", [block + 11]);
      await expect(
        guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 0n, intentDeadline, policy, intent, approvalDeadline, approval, { value: 1n })
      ).to.be.revertedWithCustomError(guard, "ApprovalExpired");
    });

    it("approval cannot bypass maxTxValue", async function () {
      const policy = await createPolicy(ethers.parseEther("10"), 0n, 1n);
      const intent = await signIntent(policy, 2n, 0n);
      const approval = await signApproval(policy, 2n, 0n, FAR_DEADLINE);
      await expect(
        guard.executeWithApproval(agent.address, wallet.address, targetAddress, 2n, "0x", 0n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 2n })
      ).to.be.revertedWithCustomError(guard, "MaxTxValueExceeded");
    });

    it("approval cannot bypass the daily limit", async function () {
      const policy = await createPolicy(1n, 0n);
      await executeWithApproval(policy, 1n, 0n, FAR_DEADLINE);
      const intent = await signIntent(policy, 1n, 1n);
      const approval = await signApproval(policy, 1n, 1n, FAR_DEADLINE);
      await expect(
        guard.executeWithApproval(agent.address, wallet.address, targetAddress, 1n, "0x", 1n, FAR_DEADLINE, policy, intent, FAR_DEADLINE, approval, { value: 1n })
      ).to.be.revertedWithCustomError(guard, "DailyLimitExceeded");
    });
  });
});
