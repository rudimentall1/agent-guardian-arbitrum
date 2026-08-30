import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * Gate 4A dedicated adversarial suite: target+selector authorization and
 * maxTxValue enforcement, exercised through the REAL AgentRegistry +
 * PolicyRegistry + AgentExecutionGuard stack (not mocks). Covers the
 * full 25-scenario attack campaign from the Gate 4A brief, the mandatory
 * Cartesian-product regression (also covered at the PolicyRegistry-only
 * level in PolicyRegistry.test.ts — this file proves it end-to-end
 * through actual `execute()` calls), and seeded property tests.
 *
 * See docs/adr/0005-paired-target-selector-authorization.md and
 * docs/gate-4a-call-authorization.md.
 */
describe("Gate 4A: call authorization (target+selector, maxTxValue) — full stack", function () {
  let agentRegistry: any;
  let agentRegistryAddress: string;
  let policyRegistry: any;
  let policyRegistryAddress: string;
  let guard: any;
  let guardAddress: string;
  let selectorTarget: any;
  let selectorTargetAddress: string;
  let recordingTarget: any;
  let recordingTargetAddress: string;
  let owner: HardhatEthersSigner;
  let wallet: HardhatEthersSigner;
  let agent: ReturnType<typeof ethers.Wallet.createRandom>;

  const FAR_DEADLINE = 4102444800n;
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

  async function registerAgent(agentWallet: any, ownerAddr: string) {
    const net = await ethers.provider.getNetwork();
    const domain = { name: "AgentRegistry", version: "1", chainId: net.chainId, verifyingContract: agentRegistryAddress };
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("config"));
    const sig = await agentWallet.signTypedData(domain, registrationTypes, {
      agent: agentWallet.address,
      owner: ownerAddr,
      metadataHash,
    });
    await agentRegistry.register(agentWallet.address, ownerAddr, metadataHash, sig);
  }

  async function createPolicy(
    forAgent: string,
    salt: string,
    opts: {
      maxTxValue?: bigint;
      calls?: { target: string; selector: string }[];
      nativeTransferTargets?: string[];
      validFrom?: bigint;
      validUntil?: bigint;
    } = {}
  ) {
    const tx = await policyRegistry.connect(owner).createPolicy(
      salt,
      forAgent,
      opts.maxTxValue ?? ethers.parseEther("1"),
      ethers.MaxUint128,
      ethers.MaxUint128,
      opts.validFrom ?? 0n,
      opts.validUntil ?? FAR_DEADLINE,
      opts.calls ?? [],
      opts.nativeTransferTargets ?? []
    );
    await tx.wait();
    const policyId = await policyRegistry.computePolicyId(owner.address, salt);
    const policyHash = await policyRegistry.policyHashOf(policyId);
    return { policyId, policyHash };
  }

  async function intentDomain() {
    const net = await ethers.provider.getNetwork();
    return { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress };
  }

  interface Intent {
    agent: string; wallet: string; target: string; value: bigint; data: string;
    nonce: bigint; deadline: bigint; policyHash: string;
  }

  async function signIntent(signer: any, p: Intent) {
    const d = await intentDomain();
    return signer.signTypedData(d, intentTypes, {
      agent: p.agent, wallet: p.wallet, target: p.target, value: p.value,
      calldataHash: ethers.keccak256(p.data), nonce: p.nonce, deadline: p.deadline, policyHash: p.policyHash,
    });
  }

  async function execute(p: Intent, sig: string) {
    return guard.execute(p.agent, p.wallet, p.target, p.value, p.data, p.nonce, p.deadline, p.policyHash, sig, {
      value: p.value,
    });
  }

  function fooCalldata(x: number) {
    return selectorTarget.interface.encodeFunctionData("foo", [x]);
  }
  function barCalldata(addr: string) {
    return selectorTarget.interface.encodeFunctionData("bar", [addr]);
  }

  beforeEach(async function () {
    [owner, wallet] = await ethers.getSigners();
    agent = ethers.Wallet.createRandom().connect(ethers.provider);

    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    agentRegistry = await AgentRegistry.deploy();
    await agentRegistry.waitForDeployment();
    agentRegistryAddress = await agentRegistry.getAddress();
    await registerAgent(agent, owner.address);

    const PolicyRegistry = await ethers.getContractFactory("PolicyRegistry");
    policyRegistry = await PolicyRegistry.deploy();
    await policyRegistry.waitForDeployment();
    policyRegistryAddress = await policyRegistry.getAddress();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    guard = await Guard.deploy(agentRegistryAddress, policyRegistryAddress);
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();

    const SelectorTarget = await ethers.getContractFactory("SelectorTarget");
    selectorTarget = await SelectorTarget.deploy();
    await selectorTarget.waitForDeployment();
    selectorTargetAddress = await selectorTarget.getAddress();

    const RecordingTarget = await ethers.getContractFactory("RecordingTarget");
    recordingTarget = await RecordingTarget.deploy();
    await recordingTarget.waitForDeployment();
    recordingTargetAddress = await recordingTarget.getAddress();
  });

  // ---------------------------------------------------------------
  // Part 10 (mandatory): Cartesian-product regression, end-to-end
  // ---------------------------------------------------------------
  describe("Cartesian-product regression — end to end through execute()", function () {
    let policyHash: string;
    let otherTarget: any;
    let otherTargetAddress: string;

    beforeEach(async function () {
      const SelectorTarget = await ethers.getContractFactory("SelectorTarget");
      otherTarget = await SelectorTarget.deploy();
      await otherTarget.waitForDeployment();
      otherTargetAddress = await otherTarget.getAddress();

      const fooSel = selectorTarget.interface.getFunction("foo")!.selector;
      const barSel = otherTarget.interface.getFunction("bar")!.selector;

      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("cartesian")), {
        calls: [
          { target: selectorTargetAddress, selector: fooSel }, // A + X
          { target: otherTargetAddress, selector: barSel }, // B + Y
        ],
      });
      policyHash = res.policyHash;
    });

    it("A+X passes, B+Y passes, A+Y and B+X both revert", async function () {
      const fooSel = selectorTarget.interface.getFunction("foo")!.selector;
      const barSel = otherTarget.interface.getFunction("bar")!.selector;

      let intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      let sig = await signIntent(agent, intent);
      await execute(intent, sig);

      intent = {
        agent: agent.address, wallet: wallet.address, target: otherTargetAddress, value: 0n,
        data: barCalldata(wallet.address), nonce: 1n, deadline: FAR_DEADLINE, policyHash,
      };
      sig = await signIntent(agent, intent);
      await execute(intent, sig);

      intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: barCalldata(wallet.address), nonce: 2n, deadline: FAR_DEADLINE, policyHash,
      };
      sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized").withArgs(selectorTargetAddress, barSel, false);

      intent = {
        agent: agent.address, wallet: wallet.address, target: otherTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 2n, deadline: FAR_DEADLINE, policyHash,
      };
      sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized").withArgs(otherTargetAddress, fooSel, false);
    });
  });

  // ---------------------------------------------------------------
  // Part 9: the 25-scenario attack campaign
  // ---------------------------------------------------------------
  describe("attack campaign", function () {
    let policyHash: string;
    let fooSel: string;

    beforeEach(async function () {
      fooSel = selectorTarget.interface.getFunction("foo")!.selector;
      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("campaign")), {
        maxTxValue: ethers.parseEther("1"),
        calls: [{ target: selectorTargetAddress, selector: fooSel }],
        nativeTransferTargets: [recordingTargetAddress],
      });
      policyHash = res.policyHash;
    });

    it("1. allowed target + allowed selector => PASS", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await execute(intent, sig);
      expect(await selectorTarget.fooCallCount()).to.equal(1n);
    });

    it("2. allowed target + forbidden selector => REVERT", async function () {
      const barCd = selectorTarget.interface.encodeFunctionData("bar", [wallet.address]);
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: barCd, nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
    });

    it("3. forbidden target + allowed selector-bytes => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
    });

    it("4. forbidden target + forbidden selector => REVERT", async function () {
      const randomTarget = ethers.Wallet.createRandom().address;
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: randomTarget, value: 0n,
        data: "0xffffffff", nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
    });

    it("8. modified target after signing => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      const tampered = { ...intent, target: recordingTargetAddress };
      await expect(execute(tampered, sig)).to.be.reverted;
    });

    it("9. modified selector/calldata after signing => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      const tampered = { ...intent, data: fooCalldata(999) };
      await expect(execute(tampered, sig)).to.be.revertedWithCustomError(guard, "InvalidSignature");
    });

    it("10. modified calldata arguments (same selector) => REVERT via signature, not silently accepted", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      const tampered = { ...intent, data: fooCalldata(2) };
      await expect(execute(tampered, sig)).to.be.revertedWithCustomError(guard, "InvalidSignature");
    });

    it("11. empty calldata without explicit native-transfer permission => REVERT", async function () {
      const randomTarget = ethers.Wallet.createRandom().address;
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: randomTarget, value: 0n,
        data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized").withArgs(randomTarget, "0x00000000", true);
    });

    it("12. explicit native transfer permission => PASS", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value: 0n,
        data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await execute(intent, sig);
      expect(await recordingTarget.callCount()).to.equal(1n);
    });

    it("13. zero-address target => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: ethers.ZeroAddress, value: 0n,
        data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "ZeroAddress");
    });

    it("14. maxTxValue exact boundary => PASS", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: ethers.parseEther("1"),
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await execute(intent, sig);
    });

    it("15. maxTxValue + 1 => REVERT", async function () {
      const value = ethers.parseEther("1") + 1n;
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "MaxTxValueExceeded");
    });

    it("16. msg.value > signed value => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: ethers.parseEther("0.5"),
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(
        guard.execute(intent.agent, intent.wallet, intent.target, intent.value, intent.data, intent.nonce, intent.deadline, intent.policyHash, sig, { value: ethers.parseEther("0.6") })
      ).to.be.revertedWithCustomError(guard, "ValueMismatch");
    });

    it("17. signed value > maxTxValue (declared and sent, still capped by policy) => REVERT", async function () {
      const value = ethers.parseEther("1") + 1n;
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "MaxTxValueExceeded");
    });

    it("18. policy belonging to another agent => REVERT", async function () {
      const otherAgent = ethers.Wallet.createRandom().connect(ethers.provider);
      await registerAgent(otherAgent, owner.address);
      const otherPolicy = await createPolicy(otherAgent.address, ethers.keccak256(ethers.toUtf8Bytes("other-agent")), {
        nativeTransferTargets: [recordingTargetAddress],
      });
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: otherPolicy.policyHash };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "PolicyAgentMismatch");
    });

    it("19. revoked policy => REVERT", async function () {
      await expect(policyRegistry.connect(owner).revoke(await policyRegistry.policyIdOfHash(policyHash))).to.not.be.reverted;
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "PolicyNotActive");
    });

    it("20. disabled agent => REVERT", async function () {
      await agentRegistry.connect(owner).deactivate(agent.address);
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "AgentNotActive");
    });

    it("21. stale nonce => REVERT", async function () {
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n, data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash };
      const sig = await signIntent(agent, intent);
      await execute(intent, sig);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "InvalidNonce");
    });

    it("22. future nonce => REVERT", async function () {
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n, data: fooCalldata(1), nonce: 1n, deadline: FAR_DEADLINE, policyHash };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "InvalidNonce");
    });

    it("23. replay exact intent => REVERT", async function () {
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n, data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash };
      const sig = await signIntent(agent, intent);
      await execute(intent, sig);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "InvalidNonce");
    });

    it("24. reentrancy attempt => safely contained (blocked, nonce still advances exactly once)", async function () {
      const ReentrantAttacker = await ethers.getContractFactory("ReentrantAttacker");
      const attacker = await ReentrantAttacker.deploy(await guard.getAddress());
      await attacker.waitForDeployment();
      const targetPolicy = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("reentrant")), {
        calls: [{ target: await attacker.getAddress(), selector: attacker.interface.getFunction("attack")!.selector }],
      });
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: await attacker.getAddress(), value: 0n, data: attacker.interface.encodeFunctionData("attack"), nonce: 0n, deadline: FAR_DEADLINE, policyHash: targetPolicy.policyHash };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.not.be.reverted;
      expect(await guard.nextNonce(agent.address)).to.equal(1n);
    });

    it("25. malicious target cannot bypass authorization by re-entering with a different (unauthorized) call", async function () {
      const ReentrantAttacker = await ethers.getContractFactory("ReentrantAttacker");
      const attacker = await ReentrantAttacker.deploy(await guard.getAddress());
      await attacker.waitForDeployment();
      const fooSel = selectorTarget.interface.getFunction("foo")!.selector;
      const policy = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("reentrant-unauthorized")), {
        calls: [{ target: await attacker.getAddress(), selector: attacker.interface.getFunction("attack")!.selector }, { target: selectorTargetAddress, selector: fooSel }],
      });
      const intent: Intent = { agent: agent.address, wallet: wallet.address, target: await attacker.getAddress(), value: 0n, data: attacker.interface.encodeFunctionData("attack"), nonce: 0n, deadline: FAR_DEADLINE, policyHash: policy.policyHash };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.not.be.reverted;
      expect(await guard.nextNonce(agent.address)).to.equal(1n);
    });
  });

  describe("property tests: authorization independence", function () {
    it("authorized(target, selector) != authorized(otherTarget, selector) across randomized (target, selector) pairs", async function () {
      const fooSel = selectorTarget.interface.getFunction("foo")!.selector;
      const barSel = selectorTarget.interface.getFunction("bar")!.selector;
      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("property-target-selector")), {
        calls: [{ target: selectorTargetAddress, selector: fooSel }, { target: recordingTargetAddress, selector: barSel }],
      });
      expect(await policyRegistry.checkAuthorization(res.policyHash, selectorTargetAddress, 1, fooSel, 0n)).to.be.ok;
      expect(await policyRegistry.checkAuthorization(res.policyHash, selectorTargetAddress, 1, barSel, 0n)).to.be.ok;
    });

    it("modified calldata (same length, different argument bytes) never bypasses signature verification, across random payloads", async function () {
      const fooSel = selectorTarget.interface.getFunction("foo")!.selector;
      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("property-calldata")), {
        calls: [{ target: selectorTargetAddress, selector: fooSel }],
      });
      for (let i = 0; i < 5; i++) {
        const a = ethers.zeroPadValue(ethers.toBeHex(i + 1), 32);
        const b = ethers.zeroPadValue(ethers.toBeHex(i + 2), 32);
        const dataA = ethers.concat([fooSel, a]);
        const dataB = ethers.concat([fooSel, b]);
        const intent: Intent = { agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n, data: dataA, nonce: BigInt(i), deadline: FAR_DEADLINE, policyHash: res.policyHash };
        const sig = await signIntent(agent, intent);
        await expect(execute({ ...intent, data: dataB }, sig)).to.be.revertedWithCustomError(guard, "InvalidSignature");
      }
    });
  });
});
