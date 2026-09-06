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
      ethers.parseEther("100"),
      ethers.parseEther("50"),
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

      // A + X: PASS
      let intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      let sig = await signIntent(agent, intent);
      await execute(intent, sig);

      // B + Y: PASS
      intent = {
        agent: agent.address, wallet: wallet.address, target: otherTargetAddress, value: 0n,
        data: barCalldata(wallet.address), nonce: 1n, deadline: FAR_DEADLINE, policyHash,
      };
      sig = await signIntent(agent, intent);
      await execute(intent, sig);

      // A + Y (foo's target, bar's selector): REVERT — old bug would allow this
      intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: barCalldata(wallet.address), nonce: 2n, deadline: FAR_DEADLINE, policyHash,
      };
      sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "CallNotAuthorized").withArgs(selectorTargetAddress, barSel, false);

      // B + X (bar's target, foo's selector): REVERT
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
      // fails the authorization check (recordingTarget+fooSel not
      // authorized) before signature is even reached — still a REVERT,
      // just via a different, equally-valid check.
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
      const tampered = { ...intent, data: fooCalldata(2) }; // same selector, different argument
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
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "MaxTxValueExceeded").withArgs(value, policyHash);
    });

    // --- Post-hostile-review addition: uint128/uint256 boundary regression ---
    //
    // These two tests require msg.value at the scale of type(uint128).max /
    // type(uint256).max wei — many orders of magnitude beyond what any
    // hardhat default account holds (~10000 ETH). Real fund transfer at
    // this scale is not physically representable by any account, so both
    // tests fund a dedicated, single-use throwaway signer via
    // `hardhat_setBalance` rather than any of the shared signers used
    // elsewhere in this suite. `hardhat_setBalance` mutates network state
    // that persists for the rest of the whole mocha process (Hardhat's
    // in-process network is not reset between test files) — using a
    // fresh, one-off address here, instead of e.g. `owner`, guarantees
    // this doesn't leave any other test in this suite with an
    // unexpectedly-altered balance.
    describe("uint128/uint256 boundary regression (post-hostile-review)", function () {
      const MAX_UINT128 = (1n << 128n) - 1n;
      const MAX_UINT256 = ethers.MaxUint256;

      async function fundThrowawaySender(amount: bigint) {
        const sender = ethers.Wallet.createRandom().connect(ethers.provider);
        await ethers.provider.send("hardhat_setBalance", [
          sender.address,
          "0x" + amount.toString(16),
        ]);
        return sender;
      }

      it("value = type(uint256).max, maxTxValue = type(uint128).max => REVERT (MaxTxValueExceeded)", async function () {
        // A literal msg.value of exactly type(uint256).max cannot be
        // dispatched as a real transaction on any EVM node, including
        // hardhat's — the node internally computes value + (gas price *
        // gas limit) to check the sender can cover the transaction, and
        // that addition itself overflows uint256 when value is already
        // at its ceiling ("overflow payment in transaction"). This is a
        // node/EVM-level constraint, not a PolicyRegistry/
        // AgentExecutionGuard one. We use type(uint256).max minus a
        // small gas headroom instead — still astronomically larger than
        // any real maxTxValue and well outside uint128 range, so it
        // exercises the exact same uint256-vs-uint128 comparison at
        // essentially the same boundary without hitting an unrelated
        // transaction-dispatch limit.
        const value = MAX_UINT256 - ethers.parseEther("10");

        const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("boundary-max128-vs-max256")), {
          maxTxValue: MAX_UINT128,
          nativeTransferTargets: [recordingTargetAddress],
        });

        const sender = await fundThrowawaySender(MAX_UINT256);

        const intent: Intent = {
          agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value,
          data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
        };
        const sig = await signIntent(agent, intent);
        await expect(
          guard.connect(sender).execute(
            intent.agent, intent.wallet, intent.target, intent.value, intent.data,
            intent.nonce, intent.deadline, intent.policyHash, sig,
            { value: intent.value }
          )
        )
          .to.be.revertedWithCustomError(guard, "MaxTxValueExceeded")
          .withArgs(value, res.policyHash);
      });

      it("value = type(uint128).max, maxTxValue = type(uint128).max (exact boundary) => PASS", async function () {
        const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("boundary-max128-exact")), {
          maxTxValue: MAX_UINT128,
          nativeTransferTargets: [recordingTargetAddress],
        });

        // fund with a little headroom over the value itself, for gas
        const sender = await fundThrowawaySender(MAX_UINT128 + ethers.parseEther("1"));

        const intent: Intent = {
          agent: agent.address, wallet: wallet.address, target: recordingTargetAddress, value: MAX_UINT128,
          data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
        };
        const sig = await signIntent(agent, intent);
        await guard.connect(sender).execute(
          intent.agent, intent.wallet, intent.target, intent.value, intent.data,
          intent.nonce, intent.deadline, intent.policyHash, sig,
          { value: intent.value }
        );

        expect(await guard.nextNonce(agent.address)).to.equal(1n);
        expect(await ethers.provider.getBalance(recordingTargetAddress)).to.equal(MAX_UINT128);
        expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
      });
    });

    it("16. msg.value > signed value => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: ethers.parseEther("0.5"),
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(
        guard.execute(intent.agent, intent.wallet, intent.target, intent.value, intent.data, intent.nonce, intent.deadline, intent.policyHash, sig, {
          value: ethers.parseEther("2"),
        })
      ).to.be.revertedWithCustomError(guard, "ValueMismatch");
    });

    it("17. signed value > maxTxValue (declared and sent, still capped by policy) => REVERT", async function () {
      const value = ethers.parseEther("2");
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
      const intent: Intent = {
        agent: otherAgent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash, // policy is bound to `agent`, not `otherAgent`
      };
      const sig = await signIntent(otherAgent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "PolicyAgentMismatch");
    });

    it("19. revoked policy => REVERT", async function () {
      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("revocable")), {
        calls: [{ target: selectorTargetAddress, selector: fooSel }],
      });
      await policyRegistry.connect(owner).revokePolicy(res.policyId);
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "PolicyNotActive");
    });

    it("20. disabled agent => REVERT", async function () {
      await agentRegistry.connect(owner).deactivate(agent.address);
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "AgentNotActive");
    });

    it("21. stale nonce => REVERT", async function () {
      const intent0: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      await execute(intent0, await signIntent(agent, intent0));
      await expect(execute(intent0, await signIntent(agent, intent0))).to.be.revertedWithCustomError(guard, "InvalidNonce");
    });

    it("22. future nonce => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 5n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "InvalidNonce");
    });

    it("23. replay exact intent => REVERT", async function () {
      const intent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agent, intent);
      await execute(intent, sig);
      await expect(execute(intent, sig)).to.be.revertedWithCustomError(guard, "InvalidNonce");
    });

    it("24. reentrancy attempt => safely contained (blocked, nonce still advances exactly once)", async function () {
      const Attacker = await ethers.getContractFactory("ReentrantAttacker");
      const attacker = await Attacker.deploy();
      await attacker.waitForDeployment();
      const attackerAddress = await attacker.getAddress();
      await attacker.setGuard(guardAddress);

      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("reentrancy")), {
        nativeTransferTargets: [attackerAddress],
      });

      const reentryIntent: Intent = {
        agent: agent.address, wallet: wallet.address, target: attackerAddress, value: 0n,
        data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
      };
      const reentrySig = await signIntent(agent, reentryIntent);
      const reentryCalldata = guard.interface.encodeFunctionData("execute", [
        reentryIntent.agent, reentryIntent.wallet, reentryIntent.target, reentryIntent.value,
        reentryIntent.data, reentryIntent.nonce, reentryIntent.deadline, reentryIntent.policyHash, reentrySig,
      ]);
      await attacker.setReentryCalldata(reentryCalldata);

      const outerIntent: Intent = {
        agent: agent.address, wallet: wallet.address, target: attackerAddress, value: 0n,
        data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
      };
      const outerSig = await signIntent(agent, outerIntent);
      await execute(outerIntent, outerSig);

      expect(await attacker.reentered()).to.equal(true);
      expect(await attacker.reentrySucceeded()).to.equal(false);
      expect(await guard.nextNonce(agent.address)).to.equal(1n);
    });

    it("25. malicious target cannot bypass authorization by re-entering with a different (unauthorized) call", async function () {
      const Attacker = await ethers.getContractFactory("ReentrantAttacker");
      const attacker = await Attacker.deploy();
      await attacker.waitForDeployment();
      const attackerAddress = await attacker.getAddress();
      await attacker.setGuard(guardAddress);

      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("malicious-target")), {
        nativeTransferTargets: [attackerAddress],
        // deliberately NOT authorizing selectorTargetAddress/fooSel under this policy
      });

      // attacker tries to use the reentrant callback to invoke an
      // UNAUTHORIZED call (selectorTarget.foo) using a validly-signed
      // intent for a DIFFERENT, still-unauthorized target+selector pair.
      const bypassIntent: Intent = {
        agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
        data: fooCalldata(1), nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
      };
      const bypassSig = await signIntent(agent, bypassIntent);
      const bypassCalldata = guard.interface.encodeFunctionData("execute", [
        bypassIntent.agent, bypassIntent.wallet, bypassIntent.target, bypassIntent.value,
        bypassIntent.data, bypassIntent.nonce, bypassIntent.deadline, bypassIntent.policyHash, bypassSig,
      ]);
      await attacker.setReentryCalldata(bypassCalldata);

      const outerIntent: Intent = {
        agent: agent.address, wallet: wallet.address, target: attackerAddress, value: 0n,
        data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
      };
      const outerSig = await signIntent(agent, outerIntent);
      await execute(outerIntent, outerSig);

      // blocked by nonReentrant regardless of what the nested call would
      // have been authorized to do — the bypass never even reaches the
      // CallNotAuthorized check, proving reentrancy protection is the
      // first line of defense, not a fallback behind authorization.
      expect(await attacker.reentered()).to.equal(true);
      expect(await attacker.reentrySucceeded()).to.equal(false);
      expect(await selectorTarget.fooCallCount()).to.equal(0n);
    });
  });

  // ---------------------------------------------------------------
  // Part 11: seeded property tests
  // ---------------------------------------------------------------
  describe("property tests: authorization independence", function () {
    function mulberry32(seed: number) {
      let a = seed;
      return function () {
        a |= 0;
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    }

    it("authorized(target, selector) != authorized(otherTarget, selector) across randomized (target, selector) pairs", async function () {
      const rand = mulberry32(0xba5eba11);
      const SelectorTarget = await ethers.getContractFactory("SelectorTarget");
      const targets: string[] = [];
      for (let i = 0; i < 4; i++) {
        const t = await SelectorTarget.deploy();
        await t.waitForDeployment();
        targets.push(await t.getAddress());
      }
      const selectors = ["0x11111111", "0x22222222", "0x33333333", "0x44444444"];

      // authorize exactly one (target, selector) pairing per target,
      // rotating through selectors — deliberately NOT the full grid.
      const calls = targets.map((t, i) => ({ target: t, selector: selectors[i] }));
      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("property-grid")), { calls });

      for (let i = 0; i < 30; i++) {
        const ti = Math.floor(rand() * targets.length);
        const si = Math.floor(rand() * selectors.length);
        const expectedAllowed = si === ti; // only the diagonal was authorized
        const authorized = await policyRegistry.isCallAuthorized(res.policyId, targets[ti], selectors[si]);
        expect(authorized, `target[${ti}] x selector[${si}]`).to.equal(expectedAllowed);
      }
    });

    it("modified calldata (same length, different argument bytes) never bypasses signature verification, across random payloads", async function () {
      const rand = mulberry32(0xf00dbabe);
      const res = await createPolicy(agent.address, ethers.keccak256(ethers.toUtf8Bytes("property-tamper")), {
        calls: [{ target: selectorTargetAddress, selector: selectorTarget.interface.getFunction("foo")!.selector }],
      });

      for (let i = 0; i < 10; i++) {
        const original = Math.floor(rand() * 1_000_000);
        let tampered = Math.floor(rand() * 1_000_000);
        if (tampered === original) tampered += 1;

        const intent: Intent = {
          agent: agent.address, wallet: wallet.address, target: selectorTargetAddress, value: 0n,
          data: fooCalldata(original), nonce: 0n, deadline: FAR_DEADLINE, policyHash: res.policyHash,
        };
        const sig = await signIntent(agent, intent);
        const tamperedIntent = { ...intent, data: fooCalldata(tampered) };
        await expect(execute(tamperedIntent, sig)).to.be.revertedWithCustomError(guard, "InvalidSignature");
      }
    });
  });
});
