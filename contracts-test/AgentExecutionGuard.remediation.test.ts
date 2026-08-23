import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * Remediation gate (pre-Gate-4): dedicated adversarial tests for the two
 * fixes required before Gate 4, run against the REAL AgentRegistry and
 * REAL PolicyRegistry (not the mocks used by
 * AgentExecutionGuard.test.ts), so both fixes are proven against actual
 * production contracts, not stand-ins.
 *
 * FIX 1 — msg.value binding: intent.value MUST equal msg.value exactly.
 * FIX 2 — policy ownership binding: a policyHash referenced by an intent
 * must belong to that same intent's agent.
 */
describe("Remediation gate: msg.value binding + policy ownership binding", function () {
  let agentRegistry: any;
  let agentRegistryAddress: string;
  let policyRegistry: any;
  let policyRegistryAddress: string;
  let guard: any;
  let guardAddress: string;
  let target: any;
  let targetAddress: string;

  let owner: HardhatEthersSigner;
  let walletA: HardhatEthersSigner;
  let walletB: HardhatEthersSigner;
  let agentA: ReturnType<typeof ethers.Wallet.createRandom>;
  let agentB: ReturnType<typeof ethers.Wallet.createRandom>;

  let policyIdA: string;
  let policyIdB: string;
  let policyHashA: string;
  let policyHashB: string;

  const FAR_DEADLINE = 4102444800n;
  const SELECTOR = "0x12345678";

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

  async function createPolicyFor(agentAddr: string, salt: string) {
    const tx = await policyRegistry
      .connect(owner)
      .createPolicy(
        salt,
        agentAddr,
        ethers.parseEther("10"),
        ethers.parseEther("100"),
        ethers.parseEther("50"),
        0n,
        FAR_DEADLINE,
        [targetAddress],
        [SELECTOR]
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

  async function signIntent(signerWallet: any, params: {
    agent: string; wallet: string; target: string; value: bigint; data: string;
    nonce: bigint; deadline: bigint; policyHash: string;
  }) {
    const d = await intentDomain();
    const calldataHash = ethers.keccak256(params.data);
    return signerWallet.signTypedData(d, intentTypes, {
      agent: params.agent,
      wallet: params.wallet,
      target: params.target,
      value: params.value,
      calldataHash,
      nonce: params.nonce,
      deadline: params.deadline,
      policyHash: params.policyHash,
    });
  }

  beforeEach(async function () {
    [owner, walletA, walletB] = await ethers.getSigners();
    agentA = ethers.Wallet.createRandom().connect(ethers.provider);
    agentB = ethers.Wallet.createRandom().connect(ethers.provider);

    const Registry = await ethers.getContractFactory("AgentRegistry");
    agentRegistry = await Registry.deploy();
    await agentRegistry.waitForDeployment();
    agentRegistryAddress = await agentRegistry.getAddress();
    await registerAgent(agentA, owner.address);
    await registerAgent(agentB, owner.address);

    const PolicyRegistry = await ethers.getContractFactory("PolicyRegistry");
    policyRegistry = await PolicyRegistry.deploy();
    await policyRegistry.waitForDeployment();
    policyRegistryAddress = await policyRegistry.getAddress();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    guard = await Guard.deploy(agentRegistryAddress, policyRegistryAddress);
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();

    const Target = await ethers.getContractFactory("RecordingTarget");
    target = await Target.deploy();
    await target.waitForDeployment();
    targetAddress = await target.getAddress();

    const resA = await createPolicyFor(agentA.address, ethers.keccak256(ethers.toUtf8Bytes("policy-A")));
    policyIdA = resA.policyId;
    policyHashA = resA.policyHash;
    const resB = await createPolicyFor(agentB.address, ethers.keccak256(ethers.toUtf8Bytes("policy-B")));
    policyIdB = resB.policyId;
    policyHashB = resB.policyHash;
  });

  describe("FIX 2 — policy ownership binding (real AgentRegistry + real PolicyRegistry)", function () {
    it("Agent A + Policy A => PASS", async function () {
      const params = {
        agent: agentA.address, wallet: walletA.address, target: targetAddress,
        value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: policyHashA,
      };
      const sig = await signIntent(agentA, params);
      await guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig);
      expect(await guard.nextNonce(agentA.address)).to.equal(1n);
    });

    it("Agent A + Policy B => REVERT", async function () {
      const params = {
        agent: agentA.address, wallet: walletA.address, target: targetAddress,
        value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: policyHashB,
      };
      // signed correctly by agentA (signature itself would be valid) —
      // the ONLY thing wrong is that policyHashB belongs to agentB.
      const sig = await signIntent(agentA, params);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig)
      ).to.be.revertedWithCustomError(guard, "PolicyAgentMismatch").withArgs(policyHashB, agentA.address, agentB.address);
      expect(await guard.nextNonce(agentA.address)).to.equal(0n);
    });

    it("Agent B + Policy A => REVERT", async function () {
      const params = {
        agent: agentB.address, wallet: walletB.address, target: targetAddress,
        value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: policyHashA,
      };
      const sig = await signIntent(agentB, params);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig)
      ).to.be.revertedWithCustomError(guard, "PolicyAgentMismatch").withArgs(policyHashA, agentB.address, agentA.address);
      expect(await guard.nextNonce(agentB.address)).to.equal(0n);
    });

    it("a revoked policy is rejected even when the agent binding is otherwise correct", async function () {
      await policyRegistry.connect(owner).revokePolicy(policyIdA);
      const params = {
        agent: agentA.address, wallet: walletA.address, target: targetAddress,
        value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: policyHashA,
      };
      const sig = await signIntent(agentA, params);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig)
      ).to.be.revertedWithCustomError(guard, "PolicyNotActive").withArgs(policyHashA);
    });

    it("an unregistered/unknown policyHash is rejected, not silently treated as 'no policy'", async function () {
      const fakeHash = ethers.keccak256(ethers.toUtf8Bytes("never-created"));
      const params = {
        agent: agentA.address, wallet: walletA.address, target: targetAddress,
        value: 0n, data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: fakeHash,
      };
      const sig = await signIntent(agentA, params);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig)
      ).to.be.revertedWithCustomError(guard, "PolicyAgentMismatch").withArgs(fakeHash, agentA.address, ethers.ZeroAddress);
    });
  });

  describe("FIX 1 — msg.value binding (four required scenarios)", function () {
    async function signedIntent(agentWallet: any, value: bigint, nonce: bigint, policyHash: string) {
      const params = {
        agent: agentWallet.address, wallet: walletA.address, target: targetAddress,
        value, data: "0x", nonce, deadline: FAR_DEADLINE, policyHash,
      };
      const sig = await signIntent(agentWallet, params);
      return { params, sig };
    }

    it("scenario 1: signed 0 ETH, send 1 ETH => REVERT", async function () {
      const { params, sig } = await signedIntent(agentA, 0n, 0n, policyHashA);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig, {
          value: ethers.parseEther("1"),
        })
      ).to.be.revertedWithCustomError(guard, "ValueMismatch").withArgs(ethers.parseEther("1"), 0n);
      expect(await guard.nextNonce(agentA.address)).to.equal(0n);
      // and the guard holds no stuck ETH — the whole tx reverted
      expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
    });

    it("scenario 2: signed 1 ETH, send 2 ETH => REVERT", async function () {
      const { params, sig } = await signedIntent(agentA, ethers.parseEther("1"), 0n, policyHashA);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig, {
          value: ethers.parseEther("2"),
        })
      ).to.be.revertedWithCustomError(guard, "ValueMismatch").withArgs(ethers.parseEther("2"), ethers.parseEther("1"));
      expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
    });

    it("scenario 3: signed a very large value, submitted with a modified (smaller) value field => signature invalid, not silently accepted at the mismatched amount", async function () {
      const hugeValue = ethers.parseEther("1000000");
      const { params, sig } = await signedIntent(agentA, hugeValue, 0n, policyHashA);
      // attacker rewrites the value field down to something they can
      // actually fund, and sends matching msg.value — passes the
      // value/msg.value check, but the signature no longer matches
      // (digest commits to the originally-signed hugeValue).
      const modifiedValue = ethers.parseEther("1");
      await expect(
        guard.execute(params.agent, params.wallet, params.target, modifiedValue, params.data, params.nonce, params.deadline, params.policyHash, sig, {
          value: modifiedValue,
        })
      ).to.be.revertedWithCustomError(guard, "InvalidSignature");
      expect(await guard.nextNonce(agentA.address)).to.equal(0n);
    });

    it("scenario 4: replay attempt with a modified value after the original nonce was already consumed => REVERT (stale nonce)", async function () {
      const { params, sig } = await signedIntent(agentA, ethers.parseEther("1"), 0n, policyHashA);
      await guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig, {
        value: ethers.parseEther("1"),
      });
      expect(await guard.nextNonce(agentA.address)).to.equal(1n);

      // attacker resubmits nonce 0 again with a different value, funding
      // it correctly this time (msg.value matches the modified value) —
      // still must fail, now on the nonce check rather than value/signature.
      const modifiedValue = ethers.parseEther("5");
      await expect(
        guard.execute(params.agent, params.wallet, params.target, modifiedValue, params.data, params.nonce, params.deadline, params.policyHash, sig, {
          value: modifiedValue,
        })
      ).to.be.revertedWithCustomError(guard, "InvalidNonce").withArgs(0n, 1n);
      expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
    });

    it("a value-matched call succeeds and forwards exactly what was sent, leaving zero balance behind", async function () {
      const { params, sig } = await signedIntent(agentA, ethers.parseEther("0.5"), 0n, policyHashA);
      const targetBalanceBefore = await ethers.provider.getBalance(targetAddress);
      await guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig, {
        value: ethers.parseEther("0.5"),
      });
      expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
      expect(await ethers.provider.getBalance(targetAddress)).to.equal(targetBalanceBefore + ethers.parseEther("0.5"));
    });
  });

  describe("both fixes combined", function () {
    it("a correctly value-matched intent still fails if it references the wrong agent's policy", async function () {
      const params = {
        agent: agentA.address, wallet: walletA.address, target: targetAddress,
        value: ethers.parseEther("1"), data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: policyHashB,
      };
      const sig = await signIntent(agentA, params);
      await expect(
        guard.execute(params.agent, params.wallet, params.target, params.value, params.data, params.nonce, params.deadline, params.policyHash, sig, {
          value: ethers.parseEther("1"),
        })
      ).to.be.revertedWithCustomError(guard, "PolicyAgentMismatch");
      expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
    });
  });
});
