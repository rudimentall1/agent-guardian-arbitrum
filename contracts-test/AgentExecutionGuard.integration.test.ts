import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * Integration between the real Gate 1 AgentRegistry and Gate 2
 * AgentExecutionGuard — exercises the actual registration flow, not the
 * MockAgentRegistry used by AgentExecutionGuard.test.ts, and specifically
 * the ownership-transfer lifecycle edge case the Gate 2 brief calls out.
 */
describe("AgentExecutionGuard + AgentRegistry integration", function () {
  let registry: any;
  let registryAddress: string;
  let guard: any;
  let guardAddress: string;
  let policyRegistry: any;
  let policyRegistryAddress: string;
  let target: any;
  let targetAddress: string;
  let owner: HardhatEthersSigner;
  let newOwner: HardhatEthersSigner;
  let wallet: HardhatEthersSigner;
  let agent: ReturnType<typeof ethers.Wallet.createRandom>;

  const METADATA_HASH = ethers.keccak256(ethers.toUtf8Bytes("agent-v1-config"));
  const ZERO_HASH = ethers.ZeroHash;
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

  async function registrationDomain() {
    const net = await ethers.provider.getNetwork();
    return { name: "AgentRegistry", version: "1", chainId: net.chainId, verifyingContract: registryAddress };
  }

  async function intentDomain() {
    const net = await ethers.provider.getNetwork();
    return { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress };
  }

  async function signIntent(nonce: bigint, deadline = FAR_DEADLINE) {
    const d = await intentDomain();
    const calldataHash = ethers.keccak256("0x");
    return agent.signTypedData(d, intentTypes, {
      agent: agent.address,
      wallet: wallet.address,
      target: targetAddress,
      value: 0n,
      calldataHash,
      nonce,
      deadline,
      policyHash: ZERO_HASH,
    });
  }

  async function execute(nonce: bigint, deadline = FAR_DEADLINE) {
    const sig = await signIntent(nonce, deadline);
    return guard.execute(agent.address, wallet.address, targetAddress, 0n, "0x", nonce, deadline, ZERO_HASH, sig);
  }

  beforeEach(async function () {
    [owner, newOwner, wallet] = await ethers.getSigners();
    agent = ethers.Wallet.createRandom().connect(ethers.provider);

    const Registry = await ethers.getContractFactory("AgentRegistry");
    registry = await Registry.deploy();
    await registry.waitForDeployment();
    registryAddress = await registry.getAddress();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    const MockPolicyRegistry = await ethers.getContractFactory("MockPolicyRegistry");
    policyRegistry = await MockPolicyRegistry.deploy();
    await policyRegistry.waitForDeployment();
    policyRegistryAddress = await policyRegistry.getAddress();
    await policyRegistry.setBinding(ZERO_HASH, agent.address, true);
    guard = await Guard.deploy(registryAddress, policyRegistryAddress);
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();

    const Target = await ethers.getContractFactory("RecordingTarget");
    target = await Target.deploy();
    await target.waitForDeployment();
    targetAddress = await target.getAddress();

    const rd = await registrationDomain();
    const regSig = await agent.signTypedData(rd, registrationTypes, {
      agent: agent.address,
      owner: owner.address,
      metadataHash: METADATA_HASH,
    });
    await registry.register(agent.address, owner.address, METADATA_HASH, regSig);
  });

  it("executes through the guard once genuinely registered and active", async function () {
    await execute(0n);
    expect(await guard.nextNonce(agent.address)).to.equal(1n);
  });

  it("rejects execution for an agent that was never registered", async function () {
    const strangerAgent = ethers.Wallet.createRandom().connect(ethers.provider);
    const d = await intentDomain();
    const sig = await strangerAgent.signTypedData(d, intentTypes, {
      agent: strangerAgent.address,
      wallet: wallet.address,
      target: targetAddress,
      value: 0n,
      calldataHash: ethers.keccak256("0x"),
      nonce: 0n,
      deadline: FAR_DEADLINE,
      policyHash: ZERO_HASH,
    });
    await expect(
      guard.execute(strangerAgent.address, wallet.address, targetAddress, 0n, "0x", 0n, FAR_DEADLINE, ZERO_HASH, sig)
    ).to.be.revertedWithCustomError(guard, "AgentNotActive");
  });

  it("rejects execution once the owner deactivates the agent via the real registry", async function () {
    await registry.connect(owner).deactivate(agent.address);
    await expect(execute(0n)).to.be.revertedWithCustomError(guard, "AgentNotActive");
  });

  describe("ownership transfer lifecycle edge case", function () {
    it("a signed-but-not-yet-submitted intent becomes unusable the instant ownership transfers, with no guard-side revocation needed", async function () {
      // agent's operator prepares a signature for nonce 0 but hasn't
      // submitted it yet
      const sig = await signIntent(0n);

      // original owner transfers the agent away (Gate 1 forces inactive
      // on transfer)
      await registry.connect(owner).transferAgentOwnership(agent.address, newOwner.address);

      // the previously-valid signature is now rejected purely because
      // AgentRegistry.isActiveAgent is checked live at execution time —
      // AgentExecutionGuard needed no explicit revocation logic of its own.
      await expect(
        guard.execute(agent.address, wallet.address, targetAddress, 0n, "0x", 0n, FAR_DEADLINE, ZERO_HASH, sig)
      ).to.be.revertedWithCustomError(guard, "AgentNotActive");
    });

    it("the SAME signature becomes valid again once the new owner reactivates — the agent key itself never changed", async function () {
      const sig = await signIntent(0n);
      await registry.connect(owner).transferAgentOwnership(agent.address, newOwner.address);
      await registry.connect(newOwner).reactivate(agent.address);

      // documented, not silently assumed: reactivation does not require
      // (and Gate 1 has no mechanism for) rotating the agent's signing
      // key, so the original operator's signature is honored again under
      // the NEW owner's authority. This is an explicit trust boundary:
      // transferring ownership without also rotating the agent key means
      // whoever held that key before the transfer can still author valid
      // intents after it, as long as the new owner reactivates without
      // re-registering under a fresh key.
      await guard.execute(agent.address, wallet.address, targetAddress, 0n, "0x", 0n, FAR_DEADLINE, ZERO_HASH, sig);
      expect(await guard.nextNonce(agent.address)).to.equal(1n);
    });

    it("nonce state is not reset by ownership transfer or reactivation", async function () {
      await execute(0n);
      await execute(1n);
      expect(await guard.nextNonce(agent.address)).to.equal(2n);

      await registry.connect(owner).transferAgentOwnership(agent.address, newOwner.address);
      await registry.connect(newOwner).reactivate(agent.address);

      // nonce continues from 2, not reset to 0
      await expect(execute(0n)).to.be.revertedWithCustomError(guard, "InvalidNonce").withArgs(0n, 2n);
      await execute(2n);
      expect(await guard.nextNonce(agent.address)).to.equal(3n);
    });
  });
});
