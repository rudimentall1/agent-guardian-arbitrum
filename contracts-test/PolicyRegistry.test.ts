import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("PolicyRegistry", function () {
  let registry: any;
  let owner: HardhatEthersSigner;
  let otherOwner: HardhatEthersSigner;
  let targetA: string;
  let targetB: string;
  const SELECTOR_X = "0x12345678";
  const SELECTOR_Y = "0xabcdef01";

  // PolicyRegistry.CallKind enum order, mirrored on the TS side for
  // readability in test assertions.
  const CallKind = { NativeTransfer: 0, FunctionCall: 1, Malformed: 2 };

  let NOW: bigint;
  let VALID_FROM: bigint;
  let VALID_UNTIL: bigint;
  let defaultAgent: string;

  function defaultParams(overrides: Partial<any> = {}) {
    return {
      salt: ethers.keccak256(ethers.toUtf8Bytes("policy-1")),
      agent: defaultAgent,
      maxTxValue: ethers.parseEther("1"),
      dailyLimit: ethers.parseEther("5"),
      approvalThreshold: ethers.parseEther("2"),
      validFrom: VALID_FROM,
      validUntil: VALID_UNTIL,
      calls: [{ target: targetA, selector: SELECTOR_X }],
      nativeTransferTargets: [] as string[],
      ...overrides,
    };
  }

  async function create(signer: HardhatEthersSigner, overrides: Partial<any> = {}) {
    const p = defaultParams(overrides);
    const tx = await registry
      .connect(signer)
      .createPolicy(
        p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil,
        p.calls, p.nativeTransferTargets
      );
    await tx.wait();
    const policyId = await registry.computePolicyId(signer.address, p.salt);
    return { policyId, params: p };
  }

  beforeEach(async function () {
    [owner, otherOwner] = await ethers.getSigners();
    targetA = ethers.Wallet.createRandom().address;
    targetB = ethers.Wallet.createRandom().address;
    defaultAgent = ethers.Wallet.createRandom().address;

    const latest = await ethers.provider.getBlock("latest");
    NOW = BigInt(latest!.timestamp);
    VALID_FROM = NOW + 100n;
    VALID_UNTIL = NOW + 1_000_000n;

    const Registry = await ethers.getContractFactory("PolicyRegistry");
    registry = await Registry.deploy();
    await registry.waitForDeployment();
  });

  describe("happy path", function () {
    it("creates a policy and derives a deterministic policyId from (owner, salt)", async function () {
      const { policyId, params } = await create(owner);
      const expectedId = await registry.computePolicyId(owner.address, params.salt);
      expect(policyId).to.equal(expectedId);
      expect(await registry.ownerOf(policyId)).to.equal(owner.address);
      expect(await registry.isPolicyActive(policyId)).to.equal(true);
    });

    it("stores mandate fields exactly as provided", async function () {
      const { policyId, params } = await create(owner);
      const m = await registry.getMandate(policyId);
      expect(m.owner).to.equal(owner.address);
      expect(m.agent).to.equal(params.agent);
      expect(m.active).to.equal(true);
      expect(m.maxTxValue).to.equal(params.maxTxValue);
      expect(m.dailyLimit).to.equal(params.dailyLimit);
      expect(m.approvalThreshold).to.equal(params.approvalThreshold);
      expect(m.validFrom).to.equal(params.validFrom);
      expect(m.validUntil).to.equal(params.validUntil);
    });

    it("emits PolicyCreated, CallAuthorized, and NativeTransferAuthorized", async function () {
      const p = defaultParams({ nativeTransferTargets: [targetB] });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      )
        .to.emit(registry, "PolicyCreated")
        .and.to.emit(registry, "CallAuthorized")
        .withArgs(await registry.computePolicyId(owner.address, p.salt), targetA, SELECTOR_X)
        .and.to.emit(registry, "NativeTransferAuthorized")
        .withArgs(await registry.computePolicyId(owner.address, p.salt), targetB);
    });

    it("two different owners can use the identical salt without colliding", async function () {
      const p = defaultParams();
      await registry.connect(owner).createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets);
      await registry.connect(otherOwner).createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets);

      const idOwner = await registry.computePolicyId(owner.address, p.salt);
      const idOther = await registry.computePolicyId(otherOwner.address, p.salt);
      expect(idOwner).to.not.equal(idOther);
      expect(await registry.ownerOf(idOwner)).to.equal(owner.address);
      expect(await registry.ownerOf(idOther)).to.equal(otherOwner.address);
    });

    it("resolvePolicyBinding resolves the correct agent and active state via policyHash", async function () {
      const { policyId, params } = await create(owner);
      const hash = await registry.policyHashOf(policyId);
      const [agent, active] = await registry.resolvePolicyBinding(hash);
      expect(agent).to.equal(params.agent);
      expect(active).to.equal(true);
      expect(await registry.agentOf(policyId)).to.equal(params.agent);
    });

    it("resolvePolicyBinding returns (zero address, false) for an unknown policyHash", async function () {
      const fakeHash = ethers.keccak256(ethers.toUtf8Bytes("never-created"));
      const [agent, active] = await registry.resolvePolicyBinding(fakeHash);
      expect(agent).to.equal(ethers.ZeroAddress);
      expect(active).to.equal(false);
    });

    it("resolvePolicyBinding reflects revocation live", async function () {
      const { policyId } = await create(owner);
      const hash = await registry.policyHashOf(policyId);
      await registry.connect(owner).revokePolicy(policyId);
      const [, active] = await registry.resolvePolicyBinding(hash);
      expect(active).to.equal(false);
    });
  });

  describe("Cartesian-product regression (Part 10 — mandatory)", function () {
    it("target A + selector X => authorized; target B + selector Y => authorized; A+Y and B+X => NOT authorized", async function () {
      const { policyId } = await create(owner, {
        calls: [
          { target: targetA, selector: SELECTOR_X },
          { target: targetB, selector: SELECTOR_Y },
        ],
      });

      expect(await registry.isCallAuthorized(policyId, targetA, SELECTOR_X)).to.equal(true);
      expect(await registry.isCallAuthorized(policyId, targetB, SELECTOR_Y)).to.equal(true);
      // the old Cartesian-product bug would have authorized these two:
      expect(await registry.isCallAuthorized(policyId, targetA, SELECTOR_Y)).to.equal(false);
      expect(await registry.isCallAuthorized(policyId, targetB, SELECTOR_X)).to.equal(false);
    });

    it("checkAuthorization confirms the same pairing end-to-end (the exact surface AgentExecutionGuard consults)", async function () {
      const { policyId, params } = await create(owner, {
        calls: [
          { target: targetA, selector: SELECTOR_X },
          { target: targetB, selector: SELECTOR_Y },
        ],
      });
      const policyHash = await registry.policyHashOf(policyId);
      await ethers.provider.send("evm_increaseTime", [200]);
      await ethers.provider.send("evm_mine", []);

      const AX = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_X, 0n);
      const BY = await registry.checkAuthorization(policyHash, targetB, CallKind.FunctionCall, SELECTOR_Y, 0n);
      const AY = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_Y, 0n);
      const BX = await registry.checkAuthorization(policyHash, targetB, CallKind.FunctionCall, SELECTOR_X, 0n);

      expect(AX.callAllowed).to.equal(true);
      expect(BY.callAllowed).to.equal(true);
      expect(AY.callAllowed).to.equal(false);
      expect(BX.callAllowed).to.equal(false);
    });
  });

  describe("native transfer vs function-call separation", function () {
    it("authorizing a native transfer for a target does NOT authorize any function call on it", async function () {
      const { policyId } = await create(owner, { calls: [], nativeTransferTargets: [targetA] });
      expect(await registry.isNativeTransferAuthorized(policyId, targetA)).to.equal(true);
      expect(await registry.isCallAuthorized(policyId, targetA, SELECTOR_X)).to.equal(false);
      expect(await registry.isCallAuthorized(policyId, targetA, "0x00000000")).to.equal(false);
    });

    it("authorizing selector 0x00000000 for a target does NOT authorize a native transfer to it", async function () {
      const { policyId } = await create(owner, { calls: [{ target: targetA, selector: "0x00000000" }], nativeTransferTargets: [] });
      expect(await registry.isCallAuthorized(policyId, targetA, "0x00000000")).to.equal(true);
      expect(await registry.isNativeTransferAuthorized(policyId, targetA)).to.equal(false);
    });

    it("checkAuthorization: CallKind.Malformed is never authorized regardless of any stored entry", async function () {
      const { policyId, params } = await create(owner, {
        calls: [{ target: targetA, selector: "0x00000000" }],
        nativeTransferTargets: [targetA],
      });
      const policyHash = await registry.policyHashOf(policyId);
      await ethers.provider.send("evm_increaseTime", [200]);
      await ethers.provider.send("evm_mine", []);
      // target A has BOTH a native-transfer AND a 0x00000000 function-call
      // authorization — Malformed must still be rejected, proving the
      // check is structural (no lookup performed) and not merely "this
      // particular mapping happens to be empty".
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.Malformed, "0x00000000", 0n);
      expect(res.callAllowed).to.equal(false);
    });
  });

  describe("adversarial: identifier collision / squatting", function () {
    it("a different caller using the same salt cannot overwrite or claim the original owner's policy", async function () {
      const { policyId } = await create(owner);
      const p = defaultParams();
      await registry.connect(otherOwner).createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets);
      expect(await registry.ownerOf(policyId)).to.equal(owner.address);
    });

    it("reverts on exact re-creation attempt with the same (owner, salt)", async function () {
      const p = defaultParams();
      await registry.connect(owner).createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets);
      await expect(
        registry.connect(owner).createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.be.revertedWithCustomError(registry, "PolicyAlreadyExists");
    });
  });

  describe("adversarial: immutability of mandate values and authorizations", function () {
    it("revoke + reactivate never changes stored mandate values, policyHash, or authorized calls", async function () {
      const { policyId } = await create(owner);
      const hashBefore = await registry.policyHashOf(policyId);
      const mandateBefore = await registry.getMandate(policyId);

      await registry.connect(owner).revokePolicy(policyId);
      await registry.connect(owner).reactivatePolicy(policyId);

      const hashAfter = await registry.policyHashOf(policyId);
      const mandateAfter = await registry.getMandate(policyId);

      expect(hashAfter).to.equal(hashBefore);
      expect(mandateAfter.maxTxValue).to.equal(mandateBefore.maxTxValue);
      expect(await registry.isCallAuthorized(policyId, targetA, SELECTOR_X)).to.equal(true);
    });

    it("there is no update function to widen an existing policy's authorized calls", async function () {
      expect(registry.interface.getFunction("updatePolicy" as any)).to.equal(null);
    });
  });

  describe("adversarial: access control on lifecycle", function () {
    it("non-owner cannot revoke", async function () {
      const { policyId } = await create(owner);
      await expect(registry.connect(otherOwner).revokePolicy(policyId))
        .to.be.revertedWithCustomError(registry, "NotPolicyOwner")
        .withArgs(policyId, otherOwner.address);
    });

    it("non-owner cannot reactivate", async function () {
      const { policyId } = await create(owner);
      await registry.connect(owner).revokePolicy(policyId);
      await expect(registry.connect(otherOwner).reactivatePolicy(policyId))
        .to.be.revertedWithCustomError(registry, "NotPolicyOwner")
        .withArgs(policyId, otherOwner.address);
    });

    it("cannot revoke an already-revoked policy", async function () {
      const { policyId } = await create(owner);
      await registry.connect(owner).revokePolicy(policyId);
      await expect(registry.connect(owner).revokePolicy(policyId)).to.be.revertedWithCustomError(registry, "PolicyAlreadyInactive");
    });

    it("cannot reactivate an already-active policy", async function () {
      const { policyId } = await create(owner);
      await expect(registry.connect(owner).reactivatePolicy(policyId)).to.be.revertedWithCustomError(registry, "PolicyAlreadyActive");
    });

    it("cannot operate on a nonexistent policy", async function () {
      const fakeId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(registry.connect(owner).revokePolicy(fakeId)).to.be.revertedWithCustomError(registry, "PolicyNotFound");
    });
  });

  describe("validation at creation", function () {
    it("rejects validUntil <= validFrom", async function () {
      const p = defaultParams({ validFrom: 100n, validUntil: 100n });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.be.revertedWithCustomError(registry, "InvalidTimeWindow");
    });

    it("rejects a policy authorizing nothing at all (empty calls AND empty nativeTransferTargets)", async function () {
      const p = defaultParams({ calls: [], nativeTransferTargets: [] });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.be.revertedWithCustomError(registry, "EmptyAuthorization");
    });

    it("accepts a policy authorizing only native transfers (no function calls)", async function () {
      const p = defaultParams({ calls: [], nativeTransferTargets: [targetA] });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.not.be.reverted;
    });

    it("rejects a zero address target inside calls", async function () {
      const p = defaultParams({ calls: [{ target: ethers.ZeroAddress, selector: SELECTOR_X }] });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    });

    it("rejects a zero address inside nativeTransferTargets", async function () {
      const p = defaultParams({ calls: [], nativeTransferTargets: [ethers.ZeroAddress] });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    });

    it("rejects a zero agent address", async function () {
      const p = defaultParams({ agent: ethers.ZeroAddress });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    });

    it("duplicate entries in calls are harmless no-ops, not rejected", async function () {
      const p = defaultParams({ calls: [{ target: targetA, selector: SELECTOR_X }, { target: targetA, selector: SELECTOR_X }] });
      await expect(
        registry.createPolicy(p.salt, p.agent, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.calls, p.nativeTransferTargets)
      ).to.not.be.reverted;
    });
  });

  describe("checkAuthorization — full combined check", function () {
    let policyId: string;
    let policyHash: string;

    beforeEach(async function () {
      const res = await create(owner, {
        calls: [{ target: targetA, selector: SELECTOR_X }],
        maxTxValue: ethers.parseEther("1"),
      });
      policyId = res.policyId;
      policyHash = await registry.policyHashOf(policyId);
      await ethers.provider.send("evm_increaseTime", [200]);
      await ethers.provider.send("evm_mine", []);
    });

    it("allows a call within target, selector, and value bounds", async function () {
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_X, ethers.parseEther("0.5"));
      expect(res.callAllowed).to.equal(true);
      expect(res.valueAllowed).to.equal(true);
      expect(res.active).to.equal(true);
      expect(res.withinWindow).to.equal(true);
    });

    it("rejects a disallowed target", async function () {
      const res = await registry.checkAuthorization(policyHash, targetB, CallKind.FunctionCall, SELECTOR_X, 0n);
      expect(res.callAllowed).to.equal(false);
    });

    it("rejects a disallowed selector", async function () {
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_Y, 0n);
      expect(res.callAllowed).to.equal(false);
    });

    it("rejects a value exceeding maxTxValue", async function () {
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_X, ethers.parseEther("1.01"));
      expect(res.valueAllowed).to.equal(false);
    });

    it("allows a value exactly at maxTxValue", async function () {
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_X, ethers.parseEther("1"));
      expect(res.valueAllowed).to.equal(true);
    });

    it("rejects a revoked policy even if all other conditions are satisfied", async function () {
      await registry.connect(owner).revokePolicy(policyId);
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_X, ethers.parseEther("0.5"));
      expect(res.active).to.equal(false);
    });

    it("rejects before validFrom", async function () {
      const res = await create(owner, {
        salt: ethers.keccak256(ethers.toUtf8Bytes("future-policy")),
        validFrom: VALID_UNTIL - 10n,
        validUntil: VALID_UNTIL + 1_000_000n,
      });
      const futureHash = await registry.policyHashOf(res.policyId);
      const check = await registry.checkAuthorization(futureHash, targetA, CallKind.FunctionCall, SELECTOR_X, 0n);
      expect(check.withinWindow).to.equal(false);
    });

    it("rejects after validUntil", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(VALID_UNTIL - VALID_FROM) + 10]);
      await ethers.provider.send("evm_mine", []);
      const res = await registry.checkAuthorization(policyHash, targetA, CallKind.FunctionCall, SELECTOR_X, 0n);
      expect(res.withinWindow).to.equal(false);
    });

    it("returns zero-value defaults for a nonexistent policy rather than reverting", async function () {
      const fakeHash = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      const res = await registry.checkAuthorization(fakeHash, targetA, CallKind.FunctionCall, SELECTOR_X, 0n);
      expect(res.agent).to.equal(ethers.ZeroAddress);
      expect(res.active).to.equal(false);
      expect(res.callAllowed).to.equal(false);
    });
  });
});
