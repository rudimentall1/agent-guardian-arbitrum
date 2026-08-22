import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("PolicyRegistry", function () {
  let registry: any;
  let owner: HardhatEthersSigner;
  let otherOwner: HardhatEthersSigner;
  let targetA: string;
  let targetB: string;
  const SELECTOR_A = "0x12345678";
  const SELECTOR_B = "0xabcdef01";

  let NOW: bigint;
  let VALID_FROM: bigint;
  let VALID_UNTIL: bigint;

  function defaultParams(overrides: Partial<any> = {}) {
    return {
      salt: ethers.keccak256(ethers.toUtf8Bytes("policy-1")),
      maxTxValue: ethers.parseEther("1"),
      dailyLimit: ethers.parseEther("5"),
      approvalThreshold: ethers.parseEther("2"),
      validFrom: VALID_FROM,
      validUntil: VALID_UNTIL,
      allowedTargets: [targetA],
      allowedSelectors: [SELECTOR_A],
      ...overrides,
    };
  }

  async function create(signer: HardhatEthersSigner, overrides: Partial<any> = {}) {
    const p = defaultParams(overrides);
    const tx = await registry
      .connect(signer)
      .createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors);
    const receipt = await tx.wait();
    const policyId = await registry.computePolicyId(signer.address, p.salt);
    return { policyId, receipt, params: p };
  }

  beforeEach(async function () {
    [owner, otherOwner] = await ethers.getSigners();
    targetA = ethers.Wallet.createRandom().address;
    targetB = ethers.Wallet.createRandom().address;

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
      expect(m.active).to.equal(true);
      expect(m.maxTxValue).to.equal(params.maxTxValue);
      expect(m.dailyLimit).to.equal(params.dailyLimit);
      expect(m.approvalThreshold).to.equal(params.approvalThreshold);
      expect(m.validFrom).to.equal(params.validFrom);
      expect(m.validUntil).to.equal(params.validUntil);
    });

    it("emits PolicyCreated with a non-zero policyHash", async function () {
      const p = defaultParams();
      await expect(
        registry.createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors)
      ).to.emit(registry, "PolicyCreated");
      const policyId = await registry.computePolicyId(owner.address, p.salt);
      const hash = await registry.policyHashOf(policyId);
      expect(hash).to.not.equal(ethers.ZeroHash);
    });

    it("two different owners can use the identical salt without colliding", async function () {
      const p = defaultParams();
      await registry.connect(owner).createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors);
      await registry.connect(otherOwner).createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors);

      const idOwner = await registry.computePolicyId(owner.address, p.salt);
      const idOther = await registry.computePolicyId(otherOwner.address, p.salt);
      expect(idOwner).to.not.equal(idOther);
      expect(await registry.ownerOf(idOwner)).to.equal(owner.address);
      expect(await registry.ownerOf(idOther)).to.equal(otherOwner.address);
    });
  });

  describe("adversarial: identifier collision / squatting", function () {
    it("a different caller using the same salt cannot overwrite or claim the original owner's policy", async function () {
      const { policyId } = await create(owner);
      // otherOwner tries to "claim" the same conceptual policyId by using
      // the same salt — but their own derived policyId is different, so
      // there is nothing to collide with. Confirm the original is untouched.
      const p = defaultParams();
      await registry.connect(otherOwner).createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors);
      expect(await registry.ownerOf(policyId)).to.equal(owner.address);
    });

    it("reverts on exact re-creation attempt with the same (owner, salt)", async function () {
      const p = defaultParams();
      await registry.connect(owner).createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors);
      await expect(
        registry.connect(owner).createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors)
      ).to.be.revertedWithCustomError(registry, "PolicyAlreadyExists");
    });
  });

  describe("adversarial: immutability of mandate values", function () {
    it("there is no update function — revoke + reactivate never change stored mandate values or policyHash", async function () {
      const { policyId } = await create(owner);
      const hashBefore = await registry.policyHashOf(policyId);
      const mandateBefore = await registry.getMandate(policyId);

      await registry.connect(owner).revokePolicy(policyId);
      await registry.connect(owner).reactivatePolicy(policyId);

      const hashAfter = await registry.policyHashOf(policyId);
      const mandateAfter = await registry.getMandate(policyId);

      expect(hashAfter).to.equal(hashBefore);
      expect(mandateAfter.maxTxValue).to.equal(mandateBefore.maxTxValue);
      expect(mandateAfter.dailyLimit).to.equal(mandateBefore.dailyLimit);
      expect(mandateAfter.approvalThreshold).to.equal(mandateBefore.approvalThreshold);
      expect(mandateAfter.validFrom).to.equal(mandateBefore.validFrom);
      expect(mandateAfter.validUntil).to.equal(mandateBefore.validUntil);
    });

    it("recreating under a different salt to 'widen' a mandate produces a different policyHash and identifier", async function () {
      const { policyId: narrowId, params: narrowParams } = await create(owner, {
        salt: ethers.keccak256(ethers.toUtf8Bytes("narrow")),
        maxTxValue: ethers.parseEther("0.1"),
      });
      const wideSalt = ethers.keccak256(ethers.toUtf8Bytes("wide"));
      await registry
        .connect(owner)
        .createPolicy(wideSalt, ethers.parseEther("100"), ethers.parseEther("1000"), ethers.parseEther("500"), VALID_FROM, VALID_UNTIL, [targetA], [SELECTOR_A]);
      const wideId = await registry.computePolicyId(owner.address, wideSalt);

      expect(wideId).to.not.equal(narrowId);
      const narrowHash = await registry.policyHashOf(narrowId);
      const wideHash = await registry.policyHashOf(wideId);
      expect(narrowHash).to.not.equal(wideHash);
      // the narrow policy's own commitment is untouched by the existence
      // of a separate, wider one
      const narrowMandate = await registry.getMandate(narrowId);
      expect(narrowMandate.maxTxValue).to.equal(narrowParams.maxTxValue);
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
        registry.createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors)
      ).to.be.revertedWithCustomError(registry, "InvalidTimeWindow");
    });

    it("rejects an empty allowedTargets list (fail closed, no wildcard)", async function () {
      const p = defaultParams({ allowedTargets: [] });
      await expect(
        registry.createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors)
      ).to.be.revertedWithCustomError(registry, "EmptyAllowLists");
    });

    it("rejects an empty allowedSelectors list", async function () {
      const p = defaultParams({ allowedSelectors: [] });
      await expect(
        registry.createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors)
      ).to.be.revertedWithCustomError(registry, "EmptyAllowLists");
    });

    it("rejects a zero address inside allowedTargets", async function () {
      const p = defaultParams({ allowedTargets: [targetA, ethers.ZeroAddress] });
      await expect(
        registry.createPolicy(p.salt, p.maxTxValue, p.dailyLimit, p.approvalThreshold, p.validFrom, p.validUntil, p.allowedTargets, p.allowedSelectors)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    });
  });

  describe("isCallAllowedByPolicy — static mandate check", function () {
    let policyId: string;

    beforeEach(async function () {
      const res = await create(owner, { allowedTargets: [targetA], allowedSelectors: [SELECTOR_A], maxTxValue: ethers.parseEther("1") });
      policyId = res.policyId;
      await ethers.provider.send("evm_increaseTime", [200]);
      await ethers.provider.send("evm_mine", []);
    });

    it("allows a call within target, selector, and value bounds", async function () {
      expect(await registry.isCallAllowedByPolicy(policyId, targetA, SELECTOR_A, ethers.parseEther("0.5"))).to.equal(true);
    });

    it("rejects a disallowed target", async function () {
      expect(await registry.isCallAllowedByPolicy(policyId, targetB, SELECTOR_A, ethers.parseEther("0.5"))).to.equal(false);
    });

    it("rejects a disallowed selector", async function () {
      expect(await registry.isCallAllowedByPolicy(policyId, targetA, SELECTOR_B, ethers.parseEther("0.5"))).to.equal(false);
    });

    it("rejects a value exceeding maxTxValue", async function () {
      expect(await registry.isCallAllowedByPolicy(policyId, targetA, SELECTOR_A, ethers.parseEther("1.01"))).to.equal(false);
    });

    it("allows a value exactly at maxTxValue", async function () {
      expect(await registry.isCallAllowedByPolicy(policyId, targetA, SELECTOR_A, ethers.parseEther("1"))).to.equal(true);
    });

    it("rejects a revoked policy even if all other conditions are satisfied", async function () {
      await registry.connect(owner).revokePolicy(policyId);
      expect(await registry.isCallAllowedByPolicy(policyId, targetA, SELECTOR_A, ethers.parseEther("0.5"))).to.equal(false);
    });

    it("rejects before validFrom", async function () {
      const res = await create(owner, {
        salt: ethers.keccak256(ethers.toUtf8Bytes("future-policy")),
        validFrom: VALID_UNTIL - 10n,
        validUntil: VALID_UNTIL + 1_000_000n,
      });
      expect(await registry.isCallAllowedByPolicy(res.policyId, targetA, SELECTOR_A, ethers.parseEther("0.5"))).to.equal(false);
    });

    it("rejects after validUntil", async function () {
      await ethers.provider.send("evm_increaseTime", [Number(VALID_UNTIL - VALID_FROM) + 10]);
      await ethers.provider.send("evm_mine", []);
      expect(await registry.isCallAllowedByPolicy(policyId, targetA, SELECTOR_A, ethers.parseEther("0.5"))).to.equal(false);
    });

    it("returns false for a nonexistent policy rather than reverting", async function () {
      const fakeId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      expect(await registry.isCallAllowedByPolicy(fakeId, targetA, SELECTOR_A, 0n)).to.equal(false);
    });
  });
});
