import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * P1 remediation: policy-owner authorization.
 *
 * PHASE 2 of the P1 brief — reproduce the attack for real, against the
 * actual AgentRegistry + PolicyRegistry + AgentExecutionGuard stack, not
 * mocks, BEFORE any fix is designed or written.
 *
 * Attack narrative:
 *   1. Legitimate owner registers Agent A and creates a restrictive
 *      Policy A (narrow target/selector, small maxTxValue).
 *   2. Agent A's own key (which — by design — is the same key that signs
 *      ExecutionIntents, and which nothing prevents from also being
 *      `msg.sender` on PolicyRegistry) calls `createPolicy` itself,
 *      naming itself as both `owner` (msg.sender) and `agent`, with a
 *      maximally permissive configuration.
 *   3. Agent A signs a valid ExecutionIntent referencing this new,
 *      self-created Policy A', not the legitimate owner's Policy A.
 *   4. `execute()` is called.
 *
 * If execution succeeds, the compromised/malicious agent has bypassed
 * every restriction the legitimate owner ever intended, using only its
 * own already-possessed signing key — no compromise of the owner's key,
 * no compromise of AgentRegistry, no signature forgery anywhere. This
 * file proves whether that is possible on the actual deployed contracts.
 */
describe("P1: PolicyRegistry policy-owner authorization", function () {
  let agentRegistry: any;
  let agentRegistryAddress: string;
  let policyRegistry: any;
  let policyRegistryAddress: string;
  let guard: any;
  let guardAddress: string;
  let dangerousTarget: any;
  let dangerousTargetAddress: string;
  let legitimateOwner: HardhatEthersSigner;
  let wallet: HardhatEthersSigner;
  let agentA: ReturnType<typeof ethers.Wallet.createRandom>;

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

  beforeEach(async function () {
    [legitimateOwner, wallet] = await ethers.getSigners();
    agentA = ethers.Wallet.createRandom().connect(ethers.provider);

    // fund agentA's own address so IT can submit transactions itself
    // (both to PolicyRegistry.createPolicy and to
    // AgentExecutionGuard.execute) — this is the whole point: the
    // attacker here is the agent's own key, already legitimately funded
    // and operating, not someone who needs to steal anything further.
    await ethers.provider.send("hardhat_setBalance", [agentA.address, "0x" + ethers.parseEther("600").toString(16)]);

    const AgentRegistry = await ethers.getContractFactory("AgentRegistry");
    agentRegistry = await AgentRegistry.deploy();
    await agentRegistry.waitForDeployment();
    agentRegistryAddress = await agentRegistry.getAddress();

    const net = await ethers.provider.getNetwork();
    const regDomain = { name: "AgentRegistry", version: "1", chainId: net.chainId, verifyingContract: agentRegistryAddress };
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("config"));
    const regSig = await agentA.signTypedData(regDomain, registrationTypes, {
      agent: agentA.address, owner: legitimateOwner.address, metadataHash,
    });
    await agentRegistry.register(agentA.address, legitimateOwner.address, metadataHash, regSig);

    const PolicyRegistry = await ethers.getContractFactory("PolicyRegistry");
    policyRegistry = await PolicyRegistry.deploy();
    await policyRegistry.waitForDeployment();
    policyRegistryAddress = await policyRegistry.getAddress();

    const Guard = await ethers.getContractFactory("AgentExecutionGuard");
    guard = await Guard.deploy(agentRegistryAddress, policyRegistryAddress);
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();

    // A dangerous, high-value target the legitimate owner never intended
    // to authorize broadly — stands in for e.g. a token contract with a
    // "drain everything" style function, or just an arbitrary high-value
    // call surface.
    const RecordingTarget = await ethers.getContractFactory("RecordingTarget");
    dangerousTarget = await RecordingTarget.deploy();
    await dangerousTarget.waitForDeployment();
    dangerousTargetAddress = await dangerousTarget.getAddress();
  });

  it("PHASE 2 PoC (pre-fix: exploit succeeded; post-fix: exploit is blocked) — a malicious/compromised agent's self-created permissive policy is rejected", async function () {
    // Step 1: legitimate owner creates a genuinely restrictive policy —
    // tiny maxTxValue, and does NOT authorize dangerousTargetAddress at
    // all (native transfer or otherwise).
    const restrictiveSalt = ethers.keccak256(ethers.toUtf8Bytes("owner-restrictive-policy"));
    const someHarmlessTarget = ethers.Wallet.createRandom().address;
    await policyRegistry.connect(legitimateOwner).createPolicy(
      restrictiveSalt,
      agentA.address,
      ethers.parseEther("0.01"), // tiny maxTxValue
      0n, 0n, 0n, FAR_DEADLINE,
      [], [someHarmlessTarget] // only a harmless target, NOT dangerousTargetAddress
    );

    // Step 2: Agent A's OWN key — the same key that will sign the
    // ExecutionIntent — calls PolicyRegistry.createPolicy ITSELF,
    // naming itself as both owner (msg.sender) and agent, with a
    // maximally permissive configuration authorizing the dangerous
    // target the legitimate owner never approved. PolicyRegistry itself
    // has no way to know this is "wrong" — creation remains
    // permissionless by design (see ADR-0006) — the policy is created
    // successfully, exactly like a legitimate one.
    const attackerSalt = ethers.keccak256(ethers.toUtf8Bytes("attacker-permissive-policy"));
    const createTx = await policyRegistry.connect(agentA).createPolicy(
      attackerSalt,
      agentA.address, // attacker names itself as the agent
      ethers.parseEther("1000"), // enormous maxTxValue
      0n, 0n, 0n, FAR_DEADLINE,
      [], [dangerousTargetAddress] // authorizes the target the owner never approved
    );
    await createTx.wait();

    const attackerPolicyId = await policyRegistry.computePolicyId(agentA.address, attackerSalt);
    const attackerPolicyHash = await policyRegistry.policyHashOf(attackerPolicyId);

    // sanity: PolicyRegistry still has no idea this is "wrong" — the
    // policy exists, is bound to agentA, and is active, exactly like a
    // legitimate one. The P1 fix does NOT change PolicyRegistry at all
    // (see ADR-0006, "why PolicyRegistry itself is unchanged") — it is
    // deliberately still permissionless here.
    expect(await policyRegistry.ownerOf(attackerPolicyId)).to.equal(agentA.address);
    expect(await policyRegistry.agentOf(attackerPolicyId)).to.equal(agentA.address);
    expect(await policyRegistry.isPolicyActive(attackerPolicyId)).to.equal(true);

    // Step 3 & 4: Agent A signs a valid intent for a large transfer to
    // the dangerous target, referencing its OWN self-created policy —
    // not the legitimate owner's restrictive one.
    const value = ethers.parseEther("500"); // far beyond the owner's intended 0.01 ETH cap
    const intent: Intent = {
      agent: agentA.address, wallet: wallet.address, target: dangerousTargetAddress, value,
      data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash: attackerPolicyHash,
    };
    const sig = await signIntent(agentA, intent);

    // Step 5: submit execute(). The fix is now in place:
    // AgentExecutionGuard checks the policy's recorded `owner` against
    // AgentRegistry's LIVE `ownerOf(agent)`. The self-created policy's
    // owner is agentA itself, but the real registered owner is
    // legitimateOwner — mismatch, REVERT.
    await expect(
      guard.connect(agentA).execute(
        intent.agent, intent.wallet, intent.target, intent.value, intent.data,
        intent.nonce, intent.deadline, intent.policyHash, sig,
        { value: intent.value }
      )
    )
      .to.be.revertedWithCustomError(guard, "PolicyOwnerMismatch")
      .withArgs(attackerPolicyHash, legitimateOwner.address, agentA.address);

    // and no funds moved, no nonce consumed — the attempt left no trace
    expect(await ethers.provider.getBalance(dangerousTargetAddress)).to.equal(0n);
    expect(await guard.nextNonce(agentA.address)).to.equal(0n);
  });

  it("positive control: the legitimate owner's OWN restrictive policy still executes correctly (the fix does not break honest use)", async function () {
    const salt = ethers.keccak256(ethers.toUtf8Bytes("owner-legit-policy"));
    await policyRegistry.connect(legitimateOwner).createPolicy(
      salt, agentA.address, ethers.parseEther("0.01"), 0n, 0n, 0n, FAR_DEADLINE, [], [dangerousTargetAddress]
    );
    const policyId = await policyRegistry.computePolicyId(legitimateOwner.address, salt);
    const policyHash = await policyRegistry.policyHashOf(policyId);

    const intent: Intent = {
      agent: agentA.address, wallet: wallet.address, target: dangerousTargetAddress, value: ethers.parseEther("0.005"),
      data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash,
    };
    const sig = await signIntent(agentA, intent);

    await guard.connect(agentA).execute(
      intent.agent, intent.wallet, intent.target, intent.value, intent.data,
      intent.nonce, intent.deadline, intent.policyHash, sig,
      { value: intent.value }
    );

    expect(await ethers.provider.getBalance(dangerousTargetAddress)).to.equal(ethers.parseEther("0.005"));
    expect(await guard.nextNonce(agentA.address)).to.equal(1n);
  });

  it("attacker cannot spoof msg.sender by passing the legitimate owner's address as any other parameter — owner is always msg.sender, never caller-suppliable", async function () {
    const [, , attacker] = await ethers.getSigners();
    // there is no "owner" parameter in createPolicy at all to spoof —
    // but to make the impossibility explicit rather than merely
    // implicit, this attacker creates a policy while every OTHER
    // address-shaped value available (agent) happens to equal the
    // legitimate owner's own address, to rule out any accidental
    // parameter-order confusion in the ABI encoding itself.
    const salt = ethers.keccak256(ethers.toUtf8Bytes("spoof-attempt"));
    const tx = await policyRegistry.connect(attacker).createPolicy(
      salt,
      legitimateOwner.address, // `agent` parameter deliberately set to the owner's own address
      ethers.parseEther("1000"), 0n, 0n, 0n, FAR_DEADLINE,
      [], [dangerousTargetAddress]
    );
    await tx.wait();
    const policyId = await policyRegistry.computePolicyId(attacker.address, salt);
    // owner is unconditionally msg.sender (the attacker), regardless of
    // what any other parameter contains.
    expect(await policyRegistry.ownerOf(policyId)).to.equal(attacker.address);
    expect(await policyRegistry.ownerOf(policyId)).to.not.equal(legitimateOwner.address);
  });

  it("a total stranger (not the agent, not the owner) also cannot author a usable policy for someone else's agent", async function () {
    const [, , stranger] = await ethers.getSigners();
    const salt = ethers.keccak256(ethers.toUtf8Bytes("stranger-policy"));
    await policyRegistry.connect(stranger).createPolicy(
      salt, agentA.address, ethers.parseEther("1000"), 0n, 0n, 0n, FAR_DEADLINE, [], [dangerousTargetAddress]
    );
    const policyId = await policyRegistry.computePolicyId(stranger.address, salt);
    const policyHash = await policyRegistry.policyHashOf(policyId);

    const intent: Intent = {
      agent: agentA.address, wallet: wallet.address, target: dangerousTargetAddress, value: ethers.parseEther("500"),
      data: "0x", nonce: 0n, deadline: FAR_DEADLINE, policyHash,
    };
    const sig = await signIntent(agentA, intent);

    await expect(
      guard.connect(agentA).execute(
        intent.agent, intent.wallet, intent.target, intent.value, intent.data,
        intent.nonce, intent.deadline, intent.policyHash, sig,
        { value: intent.value }
      )
    )
      .to.be.revertedWithCustomError(guard, "PolicyOwnerMismatch")
      .withArgs(policyHash, legitimateOwner.address, stranger.address);
  });
});
