import { expect } from "chai";
import { ethers } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("Gate 4A: call authorization and maxTxValue — full stack", function () {
  let registry: any, policyRegistry: any, guard: any, targetA: any, targetB: any, recorder: any;
  let owner: HardhatEthersSigner, wallet: HardhatEthersSigner;
  let agent: ReturnType<typeof ethers.Wallet.createRandom>;
  let guardAddress: string, agentAddress: string, targetAAddress: string, targetBAddress: string, recorderAddress: string;
  const DEADLINE = 4102444800n;
  const FOO = ethers.id("foo(uint256)").slice(0, 10);
  const BAR = ethers.id("bar(address)").slice(0, 10);

  const regTypes = { AgentRegistration: [
    { name: "agent", type: "address" }, { name: "owner", type: "address" }, { name: "metadataHash", type: "bytes32" },
  ] };
  const intentTypes = { ExecutionIntent: [
    { name: "agent", type: "address" }, { name: "wallet", type: "address" }, { name: "target", type: "address" },
    { name: "value", type: "uint256" }, { name: "calldataHash", type: "bytes32" }, { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }, { name: "policyHash", type: "bytes32" },
  ] };

  async function createPolicy(name: string, calls: { target: string; selector: string }[], nativeTargets: string[] = [], max = ethers.parseEther("1")) {
    const salt = ethers.keccak256(ethers.toUtf8Bytes(name));
    const coder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = coder.encode(
      ["bytes32","address","uint128","uint128","uint128","uint64","uint64","tuple(address target,bytes4 selector)[]","address[]"],
      [salt, agentAddress, max, ethers.MaxUint128, ethers.MaxUint128, 0n, DEADLINE, calls, nativeTargets]
    );
    const selector = ethers.id("createPolicy(bytes32,address,uint128,uint128,uint128,uint64,uint64,(address,bytes4)[],address[])").slice(0, 10);
    await owner.sendTransaction({ to: await policyRegistry.getAddress(), data: ethers.concat([selector, encoded]) });
    const id = await policyRegistry.computePolicyId(owner.address, salt);
    return policyRegistry.policyHashOf(id);
  }

  async function sign(policyHash: string, target: string, value: bigint, data: string, nonce: bigint, deadline = DEADLINE) {
    const net = await ethers.provider.getNetwork();
    return agent.signTypedData(
      { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress },
      intentTypes,
      { agent: agentAddress, wallet: wallet.address, target, value, calldataHash: ethers.keccak256(data), nonce, deadline, policyHash }
    );
  }

  async function execute(policyHash: string, target: string, value: bigint, data: string, nonce: bigint, deadline = DEADLINE) {
    const sig = await sign(policyHash, target, value, data, nonce, deadline);
    return guard.execute(agentAddress, wallet.address, target, value, data, nonce, deadline, policyHash, sig, { value });
  }

  beforeEach(async function () {
    [owner, wallet] = await ethers.getSigners();
    agent = ethers.Wallet.createRandom().connect(ethers.provider);
    agentAddress = agent.address;
    registry = await (await ethers.getContractFactory("AgentRegistry")).deploy();
    await registry.waitForDeployment();
    const net = await ethers.provider.getNetwork();
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes("gate4a"));
    const regSig = await agent.signTypedData(
      { name: "AgentRegistry", version: "1", chainId: net.chainId, verifyingContract: await registry.getAddress() },
      regTypes, { agent: agentAddress, owner: owner.address, metadataHash }
    );
    await registry.register(agentAddress, owner.address, metadataHash, regSig);
    policyRegistry = await (await ethers.getContractFactory("PolicyRegistry")).deploy();
    await policyRegistry.waitForDeployment();
    guard = await (await ethers.getContractFactory("AgentExecutionGuard")).deploy(await registry.getAddress(), await policyRegistry.getAddress());
    await guard.waitForDeployment();
    guardAddress = await guard.getAddress();
    targetA = await (await ethers.getContractFactory("SelectorTarget")).deploy();
    await targetA.waitForDeployment();
    targetAAddress = await targetA.getAddress();
    targetB = await (await ethers.getContractFactory("SelectorTarget")).deploy();
    await targetB.waitForDeployment();
    targetBAddress = await targetB.getAddress();
    recorder = await (await ethers.getContractFactory("RecordingTarget")).deploy();
    await recorder.waitForDeployment();
    recorderAddress = await recorder.getAddress();
  });

  it("enforces exact target+selector pairs and prevents the Cartesian-product bug", async function () {
    const policy = await createPolicy("cartesian", [{target: targetAAddress, selector: FOO}, {target: targetBAddress, selector: BAR}]);
    await execute(policy, targetAAddress, 0n, targetA.interface.encodeFunctionData("foo", [1]), 0n);
    await execute(policy, targetBAddress, 0n, targetB.interface.encodeFunctionData("bar", [wallet.address]), 1n);
    await expect(execute(policy, targetAAddress, 0n, targetA.interface.encodeFunctionData("bar", [wallet.address]), 2n)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
    await expect(execute(policy, targetBAddress, 0n, targetB.interface.encodeFunctionData("foo", [1]), 2n)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
  });

  it("keeps native transfer authorization separate from function calls", async function () {
    const policy = await createPolicy("native-separation", [{target: targetAAddress, selector: "0x00000000"}], [recorderAddress]);
    await execute(policy, recorderAddress, 0n, "0x", 0n);
    expect(await recorder.callCount()).to.equal(1n);
    await expect(execute(policy, recorderAddress, 0n, "0x12345678", 1n)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
  });

  it("rejects malformed 1–3 byte calldata", async function () {
    const policy = await createPolicy("malformed", [{target: targetAAddress, selector: "0x00000000"}], [targetAAddress]);
    await expect(execute(policy, targetAAddress, 0n, "0x12", 0n)).to.be.revertedWithCustomError(guard, "CallNotAuthorized");
  });

  it("enforces maxTxValue at both boundaries", async function () {
    const max = ethers.parseEther("1");
    const policy = await createPolicy("max-boundary", [{target: targetAAddress, selector: FOO}], [], max);
    await execute(policy, targetAAddress, max, targetA.interface.encodeFunctionData("foo", [1]), 0n);
    await expect(execute(policy, targetAAddress, max + 1n, targetA.interface.encodeFunctionData("foo", [1]), 1n)).to.be.revertedWithCustomError(guard, "MaxTxValueExceeded");
  });

  it("rejects wrong-agent policies and replayed nonces", async function () {
    const otherAgent = ethers.Wallet.createRandom().connect(ethers.provider);
    const policyA = await createPolicy("wrong-agent", [{target: targetAAddress, selector: FOO}]);
    const policyB = await createPolicy("wrong-agent-b", [{target: targetBAddress, selector: BAR}]);
    await execute(policyA, targetAAddress, 0n, targetA.interface.encodeFunctionData("foo", [1]), 0n);
    const data = targetA.interface.encodeFunctionData("foo", [2]);
    const otherPolicy = policyB;
    const net = await ethers.provider.getNetwork();
    const sig = await otherAgent.signTypedData(
      { name: "AgentExecutionGuard", version: "1", chainId: net.chainId, verifyingContract: guardAddress },
      intentTypes,
      { agent: agentAddress, wallet: wallet.address, target: targetAAddress, value: 0n, calldataHash: ethers.keccak256(data), nonce: 1n, deadline: DEADLINE, policyHash: otherPolicy }
    );
    await expect(guard.execute(agentAddress, wallet.address, targetAAddress, 0n, data, 1n, DEADLINE, otherPolicy, sig)).to.be.reverted;
    await expect(execute(policyA, targetAAddress, 0n, data, 0n)).to.be.reverted;
  });
});
