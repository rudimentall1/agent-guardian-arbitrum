// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IAgentRegistry} from "./interfaces/IAgentRegistry.sol";
import {IPolicyRegistry} from "./interfaces/IPolicyRegistry.sol";

/// @title AgentExecutionGuard
/// @notice Gate 2 + remediation gate: the execution-intent and
/// replay-protection foundation for delegated agent transactions, plus
/// two fixes to architectural gaps found before Gate 4. This contract
/// still does NOT implement full financial mandates (maxTxValue,
/// allowed-target/selector enforcement, daily spend, approval flow) —
/// those remain Gate 4. What it guarantees, and only this:
///
///   1. An execution intent is authorized only by an EIP-712 signature
///      from the exact agent it names, domain-separated by chain id and
///      this contract's address.
///   2. The signed digest binds every field the intent claims to
///      authorize (agent, wallet, target, value, calldata, nonce,
///      deadline, policyHash) — none of them can be altered after
///      signing without invalidating the signature.
///   3. Each agent has its own monotonic nonce. Exactly one nonce value
///      is ever executable for a given agent at a given time: the
///      current one. Not the previous one (already consumed), not any
///      future one (out of order execution is not supported by design —
///      see docs/adr/0002-monotonic-per-agent-nonce.md).
///   4. Nonce consumption and the intent's external call are atomic: if
///      the call fails, the entire transaction reverts and the nonce is
///      NOT consumed, so the same intent can be retried. There is no
///      state in which an intent both "failed" and "permanently burned
///      its nonce", and no state in which it both "succeeded" and left
///      its nonce reusable.
///   5. AgentRegistry's live `isActiveAgent` status is checked at
///      execution time, not at signing time. A signature produced while
///      an agent was active becomes unusable the instant the agent is
///      deactivated or its owner transfers it away (which itself forces
///      inactivity — see AgentRegistry), with no separate revocation
///      step required here.
///   6. [Remediation] `msg.value` sent with the transaction MUST equal
///      the intent's signed `value` field exactly. Before this gate, a
///      caller could send more or less native currency than the agent
///      actually authorized; any excess had no withdrawal path and sat
///      stuck in this contract, later spendable by an unrelated call
///      whose own declared `value` happened to be covered by that
///      leftover balance. Now the contract's ETH balance always returns
///      to exactly 0 after every successful `execute` call.
///   7. [Remediation] If `policyHash` resolves to a real policy in
///      `PolicyRegistry`, that policy's recorded agent MUST equal this
///      intent's `agent`. A `policyHash` created for Agent B can never
///      be referenced by an intent naming Agent A. See
///      docs/adr/0004-msg-value-and-policy-agent-binding.md for why
///      binding alone (without full mandate-content enforcement) is
///      still meaningfully load-bearing on its own.
///
/// @dev Explicitly out of scope for this gate (see the remediation
/// report): maxTxValue/target/selector mandate enforcement, daily spend
/// accounting, approval flows, and real wallet custody.
contract AgentExecutionGuard is EIP712, ReentrancyGuard {
    /// @dev keccak256(
    ///   "ExecutionIntent(address agent,address wallet,address target,uint256 value,bytes32 calldataHash,uint256 nonce,uint256 deadline,bytes32 policyHash)"
    /// )
    bytes32 private constant EXECUTION_INTENT_TYPEHASH =
        keccak256(
            "ExecutionIntent(address agent,address wallet,address target,uint256 value,bytes32 calldataHash,uint256 nonce,uint256 deadline,bytes32 policyHash)"
        );

    IAgentRegistry public immutable REGISTRY;
    IPolicyRegistry public immutable POLICY_REGISTRY;

    /// @notice Next valid nonce for each agent. Starts at 0. The ONLY
    /// nonce value that will be accepted by `execute` for a given agent
    /// at any point in time is `nextNonce[agent]` — not lower (already
    /// consumed), not higher (out of order, unsupported).
    mapping(address => uint256) public nextNonce;

    event IntentExecuted(
        address indexed agent, address indexed wallet, address indexed target, uint256 nonce, bytes32 policyHash
    );

    error ZeroAddress();
    error AgentNotActive(address agent);
    error IntentExpired(uint256 deadline, uint256 currentTimestamp);
    error InvalidNonce(uint256 provided, uint256 expected);
    error InvalidSignature();
    error ExecutionFailed(bytes returndata);
    error ValueMismatch(uint256 sent, uint256 signed);
    error PolicyAgentMismatch(bytes32 policyHash, address intentAgent, address boundAgent);
    error PolicyNotActive(bytes32 policyHash);

    constructor(address registry, address policyRegistry) EIP712("AgentExecutionGuard", "1") {
        if (registry == address(0) || policyRegistry == address(0)) revert ZeroAddress();
        REGISTRY = IAgentRegistry(registry);
        POLICY_REGISTRY = IPolicyRegistry(policyRegistry);
    }

    /// @notice Execute a single agent-authorized intent exactly once.
    /// @dev Ordering is deliberate and load-bearing:
    ///   deadline check -> value/msg.value match -> agent-active check ->
    ///   policy-agent binding check -> nonce check -> signature check ->
    ///   nonce consumption -> external call.
    /// The value-match and policy-binding checks were added by the
    /// remediation gate; both are cheap, state-independent checks and
    /// are placed before signature verification purely to fail fast and
    /// save gas on malformed calls — they do not weaken the guarantee
    /// that nothing state-changing happens before the signature is
    /// verified, since neither check writes any state.
    /// `nonReentrant` blocks ANY nested call back into `execute` during
    /// the external call, even one authorized for a different agent or a
    /// different nonce. A legitimate nested intent must be submitted as
    /// its own top-level transaction.
    function execute(
        address agent,
        address wallet,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes32 policyHash,
        bytes calldata signature
    ) external payable nonReentrant returns (bytes memory returndata) {
        if (agent == address(0) || wallet == address(0) || target == address(0)) revert ZeroAddress();
        if (block.timestamp > deadline) revert IntentExpired(deadline, block.timestamp);
        if (msg.value != value) revert ValueMismatch(msg.value, value);
        if (!REGISTRY.isActiveAgent(agent)) revert AgentNotActive(agent);

        (address boundAgent, bool policyActive) = POLICY_REGISTRY.resolvePolicyBinding(policyHash);
        if (boundAgent != agent) revert PolicyAgentMismatch(policyHash, agent, boundAgent);
        if (!policyActive) revert PolicyNotActive(policyHash);

        uint256 expected = nextNonce[agent];
        if (nonce != expected) revert InvalidNonce(nonce, expected);

        bytes32 digest = hashIntent(agent, wallet, target, value, keccak256(data), nonce, deadline, policyHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != agent) revert InvalidSignature();

        // Effects before interaction. Reverts on overflow by construction
        // (Solidity 0.8 checked arithmetic) rather than wrapping back to
        // 0 — see docs/adr/0002-monotonic-per-agent-nonce.md for why a
        // wraparound here would be a replay bypass, not a UX edge case.
        nextNonce[agent] = nonce + 1;

        (bool success, bytes memory ret) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed(ret);

        emit IntentExecuted(agent, wallet, target, nonce, policyHash);
        return ret;
    }

    /// @notice Compute the EIP-712 digest for an intent, for off-chain
    /// signing and on-chain verification to agree byte-for-byte.
    function hashIntent(
        address agent,
        address wallet,
        address target,
        uint256 value,
        bytes32 calldataHash,
        uint256 nonce,
        uint256 deadline,
        bytes32 policyHash
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(EXECUTION_INTENT_TYPEHASH, agent, wallet, target, value, calldataHash, nonce, deadline, policyHash)
        );
        return _hashTypedDataV4(structHash);
    }
}
