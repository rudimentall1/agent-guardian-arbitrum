// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IAgentRegistry} from "./interfaces/IAgentRegistry.sol";

/// @title AgentExecutionGuard
/// @notice Gate 2: the execution-intent and replay-protection foundation
/// for delegated agent transactions. This contract deliberately does NOT
/// yet implement financial mandates, policy enforcement, or an approval
/// flow — those are later gates. What it guarantees, and only this:
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
///
/// @dev Explicitly out of scope for this gate (see the Gate 2 report):
/// spending limits, allowed-target/selector mandates, approval flows for
/// high-risk actions, and real wallet custody. `value` forwarded through
/// `execute` is funded by the caller's `msg.value` for this transaction
/// only — this contract holds no standing balance and is not a wallet.
contract AgentExecutionGuard is EIP712, ReentrancyGuard {
    /// @dev keccak256(
    ///   "ExecutionIntent(address agent,address wallet,address target,uint256 value,bytes32 calldataHash,uint256 nonce,uint256 deadline,bytes32 policyHash)"
    /// )
    bytes32 private constant EXECUTION_INTENT_TYPEHASH =
        keccak256(
            "ExecutionIntent(address agent,address wallet,address target,uint256 value,bytes32 calldataHash,uint256 nonce,uint256 deadline,bytes32 policyHash)"
        );

    IAgentRegistry public immutable REGISTRY;

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

    constructor(address registry) EIP712("AgentExecutionGuard", "1") {
        if (registry == address(0)) revert ZeroAddress();
        REGISTRY = IAgentRegistry(registry);
    }

    /// @notice Execute a single agent-authorized intent exactly once.
    /// @dev Ordering is deliberate and load-bearing:
    ///   deadline check -> agent-active check -> nonce check ->
    ///   signature check -> nonce consumption -> external call.
    /// Signature verification happens before any state write, and nonce
    /// consumption happens before the external call (checks-effects-
    /// interactions). `nonReentrant` additionally blocks ANY nested call
    /// back into `execute` during the external call, even one authorized
    /// for a different agent or a different nonce. A legitimate nested
    /// intent is not lost — it is simply not executable from within
    /// another intent's call frame, and must be submitted as its own
    /// top-level transaction. This is a deliberate simplicity/security
    /// trade: it removes an entire class of "what can happen mid-call"
    /// reasoning for this gate and every gate built on top of it.
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
        if (!REGISTRY.isActiveAgent(agent)) revert AgentNotActive(agent);

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
