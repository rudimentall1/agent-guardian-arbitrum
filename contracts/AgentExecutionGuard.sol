// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IAgentRegistry} from "./interfaces/IAgentRegistry.sol";
import {IPolicyRegistry} from "./interfaces/IPolicyRegistry.sol";

/// @title AgentExecutionGuard
/// @notice Gate 2 + remediation + Gate 4A + P1 fix: the execution-intent,
/// replay-protection, and call-authorization boundary for delegated
/// agent transactions. Still does NOT implement daily spend accounting
/// or an approval flow — those remain Gate 4B. What it guarantees, and
/// only this:
///
///   1. An execution intent is authorized only by an EIP-712 signature
///      from the exact agent it names, domain-separated by chain id and
///      this contract's address.
///   2. The signed digest binds every field the intent claims to
///      authorize (agent, wallet, target, value, calldata, nonce,
///      deadline, policyHash) — none of them can be altered after
///      signing without invalidating the signature.
///   3. Each agent has its own monotonic nonce; exactly one nonce value
///      is ever executable at a time — see
///      docs/adr/0002-monotonic-per-agent-nonce.md.
///   4. Nonce consumption and the intent's external call are atomic —
///      a failed call reverts the whole transaction, nonce included.
///   5. AgentRegistry's live `isActiveAgent` status is checked at
///      execution time, not signing time.
///   6. [Remediation] `msg.value` MUST equal the intent's signed `value`
///      field exactly.
///   7. [Remediation] `policyHash` MUST be bound to this intent's exact
///      `agent` in PolicyRegistry.
///   8. [Gate 4A] `value` MUST NOT exceed the bound policy's
///      `maxTxValue`.
///   9. [Gate 4A] The intent's `(target, calldata)` MUST be an exactly
///      authorized (target, selector) pair — or, for empty calldata, an
///      exactly authorized native-transfer target — under the bound
///      policy. Calldata is classified into `NativeTransfer`,
///      `FunctionCall`, or `Malformed` (1–3 bytes: never authorized,
///      unconditionally) by THIS contract, from the same `data` already
///      bound into the signed digest — PolicyRegistry never receives an
///      independently-suppliable target/selector; see
///      docs/adr/0005-paired-target-selector-authorization.md.
///  10. [P1 fix] A policy's recorded `owner` MUST equal AgentRegistry's
///      LIVE current owner of the intent's `agent`. `PolicyRegistry.
///      createPolicy` is permissionless by design (see
///      docs/adr/0003-immutable-policy-derived-identifier.md) — anyone,
///      including a compromised or malicious agent's own key, can
///      create a policy naming any agent and calling themselves its
///      owner. Binding `policyHash -> agent` alone (point 7) is
///      therefore NOT sufficient proof that the policy reflects the
///      legitimate owner's intent — this check closes that gap. See
///      docs/adr/0006-policy-owner-authorization.md.
///
/// @dev Explicitly out of scope: `dailyLimit`/`approvalThreshold`
/// accounting, an approval flow, and real wallet custody. `target +
/// selector` authorization is NOT argument-level authorization — a
/// policy authorizing `token.transfer(address,uint256)` on some target
/// says nothing about which recipient or amount was passed; the signed
/// `calldataHash` still cryptographically binds the exact arguments used
/// (see the ADR, "calldata binding" — argument-level restrictions
/// remain a possible future gate, not implemented here).
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
    /// at any point in time is `nextNonce[agent]`.
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
    error PolicyOwnerMismatch(bytes32 policyHash, address registeredOwner, address policyOwner);
    error PolicyNotActive(bytes32 policyHash);
    error PolicyOutsideTimeWindow(bytes32 policyHash, uint256 currentTimestamp);
    error MaxTxValueExceeded(uint256 value, bytes32 policyHash);
    error CallNotAuthorized(address target, bytes4 selector, bool isNativeTransfer);

    constructor(address registry, address policyRegistry) EIP712("AgentExecutionGuard", "1") {
        if (registry == address(0) || policyRegistry == address(0)) revert ZeroAddress();
        REGISTRY = IAgentRegistry(registry);
        POLICY_REGISTRY = IPolicyRegistry(policyRegistry);
    }

    /// @notice Execute a single agent-authorized intent exactly once.
    /// @dev Final check ordering, and why:
    ///
    ///   1. zero-address checks (agent/wallet/target)      — cheapest,
    ///      pure calldata validation, no reads at all.
    ///   2. deadline check                                  — cheap,
    ///      pure arithmetic on already-available block data.
    ///   3. msg.value == value                               — cheap,
    ///      pure arithmetic, no reads.
    ///   4. classify calldata -> (CallKind, selector)         — cheap,
    ///      pure computation over calldata already present.
    ///   5. agent-active check (external call: AgentRegistry) — one
    ///      cold external view call.
    ///   6. combined policy check (external call: PolicyRegistry) —
    ///      one cold external view call resolving agent-binding,
    ///      active/time-window, maxTxValue, and target+selector
    ///      authorization together, so this remains ONE round trip no
    ///      matter how many mandate dimensions this function checks.
    ///   7. nonce check                                       — a
    ///      single SLOAD against this contract's own storage.
    ///   8. signature check (ECDSA.recover)                   — the
    ///      single most expensive operation in this list.
    ///   9. nonce consumption (SSTORE)                        — the
    ///      only state write before the external call.
    ///  10. external call.
    ///
    /// Cheapest-first ordering is a deliberate gas-griefing mitigation:
    /// none of steps 1–8 write any state, so there is no security cost
    /// to failing fast on a malformed or unauthorized call before paying
    /// for the most expensive check (signature recovery) — an attacker
    /// spamming invalid intents pays less gas per rejected attempt than
    /// they would under a "verify signature first" ordering, and the
    /// authorization guarantee is identical either way since nothing is
    /// trusted or mutated until every check has passed. A failed policy,
    /// maxTxValue, or target/selector check — like every check before
    /// nonce consumption — never burns a nonce.
    ///
    /// `nonReentrant` blocks ANY nested call back into `execute` during
    /// the external call, even one authorized for a different agent or
    /// nonce.
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

        (IPolicyRegistry.CallKind callKind, bytes4 selector) = classifyCalldata(data);

        if (!REGISTRY.isActiveAgent(agent)) revert AgentNotActive(agent);
        address registeredOwner = REGISTRY.ownerOf(agent);

        (address policyOwner, address boundAgent, bool policyActive, bool withinWindow, bool valueAllowed, bool callAllowed) =
            POLICY_REGISTRY.checkAuthorization(policyHash, target, callKind, selector, value);

        if (boundAgent != agent) revert PolicyAgentMismatch(policyHash, agent, boundAgent);
        // [P1 fix] A policy binding `boundAgent == agent` is not, on its
        // own, proof that the policy was authorized by whoever legitimately
        // controls `agent`. `PolicyRegistry.createPolicy` is permissionless
        // — anyone, including the agent's own key, can create a policy
        // naming any agent and calling themselves its owner. This check
        // closes that gap by requiring the policy's recorded owner to
        // match AgentRegistry's LIVE current owner of `agent`, not a
        // cached or self-asserted one. See
        // docs/adr/0006-policy-owner-authorization.md.
        if (policyOwner != registeredOwner) revert PolicyOwnerMismatch(policyHash, registeredOwner, policyOwner);
        if (!policyActive) revert PolicyNotActive(policyHash);
        if (!withinWindow) revert PolicyOutsideTimeWindow(policyHash, block.timestamp);
        if (!valueAllowed) revert MaxTxValueExceeded(value, policyHash);
        if (!callAllowed) revert CallNotAuthorized(target, selector, callKind == IPolicyRegistry.CallKind.NativeTransfer);

        uint256 expected = nextNonce[agent];
        if (nonce != expected) revert InvalidNonce(nonce, expected);

        bytes32 digest = hashIntent(agent, wallet, target, value, keccak256(data), nonce, deadline, policyHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != agent) revert InvalidSignature();

        // Effects before interaction. Reverts on overflow by construction
        // (Solidity 0.8 checked arithmetic) rather than wrapping back to
        // 0 — see docs/adr/0002-monotonic-per-agent-nonce.md.
        nextNonce[agent] = nonce + 1;

        (bool success, bytes memory ret) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed(ret);

        emit IntentExecuted(agent, wallet, target, nonce, policyHash);
        return ret;
    }

    /// @notice Classify calldata exactly as PolicyRegistry.CallKind
    /// expects: empty -> NativeTransfer, >=4 bytes -> FunctionCall (with
    /// its first 4 bytes as `selector`), 1-3 bytes -> Malformed (whose
    /// `selector` return value is meaningless and MUST NOT be used —
    /// PolicyRegistry never performs a mapping lookup for `Malformed`,
    /// so no caller-observable selector value for this case can ever
    /// become an authorization bypass regardless of what's returned
    /// here; it is fixed at `bytes4(0)` purely for a deterministic
    /// return type).
    function classifyCalldata(bytes calldata data) public pure returns (IPolicyRegistry.CallKind, bytes4 selector) {
        if (data.length == 0) {
            return (IPolicyRegistry.CallKind.NativeTransfer, bytes4(0));
        }
        if (data.length >= 4) {
            return (IPolicyRegistry.CallKind.FunctionCall, bytes4(data[0:4]));
        }
        return (IPolicyRegistry.CallKind.Malformed, bytes4(0));
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
