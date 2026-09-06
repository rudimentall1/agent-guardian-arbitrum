// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title PolicyRegistry
/// @notice Gate 3 + remediation + Gate 4A: on-chain storage and
/// commitment for financial mandates. A mandate is the maximum
/// authority a wallet owner delegates under a given policy — a
/// per-transaction native-value cap, an active time window, and a set
/// of specifically authorized (target, selector) call pairs plus
/// specifically authorized native-transfer targets.
///
/// Design decisions and why:
///
/// 1. A policy is immutable once created. There is deliberately no
///    "update mandate parameters in place" function — only `revoke` and
///    `reactivate`, which flip a single `active` bit and change nothing
///    else. This follows directly from docs/protocol-spec.md section 4:
///    "changing policy does not silently change the meaning of an
///    already signed intent." A new mandate is a new `policyId` with
///    its own `policyHash`, full stop.
///
/// 2. [Gate 4A] Authorization is a PAIRED (target, selector) tuple, not
///    two independent allow-lists. Gate 3's original representation —
///    `allowedTargets = {A, B}` and `allowedSelectors = {X, Y}` checked
///    independently — accidentally authorized the full Cartesian
///    product `{A+X, A+Y, B+X, B+Y}` even when only `A+X` and `B+Y` were
///    ever intended. That is a real privilege-escalation bug, not a
///    theoretical one: an owner who meant to allow "transfer() on token
///    A" and "approve() on token B" would have unknowingly also
///    authorized "approve() on token A" and "transfer() on token B".
///    This gate replaces both allow-lists with a single mapping keyed by
///    `keccak256(abi.encode(target, selector))`, so only the exact pairs
///    explicitly authorized at creation are ever allowed. See
///    docs/adr/0005-paired-target-selector-authorization.md for the
///    full analysis of alternatives (including why a raw `mapping(target
///    => mapping(selector => bool))` was rejected in favor of a single
///    flattened key).
///
/// 3. [Gate 4A] Native-value transfers (`data.length == 0`) are a
///    SEPARATE authorization dimension from function calls, tracked in
///    `mapping(policyId => mapping(target => bool))`, never through the
///    (target, selector) mapping. Overloading selector `0x00000000` to
///    mean "native transfer" was rejected: `0x00000000` is a real,
///    reachable function selector (any function whose signature hashes
///    to all-zero bytes), and conflating it with "no calldata" would let
///    a policy that authorizes that one unlucky selector for a target
///    also silently authorize plain ETH transfers to that target, or
///    vice versa. See the ADR, "empty calldata semantics".
///
/// 4. `dailyLimit` and `approvalThreshold` remain stored declared limits
///    only, not enforced here or anywhere in this repository yet — see
///    contract-level NatSpec point 3 in the pre-Gate-4A version of this
///    file (docs/gate-3-policy-registry.md) and
///    docs/gate-4a-call-authorization.md for current status. `maxTxValue`
///    IS enforced starting this gate, via `checkAuthorization` below.
///
/// 5. No ownership transfer, and the on-chain identifier is
///    `keccak256(abi.encode(owner, salt))` — unchanged from Gate 3, see
///    docs/adr/0003-immutable-policy-derived-identifier.md.
///
/// 6. Every policy is bound to exactly one `agent` at creation,
///    immutably — unchanged from the remediation gate, see
///    docs/adr/0004-msg-value-and-policy-agent-binding.md.
contract PolicyRegistry {
    /// @notice One explicitly authorized (target, selector) function-call
    /// pair, supplied at policy creation.
    struct AuthorizedCall {
        address target;
        bytes4 selector;
    }

    /// @notice How `AgentExecutionGuard` classifies the calldata of an
    /// execution intent before asking this registry whether it's
    /// authorized. Computed by the Guard from the actual signed calldata
    /// — see contract-level NatSpec point 3 and the ADR's discussion of
    /// the classification/authorization responsibility split.
    ///   NativeTransfer — `data.length == 0`.
    ///   FunctionCall   — `data.length >= 4`; `selector` is the first 4
    ///                     bytes.
    ///   Malformed      — `1 <= data.length <= 3`: neither a native
    ///                     transfer (data isn't empty) nor a complete
    ///                     selector (fewer than 4 bytes). NEVER
    ///                     authorized, unconditionally, regardless of
    ///                     policy configuration — there is no mapping
    ///                     lookup for this case at all, so it cannot be
    ///                     accidentally authorized by any stored entry.
    enum CallKind {
        NativeTransfer,
        FunctionCall,
        Malformed
    }

    struct Mandate {
        address owner;
        address agent;
        bool active;
        uint128 maxTxValue;
        uint128 dailyLimit;
        uint128 approvalThreshold;
        uint64 validFrom;
        uint64 validUntil;
    }

    mapping(bytes32 => Mandate) private _mandates;
    mapping(bytes32 => bytes32) public policyHashOf;
    mapping(bytes32 => bytes32) public policyIdOfHash;
    /// @dev policyId => keccak256(abi.encode(target, selector)) => authorized
    mapping(bytes32 => mapping(bytes32 => bool)) private _authorizedCalls;
    /// @dev policyId => target => native-transfer authorized
    mapping(bytes32 => mapping(address => bool)) private _authorizedNativeTransfer;

    event PolicyCreated(bytes32 indexed policyId, address indexed owner, address indexed agent, bytes32 salt, bytes32 policyHash);
    event PolicyRevoked(bytes32 indexed policyId, address indexed owner);
    event PolicyReactivated(bytes32 indexed policyId, address indexed owner);
    event CallAuthorized(bytes32 indexed policyId, address indexed target, bytes4 selector);
    event NativeTransferAuthorized(bytes32 indexed policyId, address indexed target);

    error PolicyAlreadyExists(bytes32 policyId);
    error PolicyNotFound(bytes32 policyId);
    error NotPolicyOwner(bytes32 policyId, address caller);
    error PolicyAlreadyActive(bytes32 policyId);
    error PolicyAlreadyInactive(bytes32 policyId);
    error InvalidTimeWindow(uint64 validFrom, uint64 validUntil);
    error ZeroAddress();
    error EmptyAuthorization();

    /// @notice Derive the policy identifier for `owner` and `salt`
    /// without creating anything — lets a caller compute their future
    /// `policyId` off-chain before submitting `createPolicy`.
    function computePolicyId(address owner, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(owner, salt));
    }

    /// @notice Derive the flattened storage key for a (target, selector)
    /// pair. Exposed so off-chain tooling and tests can compute it
    /// independently and confirm it matches on-chain behavior.
    function authorizedCallKey(address target, bytes4 selector) public pure returns (bytes32) {
        return keccak256(abi.encode(target, selector));
    }

    /// @notice Create a new, immutable policy owned by the caller and
    /// bound to exactly one `agent`. `calls` authorizes specific
    /// (target, selector) function-call pairs; `nativeTransferTargets`
    /// separately authorizes plain ETH transfers (empty calldata) to
    /// specific targets. At least one authorization of either kind is
    /// required — a policy authorizing nothing is a misconfiguration,
    /// not a valid "deny everything" policy (deny-everything is simply
    /// not creating a policy at all, or revoking one).
    ///
    /// Duplicate entries within `calls` (the same (target, selector)
    /// pair listed twice) or within `nativeTransferTargets` are harmless
    /// no-ops — the second write to the same storage slot has no
    /// additional effect — and are not rejected; requiring on-chain
    /// duplicate detection would need an O(n^2) scan for no security
    /// benefit.
    function createPolicy(
        bytes32 salt,
        address agent,
        uint128 maxTxValue,
        uint128 dailyLimit,
        uint128 approvalThreshold,
        uint64 validFrom,
        uint64 validUntil,
        AuthorizedCall[] calldata calls,
        address[] calldata nativeTransferTargets
    ) external returns (bytes32 policyId) {
        if (agent == address(0)) revert ZeroAddress();
        policyId = computePolicyId(msg.sender, salt);
        if (_mandates[policyId].owner != address(0)) revert PolicyAlreadyExists(policyId);
        if (validUntil <= validFrom) revert InvalidTimeWindow(validFrom, validUntil);
        if (calls.length == 0 && nativeTransferTargets.length == 0) revert EmptyAuthorization();

        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].target == address(0)) revert ZeroAddress();
            _authorizedCalls[policyId][authorizedCallKey(calls[i].target, calls[i].selector)] = true;
            emit CallAuthorized(policyId, calls[i].target, calls[i].selector);
        }
        for (uint256 i = 0; i < nativeTransferTargets.length; i++) {
            if (nativeTransferTargets[i] == address(0)) revert ZeroAddress();
            _authorizedNativeTransfer[policyId][nativeTransferTargets[i]] = true;
            emit NativeTransferAuthorized(policyId, nativeTransferTargets[i]);
        }

        _mandates[policyId] = Mandate({
            owner: msg.sender,
            agent: agent,
            active: true,
            maxTxValue: maxTxValue,
            dailyLimit: dailyLimit,
            approvalThreshold: approvalThreshold,
            validFrom: validFrom,
            validUntil: validUntil
        });

        bytes32 policyHash = keccak256(
            abi.encode(
                policyId,
                msg.sender,
                agent,
                maxTxValue,
                dailyLimit,
                approvalThreshold,
                validFrom,
                validUntil,
                keccak256(abi.encode(calls)),
                keccak256(abi.encode(nativeTransferTargets))
            )
        );
        policyHashOf[policyId] = policyHash;
        policyIdOfHash[policyHash] = policyId;

        emit PolicyCreated(policyId, msg.sender, agent, salt, policyHash);
    }

    /// @notice Revoke a policy. Only the owner may call this.
    function revokePolicy(bytes32 policyId) external {
        Mandate storage m = _mandates[policyId];
        if (m.owner == address(0)) revert PolicyNotFound(policyId);
        if (m.owner != msg.sender) revert NotPolicyOwner(policyId, msg.sender);
        if (!m.active) revert PolicyAlreadyInactive(policyId);
        m.active = false;
        emit PolicyRevoked(policyId, msg.sender);
    }

    /// @notice Reactivate a previously revoked policy. Only the owner
    /// may call this. Mandate values and all (target, selector) /
    /// native-transfer authorizations are untouched — reactivation
    /// cannot change what was originally committed to
    /// `policyHashOf[policyId]`.
    function reactivatePolicy(bytes32 policyId) external {
        Mandate storage m = _mandates[policyId];
        if (m.owner == address(0)) revert PolicyNotFound(policyId);
        if (m.owner != msg.sender) revert NotPolicyOwner(policyId, msg.sender);
        if (m.active) revert PolicyAlreadyActive(policyId);
        m.active = true;
        emit PolicyReactivated(policyId, msg.sender);
    }

    /// @notice [P1 fix] The single combined authorization check
    /// `AgentExecutionGuard.execute` uses. Takes a `policyHash` (as
    /// carried in a signed ExecutionIntent), the intent's `target`, a
    /// `callKind`/`selector` pair already classified by the Guard from
    /// the intent's actual calldata (see the `CallKind` NatSpec), and
    /// the intent's `value`. Returns every piece of information the
    /// Guard needs to produce a specific, auditable revert reason,
    /// rather than one opaque boolean:
    ///
    ///   owner        — the policy's immutably-recorded creator
    ///                  (`msg.sender` at `createPolicy` time). This
    ///                  contract makes NO claim that `owner` is the
    ///                  legitimate controller of `agent` — that
    ///                  relationship is verified LIVE by
    ///                  AgentExecutionGuard against AgentRegistry on
    ///                  every call. See
    ///                  docs/adr/0006-policy-owner-authorization.md.
    ///   agent        — the single agent this policy is bound to.
    ///   active       — the owner-controlled revoke/reactivate bit.
    ///   withinWindow — whether `block.timestamp` is inside
    ///                  [validFrom, validUntil].
    ///   valueAllowed — whether `value <= maxTxValue`.
    ///   callAllowed  — whether this exact (target, callKind, selector)
    ///                  was explicitly authorized at creation.
    ///
    /// A `Malformed` `callKind` always returns `callAllowed = false`
    /// without any storage read — see the `CallKind` NatSpec for why
    /// this must never fall through to a real mapping lookup.
    ///
    /// This is a single external call by design (see
    /// docs/adr/0005-paired-target-selector-authorization.md, "gas/DoS")
    /// rather than the Guard making several round trips.
    function checkAuthorization(bytes32 policyHash, address target, CallKind callKind, bytes4 selector, uint256 value)
        external
        view
        returns (address owner, address agent, bool active, bool withinWindow, bool valueAllowed, bool callAllowed)
    {
        bytes32 policyId = policyIdOfHash[policyHash];
        Mandate storage m = _mandates[policyId];

        owner = m.owner;
        agent = m.agent;
        active = m.active;
        withinWindow = (block.timestamp >= m.validFrom && block.timestamp <= m.validUntil);
        valueAllowed = (value <= m.maxTxValue);

        if (callKind == CallKind.NativeTransfer) {
            callAllowed = _authorizedNativeTransfer[policyId][target];
        } else if (callKind == CallKind.FunctionCall) {
            callAllowed = _authorizedCalls[policyId][authorizedCallKey(target, selector)];
        } else {
            callAllowed = false;
        }
    }

    function isCallAuthorized(bytes32 policyId, address target, bytes4 selector) external view returns (bool) {
        return _authorizedCalls[policyId][authorizedCallKey(target, selector)];
    }

    function isNativeTransferAuthorized(bytes32 policyId, address target) external view returns (bool) {
        return _authorizedNativeTransfer[policyId][target];
    }

    function getMandate(bytes32 policyId) external view returns (Mandate memory) {
        return _mandates[policyId];
    }

    function isPolicyActive(bytes32 policyId) external view returns (bool) {
        return _mandates[policyId].active;
    }

    function ownerOf(bytes32 policyId) external view returns (address) {
        return _mandates[policyId].owner;
    }

    function agentOf(bytes32 policyId) external view returns (address) {
        return _mandates[policyId].agent;
    }

    /// @notice [Remediation gate] Resolve a `policyHash` to the single
    /// agent it was created for and whether it is currently active.
    /// Returns `(address(0), false)` for any `policyHash` that was never
    /// produced by `createPolicy`. Retained alongside `checkAuthorization`
    /// for callers (or tests) that only need the agent-binding check
    /// without the Gate 4A mandate-content checks.
    function resolvePolicyBinding(bytes32 policyHash) external view returns (address agent, bool active) {
        bytes32 policyId = policyIdOfHash[policyHash];
        Mandate storage m = _mandates[policyId];
        return (m.agent, m.active);
    }
}
