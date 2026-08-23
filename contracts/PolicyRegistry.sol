// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title PolicyRegistry
/// @notice Gate 3: on-chain storage and commitment for financial
/// mandates. A mandate is the maximum authority a wallet owner delegates
/// under a given policy — allowed target contracts, allowed function
/// selectors, a per-transaction value cap, and an active time window.
///
/// Design decisions and why:
///
/// 1. A policy is immutable once created. There is deliberately no
///    "update mandate parameters in place" function — only `revoke` and
///    `reactivate`, which flip a single `active` bit and change nothing
///    else. This follows directly from docs/protocol-spec.md section 4:
///    "changing policy does not silently change the meaning of an
///    already signed intent." If mandate values could be mutated under
///    an existing `policyId`, an owner could sign a narrow, reviewed
///    mandate, let an agent's operator countersign intents against its
///    `policyHash`, then quietly widen the mandate under the same hash.
///    A new mandate is a new `policyId` with its own `policyHash`,
///    full stop.
///
/// 2. `allowedTargets` / `allowedSelectors` are explicit allow-lists,
///    fixed at creation. There is no "allow all" wildcard. An empty list
///    means nothing is allowed under that dimension — fail closed, not
///    fail open.
///
/// 3. `dailyLimit` and `approvalThreshold` are stored as declared limits
///    only. This contract does NOT track cumulative spend against them —
///    that requires execution-time state (what has actually been spent,
///    and when "today" resets) which belongs with whatever contract
///    actually executes transactions against a mandate. Tracking it here
///    would mean two contracts independently guessing at the same
///    accounting, which is a correctness hazard, not a security feature.
///    See docs/gate-3-policy-registry.md for what this gate does and
///    does not enforce.
///
/// 4. No ownership transfer. A policy's `owner` is fixed at creation.
///    An abandoned or misconfigured policy is revoked and superseded by
///    a freshly created one under the correct owner — the same
///    deliberate non-goal as AgentRegistry's lack of agent-address
///    reassignment (see AgentRegistry's NatSpec, point 3).
///
/// 5. The on-chain policy identifier is `keccak256(abi.encode(owner,
///    salt))`, derived automatically from the caller's own address and a
///    caller-chosen `salt`, not taken as a raw caller-supplied key. A
///    raw caller-supplied global identifier (as in earlier drafts of
///    this contract) would let one owner front-run another's expected
///    `policyId` to deny them that slot — a real griefing vector, unlike
///    AgentRegistry's agent-address identity, where squatting requires
///    the squatter to actually control the corresponding private key.
///    Deriving the identifier from `(owner, salt)` makes that collision
///    structurally impossible rather than merely discouraged by
///    convention: only `owner` can ever produce their own identifiers,
///    for any `salt` they choose.
///
/// 6. [Remediation gate] Every policy is bound to exactly one `agent` at
///    creation, immutably, alongside its `owner`. Before this gate,
///    `policyHash` was an opaque commitment with no recorded relationship
///    to any specific agent — nothing stopped Agent A's signed intent
///    from referencing a policy that was conceptually meant only for
///    Agent B, because no contract anywhere checked which agent a policy
///    "belonged to" in the first place. `resolvePolicyBinding` exposes
///    this relationship for `AgentExecutionGuard` to enforce. See
///    docs/adr/0004-msg-value-and-policy-agent-binding.md.
contract PolicyRegistry {
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
    mapping(bytes32 => mapping(address => bool)) private _allowedTargets;
    mapping(bytes32 => mapping(bytes4 => bool)) private _allowedSelectors;

    event PolicyCreated(bytes32 indexed policyId, address indexed owner, address indexed agent, bytes32 salt, bytes32 policyHash);
    event PolicyRevoked(bytes32 indexed policyId, address indexed owner);
    event PolicyReactivated(bytes32 indexed policyId, address indexed owner);

    error PolicyAlreadyExists(bytes32 policyId);
    error PolicyNotFound(bytes32 policyId);
    error NotPolicyOwner(bytes32 policyId, address caller);
    error PolicyAlreadyActive(bytes32 policyId);
    error PolicyAlreadyInactive(bytes32 policyId);
    error InvalidTimeWindow(uint64 validFrom, uint64 validUntil);
    error ZeroAddress();
    error EmptyAllowLists();

    /// @notice Derive the policy identifier for `owner` and `salt`
    /// without creating anything — lets a caller compute their future
    /// `policyId` off-chain before submitting `createPolicy`.
    function computePolicyId(address owner, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(owner, salt));
    }

    /// @notice Create a new, immutable policy owned by the caller and
    /// bound to exactly one `agent`. The identifier is derived as
    /// `computePolicyId(msg.sender, salt)` — see contract-level NatSpec,
    /// point 5. Reverts if that identifier has ever been used before,
    /// regardless of its prior active state (same exactly-once semantics
    /// as AgentRegistry.register).
    function createPolicy(
        bytes32 salt,
        address agent,
        uint128 maxTxValue,
        uint128 dailyLimit,
        uint128 approvalThreshold,
        uint64 validFrom,
        uint64 validUntil,
        address[] calldata allowedTargets,
        bytes4[] calldata allowedSelectors
    ) external returns (bytes32 policyId) {
        if (agent == address(0)) revert ZeroAddress();
        policyId = computePolicyId(msg.sender, salt);
        if (_mandates[policyId].owner != address(0)) revert PolicyAlreadyExists(policyId);
        if (validUntil <= validFrom) revert InvalidTimeWindow(validFrom, validUntil);
        if (allowedTargets.length == 0 || allowedSelectors.length == 0) revert EmptyAllowLists();

        for (uint256 i = 0; i < allowedTargets.length; i++) {
            if (allowedTargets[i] == address(0)) revert ZeroAddress();
            _allowedTargets[policyId][allowedTargets[i]] = true;
        }
        for (uint256 i = 0; i < allowedSelectors.length; i++) {
            _allowedSelectors[policyId][allowedSelectors[i]] = true;
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
                keccak256(abi.encode(allowedTargets)),
                keccak256(abi.encode(allowedSelectors))
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
    /// may call this. Mandate values are untouched — reactivation cannot
    /// change what was originally committed to `policyHashOf[policyId]`.
    function reactivatePolicy(bytes32 policyId) external {
        Mandate storage m = _mandates[policyId];
        if (m.owner == address(0)) revert PolicyNotFound(policyId);
        if (m.owner != msg.sender) revert NotPolicyOwner(policyId, msg.sender);
        if (m.active) revert PolicyAlreadyActive(policyId);
        m.active = true;
        emit PolicyReactivated(policyId, msg.sender);
    }

    /// @notice Static mandate check: is `target`/`selector`/`value`
    /// within this policy's declared authority right now? Does NOT check
    /// cumulative daily spend or approval-threshold routing — those
    /// require execution-time state this contract does not hold. See
    /// contract-level NatSpec, point 3.
    function isCallAllowedByPolicy(bytes32 policyId, address target, bytes4 selector, uint256 value)
        external
        view
        returns (bool)
    {
        Mandate storage m = _mandates[policyId];
        if (m.owner == address(0) || !m.active) return false;
        if (block.timestamp < m.validFrom || block.timestamp > m.validUntil) return false;
        if (value > m.maxTxValue) return false;
        if (!_allowedTargets[policyId][target]) return false;
        if (!_allowedSelectors[policyId][selector]) return false;
        return true;
    }

    function isTargetAllowed(bytes32 policyId, address target) external view returns (bool) {
        return _allowedTargets[policyId][target];
    }

    function isSelectorAllowed(bytes32 policyId, bytes4 selector) external view returns (bool) {
        return _allowedSelectors[policyId][selector];
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

    /// @notice [Remediation gate] Resolve a `policyHash` — as carried in
    /// a signed ExecutionIntent — to the single agent it was created for
    /// and whether it is currently active. Returns `(address(0), false)`
    /// for any `policyHash` that was never produced by `createPolicy`.
    /// This is the exact surface `AgentExecutionGuard` needs to enforce
    /// "an intent's policy must belong to that same agent" without
    /// exposing mandate content (`maxTxValue`, allow-lists, spend limits)
    /// that remains out of scope until Gate 4.
    function resolvePolicyBinding(bytes32 policyHash) external view returns (address agent, bool active) {
        bytes32 policyId = policyIdOfHash[policyHash];
        Mandate storage m = _mandates[policyId];
        return (m.agent, m.active);
    }
}
