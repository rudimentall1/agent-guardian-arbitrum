// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title IPolicyRegistry
/// @notice Policy authorization and immutable mandate configuration consumed by AgentExecutionGuard.
interface IPolicyRegistry {
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

    function checkAuthorization(bytes32 policyHash, address target, CallKind callKind, bytes4 selector, uint256 value)
        external
        view
        returns (address owner, address agent, bool active, bool withinWindow, bool valueAllowed, bool callAllowed);

    function getMandate(bytes32 policyId) external view returns (Mandate memory);
    function policyIdOfHash(bytes32 policyHash) external view returns (bytes32);
}
