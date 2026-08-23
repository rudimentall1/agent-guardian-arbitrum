// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title IPolicyRegistry
/// @notice The only PolicyRegistry surface AgentExecutionGuard depends
/// on for this remediation gate: resolving which single agent a
/// `policyHash` was created for, and whether that policy is currently
/// active. Deliberately does NOT expose `maxTxValue`/target/selector or
/// spend-limit fields — consulting those for real enforcement is Gate 4
/// scope, not this remediation.
interface IPolicyRegistry {
    /// @notice Resolve a `policyHash` (as referenced by a signed
    /// ExecutionIntent) to the single agent it was created for, and
    /// whether it is currently active. Returns `(address(0), false)` for
    /// any `policyHash` that does not correspond to a real policy.
    function resolvePolicyBinding(bytes32 policyHash) external view returns (address agent, bool active);
}
