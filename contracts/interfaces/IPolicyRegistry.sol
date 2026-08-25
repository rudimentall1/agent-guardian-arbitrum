// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title IPolicyRegistry
/// @notice The only PolicyRegistry surface AgentExecutionGuard depends
/// on. `checkAuthorization` is a single combined view call: it resolves
/// the policy-agent binding, the policy's active/time-window state, the
/// maxTxValue check, and the paired (target, selector) — or native-
/// transfer — authorization check, all in one external call so the
/// Guard never needs more than one round trip per intent regardless of
/// how many mandate dimensions Gate 4A/4B eventually add. Deliberately
/// does NOT expose `dailyLimit`/`approvalThreshold` — accounting against
/// those remains out of scope (Gate 4B).
interface IPolicyRegistry {
    /// @dev Mirrors PolicyRegistry.CallKind. Solidity enums are not
    /// shared between separate contracts by reference, only by having
    /// the identical definition in both places — this interface's
    /// definition and PolicyRegistry's must be kept in exact sync
    /// (same member order), which contracts-test/PolicyRegistry.test.ts
    /// and the Gate 4A adversarial suite both verify indirectly by
    /// exercising every CallKind value end-to-end through both contracts
    /// together.
    enum CallKind {
        NativeTransfer,
        FunctionCall,
        Malformed
    }

    /// @notice Resolve everything AgentExecutionGuard needs to decide
    /// whether `policyHash` authorizes calling `target` with calldata of
    /// the given `callKind`/`selector` classification and `value`.
    /// `owner` is the policy's immutably-recorded creator — [P1 fix]
    /// AgentExecutionGuard checks this LIVE against
    /// `IAgentRegistry.ownerOf(intent.agent)` on every call; it is never
    /// trusted on its own. See
    /// docs/adr/0006-policy-owner-authorization.md.
    function checkAuthorization(bytes32 policyHash, address target, CallKind callKind, bytes4 selector, uint256 value)
        external
        view
        returns (address owner, address agent, bool active, bool withinWindow, bool valueAllowed, bool callAllowed);
}
