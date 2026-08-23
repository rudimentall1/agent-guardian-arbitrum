// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title IAgentRegistry
/// @notice The only Gate 1 surface Gate 2 depends on. Kept intentionally
/// minimal so the Execution Guard's compiled bytecode does not change if
/// AgentRegistry gains unrelated functionality later — only a change to
/// this one function's semantics should ever require touching Gate 2.
interface IAgentRegistry {
    /// @notice True only if `agent` is registered AND currently active.
    function isActiveAgent(address agent) external view returns (bool);
}
