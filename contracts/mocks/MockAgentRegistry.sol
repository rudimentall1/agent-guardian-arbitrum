// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IAgentRegistry} from "../interfaces/IAgentRegistry.sol";

/// @notice TEST-ONLY mock. Lets Gate 2 tests toggle agent activity
/// directly instead of going through the real AgentRegistry's
/// EIP-712-signed registration flow, which is orthogonal to what Gate 2
/// is testing. `contracts-test/AgentExecutionGuard.integration.test.ts`
/// covers the real AgentRegistry wiring separately. Not part of any
/// deployment.
contract MockAgentRegistry is IAgentRegistry {
    mapping(address => bool) private _active;

    function setActive(address agent, bool active_) external {
        _active[agent] = active_;
    }

    function isActiveAgent(address agent) external view returns (bool) {
        return _active[agent];
    }
}
