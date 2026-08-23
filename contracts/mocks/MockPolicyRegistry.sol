// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IPolicyRegistry} from "../interfaces/IPolicyRegistry.sol";

/// @notice TEST-ONLY mock. Lets AgentExecutionGuard tests set an
/// arbitrary policyHash -> (agent, active) binding directly, instead of
/// going through the real PolicyRegistry's full creation flow, which is
/// orthogonal to what AgentExecutionGuard's own tests are checking.
/// contracts-test/PolicyRegistry.integration.test.ts (remediation gate)
/// covers the real PolicyRegistry wiring separately. Not part of any
/// deployment.
contract MockPolicyRegistry is IPolicyRegistry {
    mapping(bytes32 => address) private _agent;
    mapping(bytes32 => bool) private _active;

    function setBinding(bytes32 policyHash, address agent, bool active) external {
        _agent[policyHash] = agent;
        _active[policyHash] = active;
    }

    function resolvePolicyBinding(bytes32 policyHash) external view returns (address agent, bool active) {
        return (_agent[policyHash], _active[policyHash]);
    }
}
