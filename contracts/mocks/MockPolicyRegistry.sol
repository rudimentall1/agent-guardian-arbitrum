// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IPolicyRegistry} from "../interfaces/IPolicyRegistry.sol";

/// @notice TEST-ONLY mock. Lets AgentExecutionGuard tests set an
/// arbitrary policyHash -> (owner, agent, active, withinWindow,
/// maxTxValue, authorized calls) binding directly, instead of going
/// through the real PolicyRegistry's full creation flow, which is
/// orthogonal to what AgentExecutionGuard's own tests are checking. Real
/// PolicyRegistry wiring (including the P1 owner-authorization fix) is
/// covered separately by
/// contracts-test/AgentExecutionGuard.remediation.test.ts,
/// contracts-test/AgentExecutionGuard.gate4a.test.ts, and
/// contracts-test/P1PolicyOwnerAuthorization.poc.test.ts. Not part of
/// any deployment.
contract MockPolicyRegistry is IPolicyRegistry {
    struct Binding {
        address owner;
        address agent;
        bool active;
        bool withinWindow;
        uint256 maxTxValue;
    }

    mapping(bytes32 => Binding) private _bindings;
    mapping(bytes32 => mapping(bytes32 => bool)) private _authorizedCalls;
    mapping(bytes32 => mapping(address => bool)) private _authorizedNativeTransfer;

    /// @notice Convenience setter for tests that don't care about the
    /// P1 owner-authorization check — sets `owner == agent`, so callers
    /// wiring up a matching `MockAgentRegistry.setOwner(agent, agent)`
    /// (or simply relying on `MockAgentRegistry`'s own `ownerOf` default
    /// — see that mock's NatSpec) will pass the owner check without
    /// needing to think about it. Tests that DO care about the P1 check
    /// should use `setFullBinding` instead, with an explicit owner.
    function setBinding(bytes32 policyHash, address agent, bool active) external {
        _bindings[policyHash].owner = agent;
        _bindings[policyHash].agent = agent;
        _bindings[policyHash].active = active;
        _bindings[policyHash].withinWindow = true;
        _bindings[policyHash].maxTxValue = type(uint256).max;
    }

    function setFullBinding(
        bytes32 policyHash,
        address owner,
        address agent,
        bool active,
        bool withinWindow,
        uint256 maxTxValue
    ) external {
        _bindings[policyHash] =
            Binding({owner: owner, agent: agent, active: active, withinWindow: withinWindow, maxTxValue: maxTxValue});
    }

    function authorizeCall(bytes32 policyHash, address target, bytes4 selector) external {
        _authorizedCalls[policyHash][keccak256(abi.encode(target, selector))] = true;
    }

    function authorizeNativeTransfer(bytes32 policyHash, address target) external {
        _authorizedNativeTransfer[policyHash][target] = true;
    }

    function checkAuthorization(bytes32 policyHash, address target, CallKind callKind, bytes4 selector, uint256 value)
        external
        view
        returns (address owner, address agent, bool active, bool withinWindow, bool valueAllowed, bool callAllowed)
    {
        Binding storage b = _bindings[policyHash];
        owner = b.owner;
        agent = b.agent;
        active = b.active;
        withinWindow = b.withinWindow;
        valueAllowed = value <= b.maxTxValue;

        if (callKind == CallKind.NativeTransfer) {
            callAllowed = _authorizedNativeTransfer[policyHash][target];
        } else if (callKind == CallKind.FunctionCall) {
            callAllowed = _authorizedCalls[policyHash][keccak256(abi.encode(target, selector))];
        } else {
            callAllowed = false;
        }
    }
}
