// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IPolicyRegistry} from "../interfaces/IPolicyRegistry.sol";

contract MockPolicyRegistry is IPolicyRegistry {
    struct Binding {
        address owner;
        address agent;
        bool active;
        bool withinWindow;
        uint256 maxTxValue;
        uint128 dailyLimit;
        uint128 approvalThreshold;
    }

    mapping(bytes32 => Binding) private _bindings;
    mapping(bytes32 => mapping(bytes32 => bool)) private _authorizedCalls;
    mapping(bytes32 => mapping(address => bool)) private _authorizedNativeTransfer;

    function setBinding(bytes32 policyHash, address agent, bool active) external {
        _bindings[policyHash] = Binding({
            owner: agent,
            agent: agent,
            active: active,
            withinWindow: true,
            maxTxValue: type(uint256).max,
            dailyLimit: type(uint128).max,
            approvalThreshold: type(uint128).max
        });
    }

    function setFullBinding(
        bytes32 policyHash,
        address owner,
        address agent,
        bool active,
        bool withinWindow,
        uint256 maxTxValue
    ) external {
        _bindings[policyHash] = Binding({
            owner: owner,
            agent: agent,
            active: active,
            withinWindow: withinWindow,
            maxTxValue: maxTxValue,
            dailyLimit: type(uint128).max,
            approvalThreshold: type(uint128).max
        });
    }

    function setSpendingPolicy(bytes32 policyHash, uint128 dailyLimit, uint128 approvalThreshold) external {
        _bindings[policyHash].dailyLimit = dailyLimit;
        _bindings[policyHash].approvalThreshold = approvalThreshold;
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

    function getMandate(bytes32 policyId) external view returns (Mandate memory) {
        Binding storage b = _bindings[policyId];
        return Mandate({
            owner: b.owner,
            agent: b.agent,
            active: b.active,
            maxTxValue: b.maxTxValue > type(uint128).max ? type(uint128).max : uint128(b.maxTxValue),
            dailyLimit: b.dailyLimit,
            approvalThreshold: b.approvalThreshold,
            validFrom: 0,
            validUntil: type(uint64).max
        });
    }

    function policyIdOfHash(bytes32 policyHash) external pure returns (bytes32) {
        return policyHash;
    }
}
