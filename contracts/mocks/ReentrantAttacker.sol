// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice TEST-ONLY malicious target. When called by AgentExecutionGuard
/// as `target`, attempts to call back into the guard using calldata
/// prepared off-chain by the test (a fully-formed `execute(...)` call for
/// some other, or the same, intent). This lets tests exercise same-nonce
/// reentrancy, different-nonce reentrancy, and cross-agent reentrancy
/// without the guard's Solidity needing any test-specific hooks. Not part
/// of any deployment.
contract ReentrantAttacker {
    address public guard;
    bytes public reentryCalldata;
    bool public reentered;
    bool public reentrySucceeded;
    bytes public reentryReturnData;

    function setGuard(address guard_) external {
        guard = guard_;
    }

    function setReentryCalldata(bytes calldata data) external {
        reentryCalldata = data;
    }

    receive() external payable {
        _attempt();
    }

    fallback() external payable {
        _attempt();
    }

    function _attempt() internal {
        if (reentryCalldata.length == 0 || reentered) return;
        reentered = true;
        (bool ok, bytes memory ret) = guard.call(reentryCalldata);
        reentrySucceeded = ok;
        reentryReturnData = ret;
    }
}
