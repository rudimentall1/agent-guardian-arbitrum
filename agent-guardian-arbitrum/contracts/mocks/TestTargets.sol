// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice TEST-ONLY mock target. Records every call it receives and its
/// received value, so tests can assert the guard forwarded exactly what
/// the intent authorized. Not part of any deployment.
contract RecordingTarget {
    struct Call {
        bytes data;
        uint256 value;
    }

    Call[] public calls;

    function callCount() external view returns (uint256) {
        return calls.length;
    }

    receive() external payable {
        calls.push(Call({data: "", value: msg.value}));
    }

    fallback() external payable {
        calls.push(Call({data: msg.data, value: msg.value}));
    }
}

/// @notice TEST-ONLY mock target that always reverts, for the "failed
/// external call" attack scenario. Not part of any deployment.
contract AlwaysRevertingTarget {
    error AlwaysReverts();

    receive() external payable {
        revert AlwaysReverts();
    }

    fallback() external payable {
        revert AlwaysReverts();
    }
}

/// @notice TEST-ONLY mock target exposing a couple of distinctly-named,
/// distinctly-selectored functions, for Gate 4A target/selector
/// authorization tests that need real >=4-byte calldata (as opposed to
/// RecordingTarget's fallback-driven, selector-agnostic recording). Not
/// part of any deployment.
contract SelectorTarget {
    event Foo(uint256 value);
    event Bar(address value);

    uint256 public fooCallCount;
    uint256 public barCallCount;

    function foo(uint256) external payable {
        fooCallCount++;
        emit Foo(fooCallCount);
    }

    function bar(address) external {
        barCallCount++;
        emit Bar(msg.sender);
    }
}
