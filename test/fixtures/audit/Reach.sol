// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Base {
    address internal target;

    function setTarget(address t) public {
        target = t;
    }

    function run() external {
        execute();
    }

    function execute() internal {
        target.delegatecall("");
    }

    function orphan() internal {
        target.delegatecall("");
    }
}

contract Child is Base {
    function execute2() internal {
        target.delegatecall("");
    }

    function kick() external {
        execute2();
    }
}
