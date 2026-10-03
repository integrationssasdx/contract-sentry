// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    function setImplementation(address impl) external {
        implementation = impl;
    }

    function forward(address target, bytes memory data) external {
        target.delegatecall(data);
    }

    function upgrade() external {
        implementation.delegatecall(msg.data);
    }

    function payout(address payable to, uint256 amount) external {
        to.call{value: amount}("");
        balances[to] -= amount;
    }

    function sendAll(address payable to) external {
        to.send(address(this).balance);
    }
}
