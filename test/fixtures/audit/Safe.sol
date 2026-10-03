// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Safe {
    mapping(address => uint256) public balances;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function ping() external view returns (uint256) {
        return block.number;
    }
}
