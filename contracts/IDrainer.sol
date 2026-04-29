// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IDrainer {
    function attack(uint256 _guess, uint256 _round, uint256 _nonce) external payable;
    function distribute() external;
}
