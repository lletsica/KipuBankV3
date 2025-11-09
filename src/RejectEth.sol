// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;
contract RejectEth {
    receive() external payable {
        revert("No ETH accepted");
    }
}