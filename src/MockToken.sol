// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockToken is IERC20 {
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    function setBalance(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    function setAllowance(
        address owner,
        address spender,
        uint256 amount
    ) external {
        allowance[owner][spender] = amount;
    }

    function transfer(address, uint256) external pure override returns (bool) {
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(
        address spender,
        uint256 amount
    ) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function totalSupply() external pure override returns (uint256) {
        return 0;
    }

    function decimals() external pure returns (uint8) {
        return 6;
    }

    function name() external pure returns (string memory) {
        return "MockToken";
    }

    function symbol() external pure returns (string memory) {
        return "MOCK";
    }
}
