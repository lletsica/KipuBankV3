// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import {MockToken} from "../src/MockToken.sol";
import {MockToken} from "../src/MockToken.sol";

contract MockTokenTest is Test {
    MockToken token;
    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        token = new MockToken();
    }

    function testSetBalance() public {
        token.setBalance(alice, 1000);
        assertEq(token.balanceOf(alice), 1000);
    }

    function testSetAllowance() public {
        token.setAllowance(alice, bob, 500);
        assertEq(token.allowance(alice, bob), 500);
    }

    function testTransferAlwaysTrue() public view {
        bool success = token.transfer(bob, 100);
        assertTrue(success);
    }

    function testTransferFromUpdatesBalances() public {
        token.setBalance(alice, 1000);
        token.setAllowance(alice, address(this), 1000);
        bool success = token.transferFrom(alice, bob, 200);
        assertTrue(success);
        assertEq(token.balanceOf(alice), 800);
        assertEq(token.balanceOf(bob), 200);
    }

    function testApproveSetsAllowance() public {
        bool success = token.approve(bob, 300);
        assertTrue(success);
        assertEq(token.allowance(address(this), bob), 300);
    }

    function testTotalSupplyIsZero() public view {
        assertEq(token.totalSupply(), 0);
    }

    function testDecimalsIsSix() public view {
        assertEq(token.decimals(), 6);
    }

    function testNameIsMockToken() public view {
        assertEq(token.name(), "MockToken");
    }

    function testSymbolIsMOCK() public view {
        assertEq(token.symbol(), "MOCK");
    }
}