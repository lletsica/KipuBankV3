// SPDX-License-Identifier: UNLICENCED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {KipuBankV3} from "../src/KipuBankV3.sol";
/**
 * @title DeployKipuBankV3
 * @notice Script to deploy the KipuBankV3 contract with predefined parameters on a live or test network.
 * @dev Uses Foundry's scripting environment with `vm.startBroadcast()` to broadcast the transaction.
 */
contract DeployKipuBankV3 is Script {
    uint256 constant BANK_CAP = 100 ether;
    uint256 constant MAX_WITHDRAWAL = 5 ether;
    uint8 constant USDC_DECIMALS = 6;

    function run() external returns (KipuBankV3) {
        KipuBankV3 kipuBankV3;
        address _usdcAddress = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
        address _priceFeedAddress = address(0x694AA1769357215DE4FAC081bf1f309aDC325306);
        address _uniswapRouter = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        vm.startBroadcast();
        kipuBankV3 = new KipuBankV3(BANK_CAP,MAX_WITHDRAWAL,_usdcAddress,_priceFeedAddress, USDC_DECIMALS,_uniswapRouter);
        vm.stopBroadcast();
        return kipuBankV3;
    }

}