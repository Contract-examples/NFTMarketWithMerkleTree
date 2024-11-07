// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import "../src/NFTMarket.sol";
import "../src/MyNFT.sol";
import "../src/MyERC20PermitToken.sol";

contract DeployNFTMarket is Script {
    function run() external {
        //TODO encrypt private key
        uint256 deployerPrivateKey = vm.envUint("SEPOLIA_WALLET_PRIVATE_KEY");
        address deployerAddress = vm.addr(deployerPrivateKey);

        // replace your nft contract address
        address nftAddress = 0x32eCC13478b2d03b212AE7b371F5f3C18490Bc9d;

        // replace your payment token contract address
        address tokenAddress = 0x6343c4a548F5f75b47Cdd1A52a52eF89bC29A5eB;

        vm.startBroadcast(deployerPrivateKey);

        NFTMarket market = new NFTMarket(nftAddress, tokenAddress);

        vm.stopBroadcast();

        console2.log("NFTMarket deployed to:", address(market));
        console2.log("NFT contract address:", nftAddress);
        console2.log("Payment token address:", address(market.paymentToken()));
        console2.log("Deployed by:", deployerAddress);
    }
}
