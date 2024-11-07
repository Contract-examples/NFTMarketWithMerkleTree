// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../src/NFTMarket.sol";
import "../src/MyERC20PermitToken.sol";
import "../src/MyNFT.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract NFTMarketTest is Test, IERC20Errors {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    NFTMarket public market;
    MyERC20PermitToken public paymentToken;
    MyNFT public nftContract;

    address public owner;
    address public seller;
    address public buyer;
    address public whitelistBuyer;
    uint256 public whitelistBuyerPrivateKey;
    address public whitelistBuyer2;
    uint256 public whitelistBuyer2PrivateKey;
    address public whitelistBuyer3;
    uint256 public whitelistBuyer3PrivateKey;
    uint256 public tokenId;

    bytes32 merkleRoot;

    receive() external payable { }

    function setUp() public {
        owner = address(this);

        whitelistBuyerPrivateKey = 0x4489;
        whitelistBuyer = vm.addr(whitelistBuyerPrivateKey);
        whitelistBuyer2PrivateKey = 0x5589;
        whitelistBuyer2 = vm.addr(whitelistBuyer2PrivateKey);
        whitelistBuyer3PrivateKey = 0x6689;
        whitelistBuyer3 = vm.addr(whitelistBuyer3PrivateKey);

        paymentToken = new MyERC20PermitToken("MyNFTToken2612", "MTK2612", 1_000_000 * 10 ** 18);
        nftContract = new MyNFT("MyNFT", "MFT", 1000);

        // build the merkle tree
        address[] memory addresses = new address[](3);
        addresses[0] = whitelistBuyer;
        addresses[1] = whitelistBuyer2;
        addresses[2] = whitelistBuyer3;

        bytes32[] memory leaves = new bytes32[](addresses.length);
        for (uint256 i = 0; i < addresses.length; i++) {
            leaves[i] = keccak256(abi.encodePacked(addresses[i]));
        }

        // calculate the intermediate node hash01
        bytes32 hash01 = keccak256(
            abi.encodePacked(
                leaves[0] < leaves[1] ? leaves[0] : leaves[1], leaves[0] < leaves[1] ? leaves[1] : leaves[0]
            )
        );

        // calculate the root node
        bytes32 root = keccak256(
            abi.encodePacked(hash01 < leaves[2] ? hash01 : leaves[2], hash01 < leaves[2] ? leaves[2] : hash01)
        );
        merkleRoot = root;

        market = new NFTMarket(address(nftContract), address(paymentToken), merkleRoot);

        // mint tokens to the whitelist users
        paymentToken.mint(whitelistBuyer, 2000 * 10 ** paymentToken.decimals());
        paymentToken.mint(whitelistBuyer2, 2000 * 10 ** paymentToken.decimals());
        paymentToken.mint(whitelistBuyer3, 2000 * 10 ** paymentToken.decimals());

        seller = makeAddr("seller");
        buyer = makeAddr("buyer");

        paymentToken.mint(buyer, 20_000 * 10 ** paymentToken.decimals());

        paymentToken.mint(owner, 1000 * 10 ** 18);

        vm.prank(owner);
        nftContract.safeMint(seller, "ipfs://gmh-001");
    }

    function testClaimNFT() public {
        uint256 price = 100 * 10 ** paymentToken.decimals();
        uint256 tokenId = 0;
        uint256 deadline = block.timestamp + 1 hours;

        vm.startPrank(seller);
        nftContract.approve(address(market), tokenId);
        market.list(tokenId, price);
        vm.stopPrank();

        bytes32 permitHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                paymentToken.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        whitelistBuyer,
                        address(market),
                        price,
                        paymentToken.nonces(whitelistBuyer),
                        deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistBuyerPrivateKey, permitHash);

        uint256 sellerInitialBalance = paymentToken.balanceOf(seller);
        uint256 buyerInitialBalance = paymentToken.balanceOf(whitelistBuyer);

        vm.startPrank(whitelistBuyer);

        market.permitPrePay(price, deadline, v, r, s);

        assertEq(paymentToken.allowance(whitelistBuyer, address(market)), price);

        // build the merkle proof
        bytes32[] memory proof = getMerkleProof(whitelistBuyer);

        market.claimNFT(tokenId, proof);
        vm.stopPrank();

        assertEq(nftContract.ownerOf(tokenId), whitelistBuyer);
        assertEq(paymentToken.balanceOf(seller), sellerInitialBalance + (100 * 10 ** paymentToken.decimals()));
        assertEq(paymentToken.balanceOf(whitelistBuyer), buyerInitialBalance - (100 * 10 ** paymentToken.decimals()));
        (address listedSeller, uint256 listedPrice) = market.listings(tokenId);
        assertEq(listedSeller, address(0));
        assertEq(listedPrice, 0);

        assertEq(paymentToken.allowance(whitelistBuyer, address(market)), 0);
    }

    function testClaimNFTWhitelistBuyer2() public {
        uint256 price = 100 * 10 ** paymentToken.decimals();
        uint256 tokenId = 0;
        uint256 deadline = block.timestamp + 1 hours;

        vm.startPrank(seller);
        nftContract.approve(address(market), tokenId);
        market.list(tokenId, price);
        vm.stopPrank();

        bytes32 permitHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                paymentToken.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        whitelistBuyer2,
                        address(market),
                        price,
                        paymentToken.nonces(whitelistBuyer2),
                        deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistBuyer2PrivateKey, permitHash);

        uint256 sellerInitialBalance = paymentToken.balanceOf(seller);
        uint256 buyerInitialBalance = paymentToken.balanceOf(whitelistBuyer2);

        vm.startPrank(whitelistBuyer2);

        market.permitPrePay(price, deadline, v, r, s);

        assertEq(paymentToken.allowance(whitelistBuyer2, address(market)), price);

        bytes32[] memory proof = getMerkleProof(whitelistBuyer2);

        market.claimNFT(tokenId, proof);
        vm.stopPrank();

        assertEq(nftContract.ownerOf(tokenId), whitelistBuyer2);
        assertEq(paymentToken.balanceOf(seller), sellerInitialBalance + (100 * 10 ** paymentToken.decimals()));
        assertEq(paymentToken.balanceOf(whitelistBuyer2), buyerInitialBalance - (100 * 10 ** paymentToken.decimals()));
        (address listedSeller, uint256 listedPrice) = market.listings(tokenId);
        assertEq(listedSeller, address(0));
        assertEq(listedPrice, 0);

        assertEq(paymentToken.allowance(whitelistBuyer2, address(market)), 0);
    }

    function testClaimNFTWhitelistBuyer3() public {
        uint256 price = 100 * 10 ** paymentToken.decimals();
        uint256 tokenId = 0;
        uint256 deadline = block.timestamp + 1 hours;

        vm.startPrank(seller);
        nftContract.approve(address(market), tokenId);
        market.list(tokenId, price);
        vm.stopPrank();

        bytes32 permitHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                paymentToken.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        whitelistBuyer3,
                        address(market),
                        price,
                        paymentToken.nonces(whitelistBuyer3),
                        deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistBuyer3PrivateKey, permitHash);

        uint256 sellerInitialBalance = paymentToken.balanceOf(seller);
        uint256 buyerInitialBalance = paymentToken.balanceOf(whitelistBuyer3);

        vm.startPrank(whitelistBuyer3);

        market.permitPrePay(price, deadline, v, r, s);

        assertEq(paymentToken.allowance(whitelistBuyer3, address(market)), price);

        bytes32[] memory proof = getMerkleProof(whitelistBuyer3);

        market.claimNFT(tokenId, proof);
        vm.stopPrank();

        assertEq(nftContract.ownerOf(tokenId), whitelistBuyer3);
        assertEq(paymentToken.balanceOf(seller), sellerInitialBalance + (100 * 10 ** paymentToken.decimals()));
        assertEq(paymentToken.balanceOf(whitelistBuyer3), buyerInitialBalance - (100 * 10 ** paymentToken.decimals()));
        (address listedSeller, uint256 listedPrice) = market.listings(tokenId);
        assertEq(listedSeller, address(0));
        assertEq(listedPrice, 0);

        assertEq(paymentToken.allowance(whitelistBuyer3, address(market)), 0);
    }

    function getMerkleProof(address user) public view returns (bytes32[] memory) {
        // build the leaves
        address[] memory addresses = new address[](3);
        addresses[0] = whitelistBuyer;
        addresses[1] = whitelistBuyer2;
        addresses[2] = whitelistBuyer3;

        bytes32[] memory leaves = new bytes32[](addresses.length);
        for (uint256 i = 0; i < addresses.length; i++) {
            leaves[i] = keccak256(abi.encodePacked(addresses[i]));
        }

        // calculate the intermediate node hash01
        bytes32 hash01 = keccak256(
            abi.encodePacked(
                leaves[0] < leaves[1] ? leaves[0] : leaves[1], leaves[0] < leaves[1] ? leaves[1] : leaves[0]
            )
        );

        // calculate the root node
        bytes32 root = keccak256(
            abi.encodePacked(hash01 < leaves[2] ? hash01 : leaves[2], hash01 < leaves[2] ? leaves[2] : hash01)
        );

        // verify the root node
        require(root == market.merkleRoot(), "Merkle root mismatch");

        bytes32[] memory proof;

        if (user == whitelistBuyer) {
            proof = new bytes32[](2);
            proof[0] = leaves[1]; // sibling node
            proof[1] = leaves[2]; // next layer node
        } else if (user == whitelistBuyer2) {
            proof = new bytes32[](2);
            proof[0] = leaves[0]; // sibling node
            proof[1] = leaves[2]; // next layer node
        } else if (user == whitelistBuyer3) {
            proof = new bytes32[](1);
            proof[0] = hash01; // hash of the first two nodes
        } else {
            revert("User not in whitelist");
        }

        // print debug information
        console2.log("User address:", user);
        console2.log("Merkle root:", uint256(root));
        console2.log("Leaf hash:", uint256(keccak256(abi.encodePacked(user))));
        if (user != whitelistBuyer3) {
            console2.log("Proof[0]:", uint256(proof[0]));
            console2.log("Proof[1]:", uint256(proof[1]));
        } else {
            console2.log("Proof[0]:", uint256(proof[0]));
        }

        // verify the proof
        bytes32 computedHash = keccak256(abi.encodePacked(user));

        for (uint256 i = 0; i < proof.length; i++) {
            if (computedHash < proof[i]) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            }
        }

        require(computedHash == root, "Invalid merkle proof");

        return proof;
    }
}
