# NFT Market with merkle tree


## Test
```
forge test --match-test=testPermitBuy -vv
```

## Test result
```
Ran 2 tests for test/NFTMarket.t.sol:NFTMarketTest
[PASS] testPermitBuy() (gas: 282444)
Logs:
  Index: 0, Minted NFT with ID: 0
  NFT owner: seller
  Index: 0, Minted NFT with ID: 1
  NFT owner: seller2
  Index: 0, Minted NFT with ID: 2
  NFT owner: seller3
  messageHash: 0x2b7b88ac920b789994b632f390a6a22d7229d5d1b439284283056c1703df6432
  ethSignedMessageHash: 0xf8b99a7f0b51c47e2b7d597d06aeddd68cedb55eea402112a0bba8ec7d03638b
  v1: 0x1b
  r1: 0xc9f771fb1640b5868cbc09c27df8d81a08859c076d57d0d438e8df1e20412e97
  s1: 0x5e85a1e5d5c9cabdc20bf822a024b5819f86721447cdfd082741569d88a8a045
  whitelistSignature:
  0xc9f771fb1640b5868cbc09c27df8d81a08859c076d57d0d438e8df1e20412e975e85a1e5d5c9cabdc20bf822a024b5819f86721447cdfd082741569d88a8a0451b   
  permitHash: 0xcc01164f54e675b22910bd2ba4e3c74a0eead6c6b787886397728191d0ac278f
  v2: 0x1c
  r2: 0x3b8e9f36db7eebca74898e68df602b7da6bcd34267794e079a07f9f7c1d8a0c2
  s2: 0x3d8ff5bba9b2807b286b8af3bce202e91337d04b78a27d8ed3061f91a56c5179
  listingSeller: NaN
  listingPrice: 0

[PASS] testPermitBuyNotWhitelisted() (gas: 131418)
Logs:
  Index: 0, Minted NFT with ID: 0
  NFT owner: seller
  Index: 0, Minted NFT with ID: 1
  NFT owner: seller2
  Index: 0, Minted NFT with ID: 2
  NFT owner: seller3

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 3.41ms (2.67ms CPU time)
```

## Deploy MyERC20Token/MyNFT
```
forge script script/DeployMyERC20PermitToken.s.sol:DeployMyERC20PermitTokenScript --rpc-url arbitrum_sepolia --broadcast --verify -vvvv
forge script script/DeployMyNFT.s.sol:DeployMyNFT --rpc-url arbitrum_sepolia --broadcast --verify -vvvv
```
## Deploy result
```
https://sepolia.arbiscan.io/address/0x6343c4a548F5f75b47Cdd1A52a52eF89bC29A5eB
MyERC20Token address: 0x6343c4a548F5f75b47Cdd1A52a52eF89bC29A5eB

https://sepolia.arbiscan.io/address/0x32eCC13478b2d03b212AE7b371F5f3C18490Bc9d
NFT address: 0x32eCC13478b2d03b212AE7b371F5f3C18490Bc9d
```

## Deploy NFTMarket
```
forge script script/DeployNFTMarket.s.sol:DeployNFTMarket --rpc-url arbitrum_sepolia --broadcast --verify -vvvv
```

## Deploy result
```
https://sepolia.arbiscan.io/address/0x98A566801FF66d156971ADa3f6D729eFBABD67Ca
NFTMarket addresas: 0x98A566801FF66d156971ADa3f6D729eFBABD67Ca
```

## Mint NFT
```
forge script script/MintMyNFT.s.sol:MintMyNFT --rpc-url arbitrum_sepolia --broadcast -vvvv
```
## Mint result
```
https://testnets.opensea.io/assets/arbitrum-sepolia/0x32ecc13478b2d03b212ae7b371f5f3c18490bc9d/0
https://testnets.opensea.io/assets/arbitrum-sepolia/0x32ecc13478b2d03b212ae7b371f5f3c18490bc9d/1
```

## List NFT on NFT market
```
forge script script/ListNFTOnMarket.s.sol:ListNFTOnMarketScript --rpc-url arbitrum_sepolia --broadcast -vvvv
```
## result of "List NFT on NFT market"
```
txhash: https://sepolia.arbiscan.io/tx/0x23b15bce21238da83cd3ebafd5572a1a3a838959a30c0330d4df4916a2eabdd4
```

## Query NFT market
```
forge script script/QueryNFTMarket.s.sol:QueryNFTMarketScript --rpc-url arbitrum_sepolia --broadcast -vvvv
```
## result of "Query NFT market"
```
== Logs ==
  NFTs listed on the market:
  ----------------------------
  Token ID: 1
  Price: 100000000000000000000
  Seller: 0x059dC4EEe9328A9f163a7e813B2f5B4A52ADD4dF
  Current Owner: 0x059dC4EEe9328A9f163a7e813B2f5B4A52ADD4dF
  ----------------------------
```

## Buy NFT via whitelist on NFT market
```
forge script script/BuyNFTPermitAndQueryMarket.s.sol:BuyNFTPermitAndQueryMarketScript --rpc-url arbitrum_sepolia --broadcast -vvvv
```
## result of "Buy NFT via whitelist on NFT market"
```
== Logs ==
  whitelistBuyer: 0xe091701ac9816d38241887147b41ae312d26e1c3
  whitelistSigner: 0x059dc4eee9328a9f163a7e813b2f5b4a52add4df
  NFT seller: 0x059dC4EEe9328A9f163a7e813B2f5B4A52ADD4dF
  NFT price: 100000000000000000000
  messageHash: 0xfb0a341a7ebde5cde457ec03f6699e69cd1244a0bbccef4f3aefad756c43510f
  ethSignedMessageHash: 0x0e93b1d93932ec737f4442a29f0a4c539254444bc357d606a20fe35ff3a33a89
  v1: 0x1b
  r1: 0xc8fe53fcbb20d0699f21c7b14edea0aa198e89c13b159e73f71fb9d617b23035
  s1: 0x0b58b7ed813c8d3e55626f5ffb39ad1e0b1939ec302f32c748dc048ae481f44a
  whitelistSignature:
  0xc8fe53fcbb20d0699f21c7b14edea0aa198e89c13b159e73f71fb9d617b230350b58b7ed813c8d3e55626f5ffb39ad1e0b1939ec302f32c748dc048ae481f44a1b     
  permitHash: 0x892d53b7ffb467b9944597ae9a4f498bc321b80b3372bf16e94a332870a44eac
  v2: 0x1b
  r2: 0xe5c8480dd74079d25e1747eaec71a50150dc7a7775f3a43f98cf5553df2f612f
  s2: 0x12143427c2f1532410396ba3cd2d4ca87a91bba39b8077a4b03504f54a8cbb00
  Transaction successful
  NFT purchased:
  whitelistBuyer: 0xe091701aC9816D38241887147B41AE312d26e1C3
  Token ID: 1
  Price paid: 100000000000000000000

Current NFT Market status:
  ----------------------------
https://sepolia.arbiscan.io/tx/0x8b1c134045325a311883e490727140f27e46635f0f51614960ec34ec713c4f5d
https://testnets.opensea.io/assets/arbitrum-sepolia/0x32ecc13478b2d03b212ae7b371f5f3c18490bc9d/1
```


