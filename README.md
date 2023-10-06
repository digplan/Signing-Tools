# Simplesign

Sign and verify messages with public/private keys.  Compatible with bitcoin addresses and private WIF format.    

````
const simpsign = require('simplesign')

const pair1 = simpsign.newKeysFromWords('RANDOM WORDS SELECT MORE RANDOM WORDS THAN THESE')
const pair2 = simpsign.newKeysfromPrivateKey('0C28FCA386C7A227600B2FE50B7CAE1EC86D3BF1FBE471BE89827E19D72AA1D')
const pair3 = simpsign.newKeysFromWIF('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
const pair4 = simpsign.newKeys()  // Random

pair3.public.toString()
// 0C28FCA386C7A227600B2FE50B7CAE1EC86D3BF1FBE471BE89827E19D72AA1D
pair3.public.toAddress()
// 19BY2XCgbDe6WtTVbTyzM9eR3LYr6VitWK

pair3.private.toString()
// 0C28FCA386C7A227600B2FE50B7CAE1EC86D3BF1FBE471BE89827E19D72AA1D
pair3.private.toWIF()
// 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ

const signature = simpsign.sign(msg, pair3.private)
simpsign.verify(msg, signature, pair3.public)

simpsign.hash(value)
````

From command line
````
$ node simplesign newKeysFromWords RANDOM WORDS SELECT MORE RANDOM WORDS THAN THESE
$ node simplesign sign "my message" privkey
$ node simplesign verify "my message" signature pubkey
$ node simplesign hash "some text to hash"
````
