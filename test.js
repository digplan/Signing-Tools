const signer = require('./simplesign.js')

const pair = signer.newAddress()
console.log('1 newAddress', pair)

console.log('2 sign/verify')
sign('hello world', pair.public, pair.private)

console.log('3 hash')
console.log('Hash empty string', signer.hash(''))

console.log('4 isValid')
console.log('expect valid: ' + signer.isValid(pair.public))
console.log('expect valid: ' + signer.isValid(pair.private))
console.log('expect NOT valid: ' + signer.isValid(''))

console.log('5 sign/verify file')
sign('./simplesign.js', pair.public, pair.private)

function sign(msg, pub, pri){
 console.log(`Signing msg ${msg} for public ${pub} and private ${pri}`)
 const sig = signer.sign(msg, pri)
 console.log('Signature', sig)
 const verify = signer.verify(msg, sig, pub)
 console.log('Verified', verify)
 const noverify = signer.verify('hey no', sig, pub)
 console.log('No verify', noverify)
}
