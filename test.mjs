import Keys from './index.mjs'

const k = new Keys()
await k.createKeys()
console.log(`Created keys: ${JSON.stringify(k, null, 2)}`)

const msg = 'this message'
const sig = await k.sign(msg)
console.log(`Signing message. ${msg}, sig = ${sig}`)
assert(await k.verify(msg, sig))
console.log(`Verifying message: true ${sig} ${msg}`)

const hashed = await k.hash('cb')
console.log(`Hash a value: "cb" ${hashed}`)

const ek = await k.createEncryptionKey()
console.log(`Created encryption key: ${ek}`)

let encrypted = await k.encrypt('text to hide')
console.log(`Encrypt "text to hide": ${JSON.stringify(encrypted)}`)

let decrypted = await k.decrypt(encrypted)
console.log(`Decrypt some data: ${decrypted}`)
=======
// Sign a message'
const message = 'this message'
const sig = await k.sign(message)
console.log(`Signing message. ${message}, sig = ${sig}`)

// Verify a message
const verified = await k.verify(message, sig)
console.log(`Verifying message: ${verified} ${sig} ${message}`)

// Hash a message
const hashed = await k.hash('cb')
console.log(`Hash a value: "cb" ${hashed}`)

// Create encryption key
const ek = await k.createEncryptionKey()
console.log(`Created encryption key: ${ek}`)

// Encrypt a string
let encryptedData = await k.encrypt('text to hide')
console.log(`Encrypt "text to hide": ${JSON.stringify(encryptedData)}`)

// Decrypt a string
let decryptedData = await k.decrypt(encryptedData)
console.log(`Decrypt some data: ${decryptedData}`)

