import { Keys } from './index.mjs'

const k = new Keys()
k.createKeys()
console.log(`Created keys: ${JSON.stringify(crypto, null, 2)}`)

// Sign a message'
const message = 'this message'
const sig = k.sign(message)
console.log(`Signing message. ${message}, sig = ${sig}`)

// Verify a message
const verified = k.verify(message, sig)
console.log(`Verifying message: ${verified} ${sig} ${message}`)

// Hash a message
const hashed = k.hash('cb')
console.log(`Hash a value: "cb" ${hashed}`)

// Create encryption key
const ek = k.createEncryptionKey()
console.log(`Created encryption key: ${ek}`)

// Encrypt a string
let encryptedData = k.encrypt('text to hide')
console.log(`Encrypt "text to hide": ${JSON.stringify(encryptedData)}`)

// Decrypt a string
let decryptedData = k.decrypt(encryptedData)
console.log(`Decrypt some data: ${decryptedData}`)