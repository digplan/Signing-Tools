import { SigningTools } from './index.mjs'

const crypto = new SigningTools()
crypto.createKeys('844a4f5aaeef10dd522761264ae08ebe7b1a50d5dfaa18f48979c78b0e9a0f33')
console.log(`Created keys: ${JSON.stringify(crypto, null, 2)}`)

// Sign a message'
const message = 'this message'
const sig = crypto.sign(message)
console.log(`Signing message. ${message}, sig = ${sig}`)

// Verify a message
const verified = crypto.verify(message, sig)
console.log(`Verifying message: ${verified} ${sig} ${message}`)

// Hash a message
const hashed = crypto.hash('cb')
console.log(`Hash a value: "cb" ${hashed}`)

// Encrypt a string
let encryptedData = crypto.encrypt('text to hide')
console.log(`Encrypt "text to hide": ${JSON.stringify(encryptedData)}`)

// Decrypt a string
let decryptedData = crypto.decrypt(encryptedData)
console.log(`Decrypt some data: ${decryptedData}`)