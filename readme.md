# simplesigner
Simpler api for EC keys

### Node
````js
import SigningTools from 'signing-tools'

const crypto = new SigningTools()
crypto.createKeys('844a4f5aaeef10dd522761264ae08ebe7b1a50d5dfaa18f48979c78b0e9a0f33')
console.log(`Created keys: ${JSON.stringify(crypto, null, 2)}`)

// Sign a message
const message = 'this message'
const sig = crypto.sign(message)
console.log(`Signing message. ${message}, sig = ${sig}`)

// Verify a message
const verified = crypto.verify(message, sig)
console.log(`Verifying message: ${verified} ${sig} ${message}`)

// Verify a message with public key
const verified2 = JSON.stringify(crypto.verifyPublic(message, sig))
console.log(`Verify message with public: ${message} ${sig} ${verified2}`)

// Verify a message with public key
const verified3 = JSON.stringify(crypto.verifyPublic('bad msg', sig))
console.log(`Failed verify message with public: ${message} ${sig} ${verified3}`)

// Hash a message
const hashed = crypto.hash('cb')
console.log(`Hash a value: "cb" ${hashed}`)

// Encrypt a string
let encryptedData = crypto.encrypt('text to hide')
console.log(`Encrypt "text to hide": ${JSON.stringify(encryptedData)}`)

// Decrypt a string
let decryptedData = crypto.decrypt(encryptedData)
console.log(`Decrypt some data: ${decryptedData}`)
````

## Browser
````js
  // <script src='//unpkg.com/signing-tools/browser.js'></script>

  // <script type='module'>
  const simplesign = new Simplesign()

  const keys = await simplesign.createKeys()
  console.log(keys)
   
  const sig = await simplesign.sign('hello world')
  console.log('sign a string', sig)

  const verified = await simplesign.verify('hello world', sig)
  console.log('verified true should be true', verified, sig)

  const notverified = await simplesign.verify('!world', sig)
  console.log('verified should be false', notverified)

  const notverified2 = await simplesign.verify('hello world', 'BADSIG')
  console.log('verified should be false', notverified2)

  const hash = await simplesign.hash('cb')
  console.log('hash', hash=='103d6254a6d94bacc82e822885185f56c69cb799ec5124c0aa405e386975151b', hash)

  const exportPub = await simplesign.exportPublic()
  console.log('export public', exportPub)

  const exportPriv = await simplesign.exportPrivate()
  console.log('export private', exportPriv)

  const jwk = `{
  "crv": "P-384",
  "d": "wouCtU7Nw4E8_7n5C1-xBjB4xqSb_liZhYMsy8MGgxUny6Q8NCoH9xSiviwLFfK_",
  "ext": true,
  "key_ops": ["sign"],
  "kty": "EC",
  "x": "SzrRXmyI8VWFJg1dPUNbFcc9jZvjZEfH7ulKI1UkXAltd7RGWrcfFxqyGPcwu6AQ",
  "y": "hHUag3OvDzEr0uUQND4PXHQTXP5IDGdYhJhL-WLKjnGjQAw0rNGy5V29-aV-yseW"
  }`

  const k = await simplesign.importPrivate(jwk)
  console.log('import private', k)

  const exp = await simplesign.exportPrivate()
  console.log(jwk)
  console.log('export private', JSON.stringify(exp, null, 2))
````