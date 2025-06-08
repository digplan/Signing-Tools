# Signing Tools

A simple API for cryptographic operations using EC keys. Supports both Node.js and browser environments.

## Installation

```bash
npm install signing-tools
```

## Features

- Key generation and management
- Message signing and verification
- Public key verification
- Hashing
- Encryption/Decryption
- JWK import/export support

## Usage

### Node.js

```js
import SigningTools from 'signing-tools'

// Initialize with optional private key
const crypto = new SigningTools()
await crypto.createKeys('844a4f5aaeef10dd522761264ae08ebe7b1a50d5dfaa18f48979c78b0e9a0f33')

// Get key information
console.log('Keys:', {
  public: crypto.public,
  public_compressed: crypto.public_compressed,
  public_for_verify: crypto.public_for_verify
})

// Sign and verify
const message = 'this message'
const sig = await crypto.sign(message)
console.log('Signature:', sig)

const verified = await crypto.verify(message, sig)
console.log('Verified:', verified)

// Verify with public key
const verified2 = await crypto.verifyPublic(message, sig)
console.log('Verified with public key:', verified2)

// Hash
const hashed = await crypto.hash('cb')
console.log('Hash:', hashed)

// Encrypt/Decrypt
const encrypted = await crypto.encrypt('secret message')
console.log('Encrypted:', encrypted)

const decrypted = await crypto.decrypt(encrypted)
console.log('Decrypted:', decrypted)
```

### Browser

```html
<script src='//unpkg.com/signing-tools/browser.js'></script>
<script type='module'>
  const crypto = new Simplesign()
  
  // Generate new keys
  const keys = await crypto.createKeys()
  console.log('Keys:', keys)
  
  // Sign and verify
  const sig = await crypto.sign('hello world')
  console.log('Signature:', sig)
  
  const verified = await crypto.verify('hello world', sig)
  console.log('Verified:', verified)
  
  // Hash
  const hash = await crypto.hash('cb')
  console.log('Hash:', hash)
  
  // Export keys
  const publicKey = await crypto.exportPublic()
  const privateKey = await crypto.exportPrivate()
  
  // Import JWK
  const jwk = {
    "crv": "P-384",
    "d": "wouCtU7Nw4E8_7n5C1-xBjB4xqSb_liZhYMsy8MGgxUny6Q8NCoH9xSiviwLFfK_",
    "ext": true,
    "key_ops": ["sign"],
    "kty": "EC",
    "x": "SzrRXmyI8VWFJg1dPUNbFcc9jZvjZEfH7ulKI1UkXAltd7RGWrcfFxqyGPcwu6AQ",
    "y": "hHUag3OvDzEr0uUQND4PXHQTXP5IDGdYhJhL-WLKjnGjQAw0rNGy5V29-aV-yseW"
  }
  
  await crypto.importPrivate(jwk)
</script>
```

## API Reference

### Constructor
```js
new SigningTools(privateKey?: string)
```

### Methods

#### createKeys(privateKey?: string)
Generate new key pair or use provided private key.

#### sign(message: string)
Sign a message.

#### verify(message: string, signature: string)
Verify a message signature.

#### verifyPublic(message: string, signature: string, publicKey?: string)
Verify using public key.

#### hash(data: string)
Create SHA-256 hash.

#### encrypt(data: string)
Encrypt data using AES-256-CTR.

#### decrypt(encryptedData: string)
Decrypt data.

#### exportPublic()
Export public key.

#### exportPrivate()
Export private key.

#### importPrivate(jwk: object)
Import private key from JWK format.