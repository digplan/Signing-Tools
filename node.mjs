import { createECDH, createPublicKey, createSign, createVerify, 
  createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
    
class Signingtools {
  public = ''
  public_compressed = ''
  public_for_verify = ''
  #private = ''
  #pem

  createKeys (privateHex) {
    const ecdh = createECDH('secp256k1')
    privateHex ? ecdh.setPrivateKey(privateHex, 'hex') : ecdh.generateKeys()
    var pemformat = `308201510201010420${ecdh.getPrivateKey('hex')}a081e33081e0020101302c06072a8648ce3d0`
    pemformat += `101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000`
    pemformat += `00000000000000000000000000000000000000000000000000000000000042000000000000000000000000`
    pemformat += `0000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcd`
    pemformat += `b2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d`
    pemformat += `4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034`
    pemformat += `200${ecdh.getPublicKey('hex')}`
    console.log('********', pemformat)

    const b64 = Buffer.from(pemformat, 'hex')

    this.pem = `-----BEGIN EC PRIVATE KEY-----\n${b64.toString('base64')}\n-----END EC PRIVATE KEY-----`
    this.public = ecdh.getPublicKey('hex')
    this.public_compressed = ecdh.getPublicKey('hex', 'compressed')
    this.public_for_verify = createPublicKey({ 'key': this.pem, 'format': 'pem', 'type': 'pkcs8', 'cipher': 'aes-256-cbc' }).export({ 'type': 'spki', 'format': 'pem' })
    this.private = ecdh.getPrivateKey('hex')

    return this
  }

  sign(text) {
    const signer = createSign('SHA256')
    signer.update(text)
    signer.end()
    return signer.sign(this.pem, 'hex')
  }

  verify(text, signature) {
    if (!signature) throw Error('enter a signature')
    const verify = createVerify('SHA256')
    verify.update(text)
    return verify.verify(this.pem, signature, 'hex')
  }

  verifyPublic(text, signature, publicKey = this.public_for_verify) {
    if (!signature) throw Error('enter a signature')
    const verify = createVerify('SHA256')
    verify.update(text)
    return verify.verify(publicKey, signature, 'hex')
  }

  hash(s) {
    return createHash('sha256').update(s).digest('hex')
  }

  encrypt(text) {
    const iv = randomBytes(16)
    const cipher = createCipheriv('aes-256-ctr', this.private.slice(32), iv)
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()])
    return `${iv.toString('hex')}:${encrypted.toString('hex')}`
  }

  decrypt(ivtext) {
    const [iv, encrypted_text] = ivtext.split(':')
    const decipher = createDecipheriv('aes-256-ctr', this.private.slice(32), Buffer.from(iv, 'hex'))
    const decrpyted = Buffer.concat([decipher.update(Buffer.from(encrypted_text, 'hex')), decipher.final()])
    return decrpyted.toString();
  }
}

export { Signingtools }