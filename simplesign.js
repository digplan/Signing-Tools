var crypto = require('crypto')
var bitcore = require('bitcore-lib')
var message = require('./message.js')
const fs = require('fs')

const simplesign = module.exports = {
  newAddress: (wif)=>{
    if(wif){
      var priv = new bitcore.PrivateKey.fromWIF(wif)
    } else {
      var priv = new bitcore.PrivateKey() 
    }
    return {
      'public': String(priv.toPublicKey()),
      'public_addr': String(priv.toAddress()),
      'private': priv.toString(),
      'private_wif': priv.toWIF()
    }
  },
  sign: (msg, priv)=>{
    if(fs.existsSync(msg))
      msg = fs.readFileSync(msg).toString('base64')
    if(typeof priv === 'string')
      priv = new bitcore.PrivateKey(priv)
    const sig = new message(msg).sign(priv)
    return new Buffer(sig, 'base64').toString('hex').slice(64)
  },
  verify: (msg, sig, pub)=>{
    var v
    if(fs.existsSync(msg))
      msg = fs.readFileSync(msg).toString('base64')
    try {
      v = new message(msg).verify(pub, sig)
    } catch(e) {
      return false
    }
    return v
  },
  hash: (value)=>{
    return crypto.createHash('sha256').update(value).digest('hex')
  },
  isValid: (s)=>{
    if(bitcore.Address.isValid(s))
      return 'public'
    if(bitcore.PrivateKey.isValid(s))
      return 'private'
    return false
  }
}

if(!module.parent){
 console.log(simplesign[process.argv[2]].apply(this, process.argv.slice(3)))
}
