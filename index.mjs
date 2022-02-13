class web {
  public
  private
  createKeys() {
  }
  sign () {
  }
  verify () {
  }
  export () {
  }
  import () {
  }
}

class node {
  public
  private
   async createKeys() {
     const {generateKeyPair} = await import('crypto')
     generateKeyPair('ec', { namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki',format: 'der'},
         privateKeyEncoding: {type: 'pkcs8',format: 'der'}
     },(err, publicKey, privateKey) => {
         console.log("Public Key is: ", publicKey);
      console.log("Public Key in hex is: ", publicKey.toString('hex'));
      console.log();
      console.log("Private Key is: ", privateKey);
      console.log("Private Key in hex is: ",
      privateKey.toString('hex'));
      this.public = publicKey.toString('hex')
      this.private = privateKey.toString('hex')
     })
   }

  sign() {
    
  }
  verify() {
  }
  export() {
  }
  import() {
  }
}
