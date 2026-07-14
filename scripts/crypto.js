class CryptoWrapper {
  constructor (sodium) {
    this._s = sodium;
    this.identityKeypair = null;
  }
  newIdentityKeypair() {
    return sodium.crypto_sign_keypair();
  }
  addIdentityKeypair(keypair) {
    this.identityKeypair = keypair;
  }
  // returns the PUBLIC key for our identity key
  getIdentityKey() {
    return this.identityKeypair.publicKey;
  }
  // creates an encryption asymmetric keypair
  genKeypair() {
    return sodium.crypto_box_keypair();
  }
  hash(data, token = null) {
    return this._s.crypto_generichash(64, data);
  }
  newID(pubkey) {
    return "0" + pubkey.toHex() + "x";
  }
  getPubkeyFromId(peerId) {
    // console.log("sliced:",Uint8Array.fromHex(peerId.slice(1,-1)))
    return Uint8Array.fromHex(peerId.slice(1,-1))
  }
  getSharedKey(privateKey, publicKey) {
    return sodium.crypto_box_beforenm(publicKey, privateKey);
  }
  encryptMessage(message, sharedKey, nonce) {
    nonce ??= this._s.randombytes_buf(this._s.crypto_box_NONCEBYTES);
    const encrypted = this._s.crypto_box_easy_afternm(message, nonce, sharedKey);
    return { encrypted, nonce };
  }
  decryptMessage(crypted, sharedKey) {
    let {encrypted, nonce} = crypted;
    let out = this._s.crypto_box_open_easy_afternm(encrypted, nonce, sharedKey);
    return new TextDecoder().decode(out);
  }
  // somewhat strangely, this seems to derive the shared secret on its own?
  encryptMessage_slow(message, recipientPublicKey, privateKey, nonce) {
    nonce ??= this._s.randombytes_buf(this._s.crypto_box_NONCEBYTES);
    const encrypted = this._s.crypto_box_easy(message, nonce, recipientPublicKey, privateKey);
    return { encrypted, nonce };
  }

  // Decrypt message using own secret key and sender's public key
  decryptMessage_slow(encrypted, nonce, senderPublicKey, privateKey) {
    let out = this._s.crypto_box_open_easy(encrypted, nonce, senderPublicKey, privateKey);
    return new TextDecoder().decode(out);
  }

  // Sign message using own secret key
  signMessage(message) {
    return this._s.crypto_sign_detached(message, this.identityKeypair.privateKey);
  }

  // Verify signature using sender's public key
  verifySignature(signature, message, senderPublicKey = this.identityKeypair.publicKey) {
    return this._s.crypto_sign_verify_detached(signature, message, senderPublicKey);
  }

  // generates `amount` of random bytes, then converts to base64
  b64RandomBytes(amount) {
    return sodium.to_base64(sodium.randombytes_buf(amount));
  }
}
