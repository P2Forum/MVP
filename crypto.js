// This manages all the crypto functions

function generateKeypair(inputs = []) {
  // Returns an asymmetric keypair
  // Uses the inputs as the data if provided, otherwise generates a random one
  
}

function generateSymmetricKey() {
  // returns a randomly generated symmetric key that can be used
}

function encryptWithSymmetricKey(data, key) {
  
}

function encryptWithAsymmetricKey(data, key) {
  
}



// Basic crypto structure:
// User has "username" and "password"
// Browser generates long random data (not necessarily secret, more like a salt)
// Using both the secret and the password, a keypair is generated
// long random data is also saved to local file on disk to prevent data loss


// Identity keypair (generated with the password + long random)
// L-> signs "subidentities", each is a randomly generated keypair
//     - subidentities are used so we can have easy device linking
//
// Message crypto keypairs
//  - Generated randomly
//  - encrypt messages and data while at rest
//  - May not be necessary, we'll see
