
const crypto = require('crypto');
const keyLengthInBytes = 16; // 256 bits / 8 bits per byte// Generate a secure encryption key
const encryptionKey = crypto.randomBytes( keyLengthInBytes ); 
console.log( 'Encryption Key (hex format):', encryptionKey.toString( 'hex' ) );
