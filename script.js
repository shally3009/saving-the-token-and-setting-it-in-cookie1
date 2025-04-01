const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secret keys for encryption & JWT signing
const JWT_SECRET = 'your_jwt_secret_key';    // Secret for JWT
const ENCRYPTION_KEY = crypto.randomBytes(32);  // 32 bytes key for AES encryption
const IV_LENGTH = 16;  // AES uses a 16-byte Initialization Vector (IV)


// 🔐 Encrypt Function
const encrypt = (payload) => {
  try {
    // 1. Create JWT token with payload
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    // 2. Encrypt the JWT token using AES-256 encryption
    const iv = crypto.randomBytes(IV_LENGTH);  // Generate a random IV
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);

    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Return the IV and the encrypted token
    return ${iv.toString('hex')}:${encrypted};
  } catch (error) {
    console.error('Encryption Error:', error);
    return null;
  }
};


// 🔓 Decrypt Function
const decrypt = (encryptedToken) => {
  try {
    const [ivHex, encrypted] = encryptedToken.split(':');

    if (!ivHex || !encrypted) {
      throw new Error('Invalid token format');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Decode the JWT token to get the original payload
    const decoded = jwt.verify(decrypted, JWT_SECRET);
    return decoded;
  } catch (error) {
    console.error('Decryption Error:', error);
    return null;
  }
};


module.exports = {
  encrypt,
  decrypt
};