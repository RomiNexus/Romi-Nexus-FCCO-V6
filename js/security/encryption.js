/**
 * ROMI NEXUS ENCRYPTION MODULE (Vanilla JS)
 * ISSUE-11: Cryptographic Failures Prevention (OWASP #2)
 * DIFC Compliance: Data Protection at Rest & Transit
 *
 * Note: Requires CryptoJS library
 * <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.0/crypto-js.min.js"></script>
 */

const ENCRYPTION_CONFIG = {
  algorithm: 'AES',
  keySize: 256,
  iterations: 1000,
  derivedKeyLength: 32,
};

function encryptData(data, secretKey) {
  if (!data || !secretKey) {
    console.error('Encryption failed: missing data or key');
    return null;
  }
  try {
    const encrypted = CryptoJS.AES.encrypt(
      JSON.stringify(data),
      secretKey
    ).toString();
    console.log('[AUDIT] Data encrypted successfully');
    return encrypted;
  } catch (error) {
    console.error('[ERROR] Encryption failed:', error);
    return null;
  }
}

function decryptData(encryptedData, secretKey) {
  if (!encryptedData || !secretKey) {
    console.error('Decryption failed: missing data or key');
    return null;
  }
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, secretKey);
    const decrypted = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
    return decrypted;
  } catch (error) {
    console.error('[ERROR] Decryption failed:', error);
    return null;
  }
}

function encryptSessionToken(token, secretKey) {
  return encryptData({ token, timestamp: Date.now() }, secretKey);
}

function decryptSessionToken(encryptedToken, secretKey) {
  const data = decryptData(encryptedToken, secretKey);
  if (!data) return null;
  const age = Date.now() - data.timestamp;
  const MAX_AGE = 4 * 60 * 60 * 1000;
  if (age > MAX_AGE) {
    console.warn('[SECURITY] Token expired');
    return null;
  }
  return data.token;
}

function generateSecureToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += chars[Math.floor(Math.random() * chars.length)];
  }
  return token;
}

function hashValue(value) {
  return CryptoJS.SHA256(value).toString();
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { encryptData, decryptData, encryptSessionToken, decryptSessionToken, generateSecureToken, hashValue };
}
