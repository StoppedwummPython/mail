const crypto = require('crypto');

// In-memory storage for public keys, to be populated by server.js.
const publicKeyStore = new Map();

/**
 * Generates a new RSA key pair.
 * @returns {{publicKey: string, privateKey: string}}
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

/**
 * Registers a new identifier and stores its public key.
 * @param {string} identifier
 * @returns {{privateKey: string, alreadyExists: boolean}}
 */
function registerIdentifier(identifier) {
  if (publicKeyStore.has(identifier)) {
    return { privateKey: null, alreadyExists: true };
  }
  const { publicKey, privateKey } = generateKeyPair();
  publicKeyStore.set(identifier, publicKey);
  return { privateKey, alreadyExists: false };
}

/**
 * Retrieves the public key for a given address.
 * @param {string} address
 * @returns {string|null}
 */
function getPublicKey(address) {
  if (publicKeyStore.has(address)) {
    return publicKeyStore.get(address);
  }
  const domain = `*@${address.split('@')[1]}`;
  if (publicKeyStore.has(domain)) {
    return publicKeyStore.get(domain);
  }
  return null;
}

/**
 * Returns a list of all registered identifiers.
 * @returns {string[]}
 */
function listRegistered() {
  return Array.from(publicKeyStore.keys());
}

// Export the functions and the store itself so server.js can access it.
module.exports = {
  registerIdentifier,
  getPublicKey,
  listRegistered,
  publicKeyStore, // This export is the fix for the bug.
};