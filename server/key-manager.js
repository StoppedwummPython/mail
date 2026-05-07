const crypto = require('crypto');

// In-memory storage for public keys
const publicKeyStore = new Map();

/**
 * Generates a new RSA key pair.
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
 * Normalizes the identifier to lowercase to prevent lookup misses.
 */
function registerIdentifier(identifier) {
  if (!identifier) return { privateKey: null, alreadyExists: false };
  
  const id = identifier.trim().toLowerCase();

  if (publicKeyStore.has(id)) {
    return { privateKey: null, alreadyExists: true };
  }
  
  const { publicKey, privateKey } = generateKeyPair();
  publicKeyStore.set(id, publicKey);
  return { privateKey, alreadyExists: false };
}

/**
 * Retrieves the public key for a given address.
 * 1. Checks for exact match (normalized).
 * 2. Checks for wildcard domain match (e.g., *@domain.com).
 */
function getPublicKey(address) {
  if (!address || !address.includes('@')) return null;

  // Normalize input
  const cleanAddress = address.trim().toLowerCase();
  
  // 1. Direct Lookup
  if (publicKeyStore.has(cleanAddress)) {
    return publicKeyStore.get(cleanAddress);
  }
  
  // 2. Wildcard Lookup (e.g. user@test.com -> *@test.com)
  const domainPart = cleanAddress.split('@')[1];
  const wildcardDomain = `*@${domainPart}`;
  
  if (publicKeyStore.has(wildcardDomain)) {
    return publicKeyStore.get(wildcardDomain);
  }
  
  return null;
}

/**
 * Returns a list of all registered identifiers.
 */
function listRegistered() {
  return Array.from(publicKeyStore.keys());
}

module.exports = {
  registerIdentifier,
  getPublicKey,
  listRegistered,
  publicKeyStore,
};
