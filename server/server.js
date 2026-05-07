const express = require('express');
const keyManager = require('./key-manager');
const mailChainManager = require('./mail-chain');
const readline = require('readline');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const DB_FILE = './server_data.json';
const PUBLIC_DOMAINS = new Set(['public.com']);

const pendingChallenges = new Map();

// --- DATA PERSISTENCE ---
function loadData() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const rawData = fs.readFileSync(DB_FILE);
      const loadedData = JSON.parse(rawData);
      
      // Clear and reload the Map in keyManager
      keyManager.publicKeyStore.clear();
      for (const [identifier, key] of Object.entries(loadedData.publicKeys || {})) {
        // Ensure we load them normalized
        keyManager.publicKeyStore.set(identifier.toLowerCase(), key);
      }
      
      mailChainManager.loadChain(loadedData.mailChain);
      console.log(`[Persistence] Loaded ${keyManager.publicKeyStore.size} keys and ${mailChainManager.getChain().length} messages.`);
    } else {
      console.log(`[Persistence] No data file found. Starting fresh.`);
    }
  } catch (error) {
    console.error('[Persistence] Error loading data:', error);
  }
}

function saveData() {
  try {
    const serverData = {
      publicKeys: Object.fromEntries(keyManager.publicKeyStore),
      mailChain: mailChainManager.getChain(),
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(serverData, null, 2));
    console.log(`[Persistence] Data saved to ${DB_FILE}`);
  } catch (error) {
    console.error('[Persistence] Error saving data:', error);
  }
}

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// --- LOGGING MIDDLEWARE ---
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

// --- API ENDPOINTS ---

app.post('/register', (req, res) => {
  const { address } = req.body;
  if (!address || !address.includes('@')) return res.status(400).json({ error: 'Invalid address format.' });

  const domain = address.split('@')[1].toLowerCase();
  const isWildcard = address.startsWith('*@');

  // Logic check for Public vs Private domains
  if (!PUBLIC_DOMAINS.has(domain) && !isWildcard) { 
    return res.status(403).json({ error: `Domain '${domain}' is private. Register '*@${domain}' instead.` }); 
  }
  
  const { privateKey, alreadyExists } = keyManager.registerIdentifier(address);
  
  if (alreadyExists) {
      console.log(`[Auth] Register failed: ${address} already exists.`);
      return res.status(409).json({ error: 'Already registered.' });
  }
  
  console.log(`[Auth] SUCCESSFULLY REGISTERED: ${address}`);
  saveData();
  res.status(201).json({ message: `Registered ${address}`, privateKey });
});

app.get('/publicKey/:address', (req, res) => {
  const address = req.params.address;
  const publicKey = keyManager.getPublicKey(address);
  
  if (!publicKey) {
      console.log(`[Lookup] 404 - Key not found for: ${address}`);
      return res.status(404).json({ error: 'Public key not found.' });
  }
  
  console.log(`[Lookup] 200 - Found key for: ${address}`);
  res.status(200).json({ address, publicKey });
});

// --- CHALLENGE FLOW ---
app.post('/send-challenge', (req, res) => {
    const { sender, recipient } = req.body;
    const senderPublicKey = keyManager.getPublicKey(sender);
    
    if (!senderPublicKey) {
        console.log(`[Mail] Challenge denied: Sender ${sender} not registered.`);
        return res.status(404).json({ error: 'Sender not registered.' });
    }

    const challengeId = crypto.randomUUID();
    const originalNonce = crypto.randomBytes(32).toString('hex');
    const encryptedNonce = crypto.publicEncrypt(
        { key: senderPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(originalNonce, 'utf-8')
    );

    pendingChallenges.set(challengeId, { originalNonce, mailData: req.body });
    setTimeout(() => pendingChallenges.delete(challengeId), 300000);

    res.status(200).json({ challengeId, encryptedNonce: encryptedNonce.toString('base64') });
});

app.post('/send-verify', (req, res) => {
    const { challengeId, decryptedNonce } = req.body;
    const challenge = pendingChallenges.get(challengeId);

    if (!challenge || challenge.originalNonce !== decryptedNonce) {
        return res.status(403).json({ error: 'Challenge failed.' });
    }
    
    mailChainManager.addToChain(challenge.mailData);
    saveData();
    pendingChallenges.delete(challengeId);
    console.log(`[Mail] Message accepted from ${challenge.mailData.sender} to ${challenge.mailData.recipient}`);
    res.status(201).json({ message: 'Sent.' });
});

app.get('/mailchain', (req, res) => {
  const { address } = req.query;
  if (address) {
    return res.status(200).json({ chain: mailChainManager.getInbox(address) });
  }
  res.status(200).json({ chain: mailChainManager.getChain() });
});

app.listen(PORT, () => {
  loadData();
  console.log(`\nMail Server running on http://localhost:${PORT}`);
});
