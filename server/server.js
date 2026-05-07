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
      
      // Load Keys
      for (const [identifier, key] of Object.entries(loadedData.publicKeys || {})) {
        keyManager.publicKeyStore.set(identifier, key);
      }
      
      // Load Mail (Rebuilds indices automatically)
      mailChainManager.loadChain(loadedData.mailChain);
      
      console.log(`[Persistence] Data loaded: ${mailChainManager.getChain().length} messages found.`);
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
  } catch (error) {
    console.error('[Persistence] Error saving data:', error);
  }
}

// --- API ENDPOINTS ---
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

app.post('/register', (req, res) => {
  const { address } = req.body;
  if (!address || !address.includes('@')) return res.status(400).json({ error: 'Valid address required.' });

  const domain = address.split('@')[1];
  const isWildcard = address.startsWith('*@');

  if (!PUBLIC_DOMAINS.has(domain) && !isWildcard) { 
    return res.status(403).json({ error: `Private domain: register '*@${domain}' instead.` }); 
  }
  
  const { privateKey, alreadyExists } = keyManager.registerIdentifier(address);
  if (alreadyExists) return res.status(409).json({ error: 'Already registered.' });
  
  saveData();
  res.status(201).json({ message: `Registered ${address}`, privateKey });
});

// --- CHALLENGE-RESPONSE FLOW ---
app.post('/send-challenge', (req, res) => {
    const { 
        sender, recipient, 
        encryptedMessage, iv, tag, encryptedKeyForRecipient, encryptedKeyForSender,
        encryptedContent, encryptedForRecipient, encryptedForSender 
    } = req.body;
    
    if (!sender || !recipient) return res.status(400).json({ error: 'Sender/recipient required.' });

    const senderPublicKey = keyManager.getPublicKey(sender);
    if (!senderPublicKey) return res.status(404).json({ error: 'Sender not registered.' });

    const challengeId = crypto.randomUUID();
    const originalNonce = crypto.randomBytes(32).toString('hex');
    const encryptedNonce = crypto.publicEncrypt(
        { key: senderPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(originalNonce, 'utf-8')
    );

    const mailData = { 
        sender, recipient, timestamp: new Date().toISOString(),
        encryptedMessage, iv, tag, encryptedKeyForRecipient, encryptedKeyForSender,
        encryptedContent, encryptedForRecipient, encryptedForSender 
    };

    pendingChallenges.set(challengeId, { originalNonce, mailData });
    setTimeout(() => pendingChallenges.delete(challengeId), 300000);

    res.status(200).json({ challengeId, encryptedNonce: encryptedNonce.toString('base64') });
});

app.post('/send-verify', (req, res) => {
    const { challengeId, decryptedNonce } = req.body;
    const challenge = pendingChallenges.get(challengeId);

    if (!challenge || challenge.originalNonce !== decryptedNonce) {
        pendingChallenges.delete(challengeId);
        return res.status(403).json({ error: 'Challenge failed.' });
    }
    
    const record = mailChainManager.addToChain(challenge.mailData);
    saveData();
    pendingChallenges.delete(challengeId);
    
    res.status(201).json({ message: 'Mail sent.', record });
});

// --- EFFICIENT DATA RETRIEVAL ---

/**
 * GET /mailchain?address=user@example.com
 * If address is provided, returns only relevant mail (O(1) lookup).
 * If no address, returns the whole chain.
 */
app.get('/mailchain', (req, res) => {
  const { address } = req.query;
  if (address) {
    return res.status(200).json({ address, chain: mailChainManager.getInbox(address) });
  }
  res.status(200).json({ chain: mailChainManager.getChain() });
});

app.get('/publicKey/:address', (req, res) => {
  const publicKey = keyManager.getPublicKey(req.params.address);
  if (!publicKey) return res.status(404).json({ error: 'Not found.' });
  res.status(200).json({ address: req.params.address, publicKey });
});

app.listen(PORT, () => {
  loadData();
  console.log(`\nServer running on http://localhost:${PORT}`);
  initializeCli();
});

function initializeCli() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'SERVER> ' });
  rl.prompt();
  rl.on('line', (line) => {
    const args = line.trim().split(' ');
    switch (args[0].toLowerCase()) {
      case 'list':
        console.log(keyManager.listRegistered());
        break;
      case 'exit': process.exit(0);
    }
    rl.prompt();
  });
}
