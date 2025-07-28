const express = require('express');
const keyManager = require('./key-manager');
const mailChainManager = require('./mail-chain');
const readline = require('readline');
const fs = require('fs');
const crypto = require('crypto'); // Import crypto for generating challenges

const app = express();
const PORT = 3000;
const DB_FILE = './server_data.json';
const PUBLIC_DOMAINS = new Set(['public.com']);

// In-memory store for pending challenges. In production, this would be a Redis cache or similar.
const pendingChallenges = new Map();


// --- DATA PERSISTENCE ---
function loadData() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const rawData = fs.readFileSync(DB_FILE);
      const loadedData = JSON.parse(rawData);
      for (const [identifier, key] of Object.entries(loadedData.publicKeys || {})) {
        keyManager.publicKeyStore.set(identifier, key);
      }
      mailChainManager.loadChain(loadedData.mailChain);
      console.log(`[Persistence] Data successfully loaded from ${DB_FILE}`);
    } else {
      console.log(`[Persistence] No data file found. A new one will be created on the first change.`);
    }
  } catch (error) { console.error('[Persistence] Critical error loading data. Starting fresh. Error:', error); }
}

function saveData() {
  try {
    const wasFileMissing = !fs.existsSync(DB_FILE);
    const serverData = {
      publicKeys: Object.fromEntries(keyManager.publicKeyStore),
      mailChain: mailChainManager.getChain(),
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(serverData, null, 2));
    if (wasFileMissing) { console.log(`\n[Persistence] New data file created at ${DB_FILE}`); }
  } catch (error) { console.error('\n[Persistence] Error saving data:', error); }
}

// --- API ENDPOINTS ---
app.use(express.json());
app.use(express.static('public')); // Serve static files from 'public' directory

app.post('/register', (req, res) => {
  const { address } = req.body;
  if (!address || !address.includes('@')) { return res.status(400).json({ error: 'A valid address format (user@domain or *@domain) is required.' }); }
  const isWildcard = address.startsWith('*@');
  const domain = address.split('@')[1];
  if (!PUBLIC_DOMAINS.has(domain)) {
    if (!isWildcard) { return res.status(403).json({ error: `Registration of individual addresses on the private domain '${domain}' is not allowed. Please register the entire domain using '*@${domain}'.` }); }
  }
  if (PUBLIC_DOMAINS.has(domain)) {
    if (isWildcard) { return res.status(403).json({ error: `Cannot register an entire public domain. Please register a specific address on '${domain}'.` }); }
  }
  const { privateKey, alreadyExists } = keyManager.registerIdentifier(address);
  if (alreadyExists) { return res.status(409).json({ error: `The address or domain '${address}' is already registered.` }); }
  console.log(`\n[API] Registered new identifier: ${address}`);
  saveData();
  res.status(201).json({ message: `Successfully registered '${address}'.`, privateKey: privateKey });
});


// --- NEW CHALLENGE-RESPONSE FLOW FOR SENDING MAIL ---

// STEP 1: Client initiates a send, server replies with a challenge
app.post('/send-challenge', (req, res) => {
    const { sender, recipient, encryptedContent } = req.body;
    if (!sender || !recipient || !encryptedContent) {
        return res.status(400).json({ error: 'Request must include sender, recipient, and encryptedContent.' });
    }

    const senderPublicKey = keyManager.getPublicKey(sender);
    if (!senderPublicKey) {
        return res.status(404).json({ error: `Sender '${sender}' is not registered.` });
    }

    const challengeId = crypto.randomUUID();
    const originalNonce = crypto.randomBytes(32).toString('hex'); // This is the secret answer

    // Encrypt the secret answer with the sender's public key
    const encryptedNonce = crypto.publicEncrypt(
        { key: senderPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(originalNonce, 'utf-8')
    );

    // Store the challenge details temporarily
    pendingChallenges.set(challengeId, {
        originalNonce,
        mailData: { sender, recipient, encryptedContent, timestamp: new Date().toISOString() }
    });
    
    // Set a timeout to clean up the challenge if it's not solved
    setTimeout(() => pendingChallenges.delete(challengeId), 300000); // 5 minutes

    // Send the encrypted challenge back to the client
    res.status(200).json({
        challengeId,
        encryptedNonce: encryptedNonce.toString('base64'),
    });
});

// STEP 2: Client sends back the decrypted challenge, server verifies and finalizes
app.post('/send-verify', (req, res) => {
    const { challengeId, decryptedNonce } = req.body;
    if (!challengeId || !decryptedNonce) {
        return res.status(400).json({ error: 'Verification request requires challengeId and decryptedNonce.' });
    }

    const challenge = pendingChallenges.get(challengeId);
    if (!challenge) {
        return res.status(404).json({ error: 'Invalid or expired challenge ID.' });
    }
    
    // THE CORE VERIFICATION
    if (challenge.originalNonce === decryptedNonce) {
        // SUCCESS! Proof of key possession is confirmed.
        const record = mailChainManager.addToChain(challenge.mailData);
        saveData();
        pendingChallenges.delete(challengeId); // Clean up immediately
        
        console.log(`\n[API] Challenge solved. Mail added from ${challenge.mailData.sender}`);
        return res.status(201).json({ message: 'Challenge successful. Mail sent.', record });
    } else {
        // FAILURE!
        pendingChallenges.delete(challengeId);
        return res.status(403).json({ error: 'Challenge failed. Invalid response.' });
    }
});


// --- OTHER ENDPOINTS AND SERVER LOGIC ---
app.get('/publicKey/:address', (req, res) => {
  const { address } = req.params;
  const publicKey = keyManager.getPublicKey(address);
  if (!publicKey) return res.status(404).json({ error: 'Public key not found.' });
  res.status(200).json({ address, publicKey });
});

app.get('/mailchain', (req, res) => {
  res.status(200).json({ chain: mailChainManager.getChain() });
});

app.listen(PORT, () => {
  loadData();
  console.log(`\nMain server running on http://localhost:${PORT}`);
  console.log('API Endpoints are live.');
  console.log('Type "help" for admin commands.\n');
  initializeCli();
});

function initializeCli() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'SERVER> ' });
  rl.prompt();
  rl.on('line', (line) => {
    // ... CLI logic remains the same ...
    const args = line.trim().split(' ');
    const command = args[0].toLowerCase();
    switch (command) {
      case 'help':
        console.log(`Available Commands:\n  list, genkey <addr>, lookup <addr>, mailchain, clear, exit`);
        break;
      case 'list':
        const ids = keyManager.listRegistered();
        console.log(ids.length ? 'Registered:\n- ' + ids.join('\n- ') : 'None registered.');
        break;
      case 'exit': process.exit(0);
    }
    rl.prompt();
  });
}