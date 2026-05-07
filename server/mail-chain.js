// Internal data structures
let mailChain = []; // Global history (The "Chain")
const inboxIndex = new Map(); // Optimization: address -> [indices in mailChain]

/**
 * Adds a record to the mail-chain and updates the index for fast lookup.
 */
function addToChain(mailData) {
  const record = { id: mailChain.length + 1, ...mailData };
  mailChain.push(record);

  // Index by recipient for O(1) access
  const recipient = mailData.recipient;
  if (!inboxIndex.has(recipient)) {
    inboxIndex.set(recipient, []);
  }
  inboxIndex.get(recipient).push(record);

  return record;
}

/**
 * Returns mail for a specific address. Much faster than filtering the whole chain.
 */
function getInbox(address) {
  return inboxIndex.get(address) || [];
}

/**
 * Returns the full chain.
 */
function getChain() {
  return mailChain;
}

/**
 * Clears and rebuilds the chain and indices from persisted data.
 */
function loadChain(dataToLoad = []) {
  mailChain = [];
  inboxIndex.clear();
  
  if (Array.isArray(dataToLoad)) {
    dataToLoad.forEach(item => {
      addToChain(item);
    });
  }
}

module.exports = {
  addToChain,
  getChain,
  getInbox,
  loadChain,
};
