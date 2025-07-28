// In-memory array, managed internally by this module.
const mailChain = [];

/**
 * Adds a record to the mail-chain.
 * @param {object} mailData
 * @returns {object} The newly added record.
 */
function addToChain(mailData) {
  const record = { id: mailChain.length + 1, ...mailData };
  mailChain.push(record);
  return record;
}

/**
 * Returns a copy of the entire mail chain.
 * @returns {Array}
 */
function getChain() {
  return [...mailChain];
}

/**
 * [NEW] Clears the current chain and loads it from an array.
 * This is the safe way to populate data from a file.
 * @param {Array} dataToLoad The array of mail objects to load.
 */
function loadChain(dataToLoad = []) {
    // .splice(0, array.length) is a robust way to clear an array in place.
    mailChain.splice(0, mailChain.length, ...dataToLoad);
}

// Export the functions for use by server.js
module.exports = {
  addToChain,
  getChain,
  loadChain, // Export the new loading function
};