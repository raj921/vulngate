// TRAP FILE — safe patterns a dumb scanner might flag. Expected: zero findings.
const crypto = require('crypto');

const API_KEY = process.env.API_KEY; // env-based, safe

function showText(value) {
  document.getElementById('x').textContent = value; // DOM-safe
}

function hashStrong(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex'); // strong hash
}
