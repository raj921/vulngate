// Intentionally vulnerable demo JS — VulnGate must flag these.
const crypto = require('crypto');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

function renderUntrusted(html) {
  document.getElementById('out').innerHTML = html; // DOM XSS
}

function listFiles(req, res) {
  exec('ls ' + req.query.dir, (e, out) => res.send(out)); // command injection
}

function hashPw(pw) {
  return crypto.createHash('md5').update(pw).digest('hex'); // weak hash
}

function skipAuth(token) {
  return jwt.verify(token, 'secret', { algorithms: ['none'] }); // alg=none
}
