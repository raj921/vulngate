// Vulnerable: command injection, DOM XSS, alg=none JWT.
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

function cleanup(req, res) {
  exec('rm -rf ' + req.query.dir, (e) => res.send('done')); // CWE-78
}

function show(html) {
  document.getElementById('x').innerHTML = html; // CWE-79
}

function trust(token) {
  return jwt.verify(token, 'k', { algorithms: ['none'] }); // CWE-347
}
