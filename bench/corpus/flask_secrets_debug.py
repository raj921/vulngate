"""Vulnerable: hardcoded secret and debug server."""
from flask import Flask

STRIPE_API_KEY = "sk-live-9f8d7c6b5a4e3d2c1b0a"  # CWE-798
DB_PASSWORD = "prod-hunter2-password"  # CWE-798

app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # CWE-489
