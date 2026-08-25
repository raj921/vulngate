"""Intentionally vulnerable demo app — VulnGate must BLOCK this file."""
import hashlib
import os
import pickle

import requests
from flask import Flask, request

app = Flask(__name__)

API_KEY = "sk-live-9f8d7c6b5a4e3d2c1b0a"  # hardcoded credential
DB_PASSWORD = "hunter2-prod-database"

db = None


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    row = db.execute(f"SELECT * FROM users WHERE id = {uid}")  # SQLi
    return str(row)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c1 " + host)  # command injection
    return "ok"


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text  # SSRF


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "1+1")))  # eval of user input


@app.route("/load", methods=["POST"])
def load():
    return pickle.loads(request.data)  # unsafe deserialization


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # weak hash


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # debug mode
