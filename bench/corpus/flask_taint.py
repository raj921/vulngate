"""Vulnerable: user input flows to SSRF, command injection, and SQLi sinks."""
import os

import requests
from flask import request

db = None


def fetch_avatar():
    url = request.args.get("url")
    return requests.get(url).text  # CWE-918: tainted SSRF


def ping_host():
    host = request.form.get("host")
    os.system("ping -c1 " + host)  # CWE-78: tainted command


def get_user():
    uid = request.args.get("id")
    safe_id = int(uid)
    row = db.execute(f"SELECT * FROM users WHERE id = {safe_id}")  # CWE-89: tainted SQL
    return str(row)
