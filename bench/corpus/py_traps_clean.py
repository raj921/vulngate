"""TRAP FILE — looks suspicious to grep but is safe. Expected: zero findings."""
import hashlib
import os
import subprocess

import requests
import yaml

API_URL = "https://api.example.com/v1/status"
API_KEY = os.environ["API_KEY"]  # env-based, safe
MAX_URLS = 100


def healthcheck():
    # constant URL, no user input — a regex scanner flags this, taint analysis must not
    return requests.get(API_URL).status_code


def list_dir(folder):
    # argv list without shell — safe
    return subprocess.run(["ls", "-la", folder], check=True, capture_output=True)


def fingerprint(blob):
    # md5 used for non-security fingerprinting — explicitly safe
    return hashlib.md5(blob, usedforsecurity=False).hexdigest()


def load_config(text):
    return yaml.safe_load(text)  # safe loader
