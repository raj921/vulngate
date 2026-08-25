"""Vulnerable: weak hashes and disabled JWT signature verification."""
import hashlib

import jwt


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # CWE-327


def checksum(data):
    return hashlib.sha1(data).hexdigest()  # CWE-327


def decode_unsafe(token):
    return jwt.decode(token, "key", options={"verify_signature": False})  # CWE-347
