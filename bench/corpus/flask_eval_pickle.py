"""Vulnerable: eval of query string, pickle of request body."""
import pickle

from flask import request


def calc():
    return str(eval(request.args.get("expr", "1+1")))  # CWE-94


def load():
    return pickle.loads(request.data)  # CWE-502
