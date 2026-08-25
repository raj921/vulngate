#!/usr/bin/env python3
"""Naive LLM security-review baseline: one prompt per corpus file, no tools,
no rules. Mimics the common "just ask the LLM to review the diff" approach.

Requires OPENAI_API_KEY + OPENAI_BASE_URL in the environment. The model is
auto-discovered via GET {base}/models (first entry) unless passed as argv[1].

Writes bench/llm_pred.json in VulnGate's report shape so score.py can consume it.
"""
import json
import os
import sys
import urllib.request
from glob import glob
from os.path import basename, dirname, join, relpath

HERE = dirname(__file__)
BASE = os.environ["OPENAI_BASE_URL"].rstrip("/")
KEY = os.environ["OPENAI_API_KEY"]

SYSTEM = "You are a security code reviewer."
PROMPT = """Review this file for security vulnerabilities (OWASP-style).
Return ONLY a JSON array, no prose, no markdown fences:
[{{"line": <int>, "cwe": "CWE-<number>"}}]
Use these CWE ids where applicable: CWE-798 hardcoded credential, CWE-89 SQLi,
CWE-78 command injection, CWE-918 SSRF, CWE-502 unsafe deserialization,
CWE-94 eval/code injection, CWE-327 weak hash, CWE-489 debug mode,
CWE-79 XSS, CWE-347 JWT verification disabled.
If the file is safe, return [].

FILE {name}:
{code}"""


def chat(model, system, user):
    req = urllib.request.Request(
        f"{BASE}/chat/completions",
        data=json.dumps({
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }).encode(),
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.load(resp)["choices"][0]["message"]["content"]


def parse_array(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    start, end = text.find("["), text.rfind("]")
    if start < 0:
        return []
    try:
        arr = json.loads(text[start : end + 1])
        return arr if isinstance(arr, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def main():
    model = None
    root = join(HERE, "corpus")
    out_name = "llm_pred.json"
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--dir":
            root = sys.argv[i + 1]
            out_name = f"llm_pred_{basename(root)}.json"
            i += 2
        elif not a.startswith("--"):
            model = a
            i += 1
        else:
            i += 1
    if not model:
        with urllib.request.urlopen(urllib.request.Request(
                f"{BASE}/models", headers={"Authorization": f"Bearer {KEY}"}), timeout=60) as r:
            model = json.load(r)["data"][0]["id"]
        print(f"model: {model}")

    findings = []
    for path in sorted(glob(join(root, "**", "*.py"), recursive=True)
                       + glob(join(root, "**", "*.js"), recursive=True)):
        code = open(path).read()
        rel = relpath(path, HERE)
        if len(code) > 20000:
            print(f"  SKIP {basename(path)}: {len(code)} chars exceeds naive-baseline context")
            continue
        items = []
        for attempt in range(2):
            try:
                extra = "" if attempt == 0 else "\nIMPORTANT: reply with ONLY the JSON array."
                raw = chat(model, SYSTEM, PROMPT.format(name=basename(path), code=code) + extra)
                items = parse_array(raw)
                if items or "[" in raw:
                    break
            except Exception as e:  # noqa: BLE001 - baseline tool, log and continue
                if attempt == 1:
                    print(f"  ERROR {basename(path)}: {e}")
                items = []
        for it in items:
            cwe = str(it.get("cwe", ""))
            if not cwe.startswith("CWE-"):
                continue
            findings.append({
                "rule_id": "LLM", "name": "llm-review", "severity": "HIGH",
                "cwe": cwe, "path": rel, "line": int(it.get("line", 0) or 0),
                "code": "", "fix": "", "tier": "llm",
            })
        print(f"  {basename(path):26s} -> {len(items)} item(s)")

    out = {"tool": "naive-llm-baseline", "version": model, "findings": findings,
           "counts": {}, "verdict": "n/a"}
    dest = join(HERE, out_name)
    json.dump(out, open(dest, "w"), indent=2)
    print(f"wrote {dest} ({len(findings)} findings)")


if __name__ == "__main__":
    main()
