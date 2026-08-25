#!/usr/bin/env python3
"""Score a prediction file (VulnGate JSON or LLM baseline JSON) against
bench/corpus/labels.json. CWE-set comparison per file (matched by basename).

Usage: score.py <predictions.json> [--tier regex|ast]
"""
import json
import sys
from collections import defaultdict
from os.path import basename, dirname, join

HERE = dirname(__file__)
LABELS = json.load(open(join(HERE, "corpus", "labels.json")))


def main():
    pred_path = sys.argv[1]
    tier = None
    if "--tier" in sys.argv:
        tier = sys.argv[sys.argv.index("--tier") + 1]
    pred = json.load(open(pred_path))

    found = defaultdict(set)
    for f in pred["findings"]:
        if tier and f.get("tier", "llm") != tier:
            continue
        found[basename(f["path"])].add(f["cwe"])

    tp = fp = fn = 0
    rows = []
    for name, expected in sorted(LABELS.items()):
        exp, got = set(expected), found.get(name, set())
        f_tp, f_fp, f_fn = len(exp & got), len(got - exp), len(exp - got)
        tp, fp, fn = tp + f_tp, fp + f_fp, fn + f_fn
        rows.append((name, sorted(exp), sorted(got), f_tp, f_fp, f_fn))

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    tag = pred.get("tool", "?") + (f" [tier={tier}]" if tier else "")
    print(f"\n== {tag} ==")
    for name, exp, got, a, b, c in rows:
        marks = "" if b == 0 and c == 0 else f"  (fp:{b} fn:{c})"
        print(f"  {name:26s} expected={exp!s:28s} got={got!s:28s}{marks}")
    print(f"  TP={tp} FP={fp} FN={fn} | precision={precision:.2f} recall={recall:.2f} F1={f1:.2f}\n")
    return precision, recall, f1


if __name__ == "__main__":
    main()
