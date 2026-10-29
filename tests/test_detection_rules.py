

import os
import sys
import re
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.analyzer import SQLI_PATTERNS, detect_sql_injection


IMPROVED_SQLI_PATTERNS = [
    re.compile(r"(\bor\b|\band\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+", re.IGNORECASE),
    re.compile(r"(\bor\b|\band\b)\s+[\'\"][a-zA-Z0-9]+[\'\"]\s*=\s*[\'\"][a-zA-Z0-9]+[\'\"]", re.IGNORECASE),
    re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
    re.compile(r"\b(drop|truncate|alter)\s+table\b", re.IGNORECASE),
    re.compile(r"\binsert\s+into\b.+?\bvalues\b", re.IGNORECASE),
    re.compile(r"\b(delete|select)\s+.*?\s+\bfrom\b", re.IGNORECASE),
    re.compile(r"(--|#|/\*.*?\*/)\s*$", re.IGNORECASE),
    re.compile(r"[\'\"];\s*(select|update|delete|drop|insert)\b", re.IGNORECASE),
]


def detect_sql_injection_improved(details: str) -> bool:

    if not details:
        return False
    value = details.strip()
    return any(pattern.search(value) is not None for pattern in IMPROVED_SQLI_PATTERNS)


SYNTHETIC_DATASET = [

    {"payload": "' OR 1=1 --", "is_attack": True, "category": "Tautology"},
    {"payload": "\" OR 1=1 #", "is_attack": True, "category": "Tautology"},
    {"payload": "admin' --", "is_attack": True, "category": "Auth Bypass Comment"},
    {"payload": "1' UNION SELECT username, password FROM users --", "is_attack": True, "category": "Union Based"},
    {"payload": "1; DROP TABLE logs; --", "is_attack": True, "category": "Stacked Query"},
    {"payload": "test') UNION ALL SELECT 1, 2, 3--", "is_attack": True, "category": "Union Based"},


    {"payload": "Please select the best insurance plan for employees", "is_attack": False, "category": "Benign Text"},
    {"payload": "Need to update my personal contact information", "is_attack": False, "category": "Benign Text"},
    {"payload": "Where can I drop off the project documents?", "is_attack": False, "category": "Benign Text"},
    {"payload": "Review of the select committee quarterly report", "is_attack": False, "category": "Benign Text"},
    {"payload": "Order number 101 or 102 was delivered yesterday", "is_attack": False, "category": "Benign Text"},
    {"payload": "Employee salary directory and benefits", "is_attack": False, "category": "Benign Text"},
]


class TestDefensiveDetectionRule(unittest.TestCase):


    def test_baseline_rule_identifies_true_positives(self):

        attacks = [item for item in SYNTHETIC_DATASET if item["is_attack"]]
        detected = [item for item in attacks if detect_sql_injection(item["payload"])]

        self.assertGreaterEqual(len(detected), len(attacks) - 1)

    def test_baseline_rule_exhibits_false_positives(self):

        false_positive_candidates = [
            "Please select the best insurance plan for employees",
            "Need to update my personal contact information",
            "Where can I drop off the project documents?"
        ]

        flagged = [p for p in false_positive_candidates if detect_sql_injection(p)]
        self.assertTrue(len(flagged) > 0, "Demonstrates baseline rule vulnerability to false positives")

    def test_improved_rule_eliminates_false_positives(self):

        benign = [item for item in SYNTHETIC_DATASET if not item["is_attack"]]
        false_alarms = [item for item in benign if detect_sql_injection_improved(item["payload"])]
        self.assertEqual(len(false_alarms), 0, f"Improved rule produced false alarms: {false_alarms}")

    def test_improved_rule_catches_all_true_positives(self):

        attacks = [item for item in SYNTHETIC_DATASET if item["is_attack"]]
        missed = [item for item in attacks if not detect_sql_injection_improved(item["payload"])]
        self.assertEqual(len(missed), 0, f"Improved rule missed real attacks: {missed}")


def run_benchmark():

    print("=" * 65)
    print("TASK 9: DETECTION RULE BENCHMARK & EVALUATION REPORT")
    print("=" * 65)

    baseline_tp = 0
    baseline_fp = 0
    improved_tp = 0
    improved_fp = 0

    total_attacks = sum(1 for x in SYNTHETIC_DATASET if x["is_attack"])
    total_benign = sum(1 for x in SYNTHETIC_DATASET if not x["is_attack"])

    print(f"\nSynthetic Test Corpus: {len(SYNTHETIC_DATASET)} samples ({total_attacks} attacks, {total_benign} benign)")
    print("-" * 65)
    print(f"{'Payload':<45} | {'Type':<8} | {'Base':<5} | {'Impr'}")
    print("-" * 65)

    for item in SYNTHETIC_DATASET:
        base_result = detect_sql_injection(item["payload"])
        impr_result = detect_sql_injection_improved(item["payload"])

        if item["is_attack"]:
            if base_result: baseline_tp += 1
            if impr_result: improved_tp += 1
        else:
            if base_result: baseline_fp += 1
            if impr_result: improved_fp += 1

        label = "ATTACK" if item["is_attack"] else "BENIGN"
        display_text = item["payload"][:42] + ("..." if len(item["payload"]) > 42 else "")
        print(f"{display_text:<45} | {label:<8} | {str(base_result):<5} | {str(impr_result)}")

    print("-" * 65)
    print("RULE PERFORMANCE METRICS:")
    print(f"Baseline Rule: True Positive Rate: {baseline_tp}/{total_attacks} | False Positives: {baseline_fp}/{total_benign}")
    print(f"Improved Rule: True Positive Rate: {improved_tp}/{total_attacks} | False Positives: {improved_fp}/{total_benign}")
    print("=" * 65)


if __name__ == "__main__":
    run_benchmark()
    unittest.main()
