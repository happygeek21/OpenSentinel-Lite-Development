

import os
import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.parser import parse_log
from backend.analyzer import detect_sql_injection, detect_reconnaissance, classify_event
from backend import database


class TestLogParser(unittest.TestCase):


    def test_parse_valid_event(self):
        line = "2026-10-29T10:00:00 | LOGIN | user=alice | ip=192.168.1.10 | status=SUCCESS | details=Login ok"
        parsed = parse_log(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["user"], "alice")
        self.assertEqual(parsed["ip"], "192.168.1.10")
        self.assertEqual(parsed["status"], "SUCCESS")
        self.assertEqual(parsed["event"], "LOGIN")
        self.assertEqual(parsed["details"], "Login ok")

    def test_parse_legacy_event(self):
        line = "2026-10-29T10:00:00 | SUCCESS | user=bob | ip=10.0.0.5"
        parsed = parse_log(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["user"], "bob")
        self.assertEqual(parsed["ip"], "10.0.0.5")
        self.assertEqual(parsed["status"], "SUCCESS")
        self.assertEqual(parsed["event"], "LOGIN")

    def test_parse_malformed_event(self):
        self.assertIsNone(parse_log("invalid log string"))
        self.assertIsNone(parse_log("2026-10-29 | LOGIN"))


class TestThreatClassification(unittest.TestCase):


    def test_detect_sql_injection(self):
        self.assertTrue(detect_sql_injection("' OR 1=1 --"))
        self.assertTrue(detect_sql_injection("UNION SELECT * FROM users"))
        self.assertTrue(detect_sql_injection("admin'--"))
        self.assertFalse(detect_sql_injection("normal employee search query"))

    def test_detect_reconnaissance(self):
        self.assertTrue(detect_reconnaissance("GET /.env", "404"))
        self.assertTrue(detect_reconnaissance("../../etc/passwd", "200"))
        self.assertTrue(detect_reconnaissance("requesting /admin", "403"))
        self.assertFalse(detect_reconnaissance("normal query", "200"))

    def test_classify_event_severity(self):
        sqli_event = {
            "event_type": "SEARCH",
            "status": "REQUEST",
            "details": "search: ' OR 1=1 --"
        }
        severity, risk = classify_event(sqli_event)
        self.assertEqual(severity, "HIGH")
        self.assertEqual(risk, 90)

        normal_event = {
            "event_type": "SEARCH",
            "status": "REQUEST",
            "details": "search: company holiday calendar"
        }
        severity, risk = classify_event(normal_event)
        self.assertEqual(severity, "NORMAL")
        self.assertEqual(risk, 0)


class TestDatabasePersistence(unittest.TestCase):


    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_opensentinel.db")
        self.orig_db = database.DB
        database.DB = self.db_path
        database.create_database()

    def tearDown(self):
        database.DB = self.orig_db
        self.temp_dir.cleanup()

    def test_save_and_retrieve_alert(self):
        alert_data = {
            "type": "SQL_INJECTION",
            "ip": "192.168.1.50",
            "username": "attacker",
            "attempts": 3,
            "risk": 90,
            "severity": "HIGH",
            "detection_method": "SQL Injection Rule",
            "first_seen": "2026-10-29T10:00:00",
            "last_seen": "2026-10-29T10:05:00",
        }
        database.save_alert(alert_data)

        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE type = 'SQL_INJECTION'")
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["ip"], "192.168.1.50")
        self.assertEqual(row["risk_score"], 90)


        cursor.execute("SELECT * FROM notifications WHERE alert_id = ?", (row["id"],))
        notification = cursor.fetchone()
        self.assertIsNotNone(notification)
        self.assertIn("SQL_INJECTION Detected", notification["title"])
        conn.close()


if __name__ == "__main__":
    unittest.main()
