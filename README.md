# OpenSentinel Lite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Defensive Security Log Monitoring, Threat Detection & Rule Evaluation System**  
> *Developed for Cybersecurity Assessment: Task 13 (Defensive Security Tool) & Task 9 (Defensive Detection Rule Testing).*

---

## Overview

**OpenSentinel Lite** is an end-to-end defensive cybersecurity monitoring solution designed to ingest, parse, analyze, and visualize security events in real-time. It detects malicious activities including:
- **SQL Injection Attacks:** Tautologies, union-based queries, and stacked injection attempts.
- **Reconnaissance & Directory Traversal:** Path traversal (`../../etc/passwd`), sensitive configuration hunting (`/.env`), and abnormal endpoint probing.
- **Brute Force Authentication:** Rapid login failure clustering with dynamic risk scoring (Medium to Critical).

---

## Assessment Deliverables

| Task | Title | Deliverables | Location |
| :--- | :--- | :--- | :--- |
| **Task 13** | **Build a Small Defensive Security Tool** | Working prototype, synthetic log generator, SQLite persistence, FastAPI backend, and React dashboard. | [`backend/`](backend/), [`frontend/`](frontend/), [`SUBMISSION_REPORT.md`](SUBMISSION_REPORT.md) |
| **Task 9** | **Test a Defensive Detection Rule** | Synthetic test corpus (12 cases), false positive analysis on baseline rules, improved regex/boundary rule, and benchmark report. | [`tests/test_detection_rules.py`](tests/test_detection_rules.py), [`reports/`](reports/) |

Detailed findings, methodology, and evaluation metrics are documented in [`SUBMISSION_REPORT.md`](SUBMISSION_REPORT.md).

---

## Project Structure

```text
OpenSentinel-Lite/
├── backend/
│   ├── analyzer.py        # Threat detection heuristics and risk scoring
│   ├── auth.py            # User authentication and admin password hashing (bcrypt)
│   ├── database.py        # SQLite schema, migrations, and alert persistence
│   ├── event_logger.py    # Standardized event logger
│   ├── log_generator.py   # Synthetic security log generator
│   ├── main.py            # FastAPI REST API endpoints
│   ├── parser.py          # Pipe-delimited log parser
│   └── scanner.py         # Standalone CLI security scanner
├── frontend/              # Vite + React real-time security dashboard
│   ├── src/               # React components, styles, and API integrations
│   └── package.json
├── tests/
│   ├── test_defensive_tool.py    # Unit tests for parsing, detection & database
│   └── test_detection_rules.py   # Task 9 detection rule benchmark suite
├── reports/               # Automated test execution outputs
│   ├── detection_rule_benchmark.txt
│   └── unit_test_results.txt
├── requirements.txt       # Backend dependencies
├── README.md              # Project documentation
└── SUBMISSION_REPORT.md   # Formal assessment submission report
```

---

## Quick Start Guide

### 1. Backend Setup

Create virtual environment and install dependencies:
```bash
python -m venv venv
.\venv\Scripts\activate       # On Windows (or: source venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
```

Start the FastAPI backend server:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
* Interactive API Documentation (Swagger): [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* Default Admin Credentials: `admin` / `admin123`

---

### 2. Frontend Setup

In a new terminal:
```bash
cd frontend
npm install
npm run dev
```
* Dashboard URL: [http://localhost:5173/](http://localhost:5173/)

---

### 3. Generate Demo Events & Run Scanner

Generate synthetic security events:
```bash
# Generate immediate sequence of normal, SQLi, recon, and brute-force events
python -m backend.log_generator --interval 0

# Run scanner manually
python backend/scanner.py
```

---

### 4. Run Automated Test Suites

```bash
# Run all unit tests (Task 13 verification)
python -m unittest discover -s tests -p "test_*.py" -v

# Run Detection Rule Benchmark (Task 9 verification)
python tests/test_detection_rules.py
```

---

## Benchmark Results (Task 9)

```text
=================================================================
TASK 9: DETECTION RULE BENCHMARK & EVALUATION REPORT
=================================================================
Synthetic Test Corpus: 12 samples (6 attacks, 6 benign)
-----------------------------------------------------------------
RULE PERFORMANCE METRICS:
Baseline Rule: True Positive Rate: 6/6 | False Positives: 3/6 (50.0% FP)
Improved Rule: True Positive Rate: 6/6 | False Positives: 0/6 (0.0% FP)
=================================================================
```

---

## License

This project is licensed under the MIT License.
