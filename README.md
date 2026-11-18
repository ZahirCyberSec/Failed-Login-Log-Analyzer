# Failed Login Log Analyzer

A beginner-friendly Blue Team cybersecurity project built with Python. This tool analyzes SSH authentication logs, detects repeated failed login attempts, and identifies potentially suspicious IP addresses.

## Project Overview

The Failed Login Log Analyzer helps security analysts understand authentication logs and identify patterns that may indicate brute-force login attempts.

It analyzes failed and successful login events and generates a report showing suspicious activity.

## Features

- Parses SSH authentication log entries.
- Detects failed and successful login attempts.
- Counts failed attempts by source IP address.
- Identifies suspicious IP addresses using a configurable threshold.
- Tracks usernames attempted by each IP.
- Warns about successful logins after repeated failed attempts.
- Handles missing and unrecognized log entries.
- Includes automated tests using pytest.

## Project Structure

```text
Failed-Login-Log-Analyzer/
├── analyzer.py
├── generate_sample_log.py
├── test_analyzer.py
├── auth.log
├── README.md
├── requirements.txt
└── .gitignore
```

## Requirements

- Python 3
- pytest

## Installation

Clone the repository:

```bash
git clone https://github.com/ZahirCyberSec/Failed-Login-Log-Analyzer.git
```

Open the project directory:

```bash
cd Failed-Login-Log-Analyzer
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

### 1. Generate sample authentication logs

```bash
python generate_sample_log.py
```

### 2. Run the analyzer

```bash
python analyzer.py
```

### 3. Change the detection threshold

```bash
python analyzer.py --threshold 10
```

The threshold determines how many failed login attempts from an IP address are required before it is flagged.

### 4. Analyze another log file

```bash
python analyzer.py --file auth.log
```

## Run Tests

Run all automated tests:

```bash
python -m pytest -v
```

## Sample Results

The included synthetic dataset contains:

- Total login events: 76
- Failed login attempts: 66
- Successful login attempts: 10
- Unique source IP addresses: 6
- Suspicious IP addresses at threshold 5: 3

## Technologies Used

- Python
- Regular Expressions
- Pytest
- Linux SSH authentication log format
- Git and GitHub

## Learning Objectives

This project demonstrates practical beginner-level cybersecurity skills:

- Log analysis
- Authentication monitoring
- Brute-force detection concepts
- Python scripting
- Basic security automation
- Automated software testing

## Important Note

This project uses synthetic SSH authentication log data generated for educational and testing purposes. It does not contain real server logs or represent actual attacks.

A successful login after repeated failures is a warning for further investigation, not proof of a compromised account.

## Future Improvements

- Export reports to CSV.
- Add time-based detection.
- Support IPv6 addresses.
- Add a graphical dashboard.
- Integrate with real logs from authorized systems.

## Author

**Zahir Rahman**

BS Cyber Security Student

GitHub: [https://github.com/ZahirCyberSec](https://github.com/ZahirCyberSec)