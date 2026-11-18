
"""Failed Login Log Analyzer - Beginner Blue Team Project.

Reads SSH authentication logs, counts failed logins,
identifies suspicious IP addresses, and detects possible
successful logins after repeated failures.

Run:
    python analyzer.py
    python analyzer.py --file auth.log --threshold 10
"""

import argparse
import re
import ipaddress
from collections import Counter, defaultdict

# ---------- SETTINGS ----------
DEFAULT_FILE = "auth.log"
DEFAULT_THRESHOLD = 5
# ------------------------------

# Match standard SSH authentication log entries
PATTERN = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b"
)


def parse_line(line):
    """Parse one SSH log line and return its details."""

    match = PATTERN.search(line)

    if not match:
        return None

    event = match.groupdict()

    # Validate the IP address
    try:
        ipaddress.ip_address(event["ip"])
    except ValueError:
        return None

    return event


def analyze(lines, threshold=DEFAULT_THRESHOLD):
    """Analyze SSH log events and return statistics."""

    failures = Counter()
    users_tried = defaultdict(set)
    failed_before = Counter()

    possible_break_ins = []

    successful = 0
    parsed = 0

    for line in lines:

        event = parse_line(line)

        if event is None:
            continue

        parsed += 1

        ip = event["ip"]
        user = event["user"]

        if event["status"] == "Failed":

            failures[ip] += 1
            failed_before[ip] += 1
            users_tried[ip].add(user)

        else:

            successful += 1

            if failed_before[ip] >= threshold:

                possible_break_ins.append(
                    (ip, user, failed_before[ip], event["time"])
                )

    # Identify suspicious IP addresses
    suspicious = {
        ip: count
        for ip, count in failures.items()
        if count >= threshold
    }

    suspicious = dict(
        sorted(suspicious.items(), key=lambda item: item[1], reverse=True)
    )

    return {
        "total_lines": len(lines),
        "parsed": parsed,
        "unparsed": len(lines) - parsed,
        "failed": sum(failures.values()),
        "successful": successful,
        "unique_ips": len(failures),
        "failures_by_ip": failures,
        "users_tried": users_tried,
        "suspicious": suspicious,
        "possible_break_ins": possible_break_ins,
        "threshold": threshold,
    }


def print_report(result):
    """Display the analysis report."""

    print("\n========== FAILED LOGIN REPORT ==========")

    print(f"Total log lines:       {result['total_lines']}")
    print(f"Parsed login events:   {result['parsed']}")
    print(f"Unrecognized lines:    {result['unparsed']}")
    print(f"Failed logins:         {result['failed']}")
    print(f"Successful logins:     {result['successful']}")
    print(f"Unique source IPs:     {result['unique_ips']}")

    print(
        f"\n========== SUSPICIOUS IPs "
        f"({result['threshold']}+ failures) =========="
    )

    if not result["suspicious"]:
        print("No suspicious IP addresses found.")

    for ip, count in result["suspicious"].items():

        users = len(result["users_tried"][ip])

        if count >= result["threshold"] * 2:
            risk = "HIGH"
        else:
            risk = "MEDIUM"

        print(f"\nIP Address: {ip}")
        print(f"Failed Attempts: {count}")
        print(f"Different Usernames: {users}")
        print(f"Risk Level: {risk}")

    print("\n========== POSSIBLE SUCCESS AFTER FAILURES ==========")

    if not result["possible_break_ins"]:
        print("No such login events detected.")

    for ip, user, fails, when in result["possible_break_ins"]:

        print(
            f"WARNING: {ip} successfully logged in as '{user}' "
            f"at {when} after {fails} failed attempts."
        )

    print("\n==========================================\n")


def main():

    parser = argparse.ArgumentParser(
        description="SSH Failed Login Log Analyzer"
    )

    parser.add_argument(
        "--file",
        default=DEFAULT_FILE,
        help="Path to SSH authentication log"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Number of failed attempts before an IP is flagged"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    try:

        with open(
            args.file,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            lines = file.read().splitlines()

    except FileNotFoundError:
        print(f"Error: File '{args.file}' was not found.")
        print("Run: python generate_sample_log.py")
        return

    except OSError as error:
        print(f"Error reading log file: {error}")
        return

    results = analyze(lines, args.threshold)

    print_report(results)


if __name__ == "__main__":
    main()
