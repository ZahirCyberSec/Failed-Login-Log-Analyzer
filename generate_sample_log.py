

"""Generate a fake SSH authentication log for cybersecurity practice.

All IP addresses are documentation or private network addresses.
Run: python generate_sample_log.py
"""

import random
from pathlib import Path

random.seed(10)

USERS = ["admin", "root", "test", "ubuntu", "zahir", "guest"]
HOST = "server01"

ATTACKERS = {
    "203.0.113.50": 34,
    "203.0.113.77": 21,
    "198.51.100.9": 8
}

NORMAL = [
    "192.168.1.10",
    "192.168.1.22",
    "10.0.0.5"
]

lines = []
failed_count = 0
success_count = 0

hour, minute, second = 0, 0, 0


def stamp():
    global hour, minute, second

    second += random.randint(5, 40)

    if second >= 60:
        minute += second // 60
        second %= 60

    if minute >= 60:
        hour += minute // 60
        minute %= 60

    return f"Nov 16 {hour % 24:02d}:{minute:02d}:{second:02d}"


# Create login events
events = []

for ip, count in ATTACKERS.items():
    for _ in range(count):
        events.append(("fail", ip))

for ip in NORMAL:
    for _ in range(3):
        events.append(("ok", ip))

    events.append(("fail", ip))

# Simulate a successful login after repeated failures
events.append(("ok", "203.0.113.77"))

# Randomize events while placing one attacker's failures first
random.shuffle(events)

events.sort(
    key=lambda event: 0
    if event[0] == "fail" and event[1] == "203.0.113.77"
    else 1
)

# Generate log lines
for kind, ip in events:

    user = random.choice(USERS)
    port = random.randint(30000, 60000)
    pid = random.randint(1000, 9999)

    if kind == "fail":
        status = "Failed password"
        failed_count += 1
    else:
        status = "Accepted password"
        success_count += 1

    lines.append(
        f"{stamp()} {HOST} sshd[{pid}]: "
        f"{status} for {user} from {ip} port {port} ssh2"
    )


# Save auth.log beside this Python file
output_file = Path(__file__).with_name("auth.log")

with output_file.open("w", encoding="utf-8") as file:
    file.write("\n".join(lines) + "\n")


print("Sample authentication log created successfully!")
print(f"Total events: {len(lines)}")
print(f"Failed logins: {failed_count}")
print(f"Successful logins: {success_count}")
print(f"Saved to: {output_file}")
