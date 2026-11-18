
from analyzer import parse_line, analyze

# Sample SSH authentication log entries

FAIL = (
    "Nov 16 01:00:00 s sshd[1]: "
    "Failed password for admin from 203.0.113.5 port 22 ssh2"
)

INVALID = (
    "Nov 16 01:00:01 s sshd[1]: "
    "Failed password for invalid user bob from 203.0.113.5 port 22 ssh2"
)

OK = (
    "Nov 16 01:00:02 s sshd[1]: "
    "Accepted password for zahir from 192.168.1.10 port 22 ssh2"
)


# TEST 1: Parse failed and successful login events

def test_parse_failed_and_accepted():
    assert parse_line(FAIL)["ip"] == "203.0.113.5"
    assert parse_line(FAIL)["status"] == "Failed"
    assert parse_line(OK)["status"] == "Accepted"
    assert parse_line(INVALID)["user"] == "bob"


# TEST 2: Ignore invalid log lines

def test_garbage_line_is_ignored():
    assert parse_line("this is not a log line") is None


# TEST 3: Flag IP after reaching the threshold

def test_flags_ip_over_threshold():
    result = analyze([FAIL] * 5 + [OK], threshold=5)

    assert "203.0.113.5" in result["suspicious"]
    assert "192.168.1.10" not in result["suspicious"]


# TEST 4: Do not flag IP below threshold

def test_below_threshold_not_flagged():
    result = analyze([FAIL] * 4, threshold=5)

    assert result["suspicious"] == {}


# TEST 5: Detect successful login after repeated failures

def test_break_in_detected():
    success = (
        "Nov 16 01:00:09 s sshd[1]: "
        "Accepted password for root from 203.0.113.5 port 22 ssh2"
    )

    result = analyze([FAIL] * 6 + [success], threshold=5)

    assert len(result["possible_break_ins"]) == 1
    assert result["possible_break_ins"][0][0] == "203.0.113.5"


# TEST 6: Identify multiple suspicious IP addresses

def test_multiple_suspicious_ips():
    other_fail = (
        "Nov 16 01:00:03 s sshd[2]: "
        "Failed password for root from 203.0.113.8 port 22 ssh2"
    )

    result = analyze([FAIL] * 5 + [other_fail] * 5, threshold=5)

    assert "203.0.113.5" in result["suspicious"]
    assert "203.0.113.8" in result["suspicious"]


# TEST 7: Reject invalid IP addresses

def test_invalid_ip_is_ignored():
    invalid_ip = (
        "Nov 16 01:00:04 s sshd[3]: "
        "Failed password for admin from 999.999.999.999 port 22 ssh2"
    )

    assert parse_line(invalid_ip) is None


# TEST 8: Count failed and successful logins correctly

def test_login_statistics():
    result = analyze([FAIL] * 3 + [OK], threshold=5)

    assert result["failed"] == 3
    assert result["successful"] == 1
    assert result["parsed"] == 4


# TEST 9: Count different usernames tried by an IP

def test_different_usernames():
    second_user = (
        "Nov 16 01:00:03 s sshd[2]: "
        "Failed password for root from 203.0.113.5 port 22 ssh2"
    )

    result = analyze([FAIL, second_user], threshold=5)

    assert len(result["users_tried"]["203.0.113.5"]) == 2


# TEST 10: Detect no suspicious IP below threshold

def test_no_suspicious_activity():
    result = analyze([FAIL, FAIL], threshold=5)

    assert result["suspicious"] == {}
    assert result["possible_break_ins"] == []
