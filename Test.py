"""Reading sample log parsing, spliting"""


from unittest import result


def detect_failed_privileged_totals():
    failed_count = 0
    total_count = 0
    privileged_count = 0
    first_line = ""

    with open("sample_log.txt", "r", encoding="utf-8") as file:
        first_line = file.readline()
        for line in file:
            total_count += 1
            if "AUTH_FAIL" in line.upper():
                failed_count += 1
            elif "PRIV_CHANGE" in line.upper():
                privileged_count += 1

    return first_line, total_count, failed_count, privileged_count

# Then to analyze the data for patterns, trends, and store them into a
# document for analysis.  The document will be used to create a report for the client.
# Below is some of the output code.


first_line, total_count, failed_count, privileged_count = detect_failed_privileged_totals()

print("First line of the log file:")
print(first_line.strip())
print("=======================")

print("Total log entries:", total_count)
print("Failed authentication attempts:", failed_count)
print("Privileged access attempts:", privileged_count)


def parse_log_entry(line):

    parts = line.strip().split("\t")
    if len(parts) < 5:
        return None

    return {
        "timestamp": parts[0],
        "user": parts[1],
        "event": parts[2],
        "ip": parts[3],
        "message": parts[4]
    }


def failed_login_patterns():
    failures_by_user = {}

    with open("sample_log.txt", "r", encoding="utf-8") as file:
        for line in file:
            if "AUTH_FAIL" in line.upper():
                user = line.split("\t")[2]
                if user not in failures_by_user:
                    failures_by_user[user] = 1
                else:
                    failures_by_user[user] += 1
    failures = ""
    print("Suspicious User Login Patterns:")
    for user, count in failures_by_user.items():
        if count >= 5:
            print(
                f"User '{user}' had {count} failed logins. These should be investigated")

    return failures


failed_login_patterns()

#  usernames with multiple failed login attempts
# in summary report, user and a list of IP addresses used for the failed attempts.
#
# print"User ____ has had ___- numbr of failed login attempts. Using IP addresses: ___, ___, ___, etc.  This is a pattern that should be investigated further.


def detection_suspicious_ip_addresses(file):
    suspicious_ips = set()
    for entry in file:
        if entry["event"] == "AUTH_FAIL":
            suspicious_ips.add(entry["ip"])
    return suspicious_ips

# in summary below "IP addresses ___ has been flagged as suspicious due to multiple failed login attempts.  This is a pattern that should be investigated further."


# def main():
#     # for now, the main function is empty, but it can be used to call other functions or implement additional logic in the future.
#     pass

# this is my code for Findings.txt file output


with open("Findings.txt", "w", encoding="utf-8") as out:
    out.write("Cybersecurity Log Analysis Report\n")
    out.write("Barbara Adkins\n")
    out.write("Jr. Analyst\n")
    out.write("================================\n\n")
    out.write("First line of the log file:\n")
    out.write(first_line.strip() + "\n\n")
    out.write("=======================\n\n")
    out.write("Total numbers by category:\n")
    out.write(f"All log entries: {total_count}\n")
    out.write(f"Failed authentication attempts: {failed_count}\n")
    out.write(f"Privileged access attempts: {privileged_count}\n\n")
    out.write("=======================\n\n")
    out.write("Suspicious User Login Patterns:\n")
    out.write(failed_login_patterns() + "\n\n")

# if main == "__main__":
#     main()
