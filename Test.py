"""Reading sample log parsing, spliting"""


def count_log_events():
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


first_line, total_count, failed_count, privileged_count = count_log_events()

print("First line of the log file:")
print(first_line.strip())
print("================================")

print("Total numbers by category:" + "\n")
print("Total log entries:", total_count)
print("Failed authentication attempts:", failed_count)
print("Privileged access attempts:", privileged_count)
print("=================================")
print(" ")


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

    print("Suspicious User Login Patterns:")
    for user, count in failures_by_user.items():
        if count >= 5:
            print(
                f"User '{user}' had {count} failed logins. These should be investigated.")

    return failures_by_user
    # return failures


user_ip_list = failed_login_patterns()


# in summary report, user and a list of IP addresses used for the failed attempts.
#
# Using IP addresses: ___, ___, ___, etc.  This is a pattern that should be investigated further.


def detection_suspicious_ip_addresses(file):
    suspicious_ips = set()
    for entry in file:
        if entry["event"] == "AUTH_FAIL":
            suspicious_ips.add(entry["ip"])
    return suspicious_ips


def main():
    # for now, the main function is empty, but it can be used to call other functions or implement additional logic in the future.
    pass

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
    out.write("Suspicious User Login Patterns:\n\n")
    for user, count in user_ip_list.items():
        if count >= 5:
            out.write(
                f"User '{user}' had {count} failed logins. These should be investigated.\n"
            )
    out.write("\n")
    # out.write("=======================\n\n")
    # out.write("Suspicious IP & user login patterns:\n")
    # out.write(suspicious_ips() + "\n\n")
    # out.write("====================================")

# if main == "__main__":
#     main()
