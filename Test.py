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

print("Log File Verification:")
print(first_line.strip())
print("")
print("==============================" + "\n")
print("Summary of Key Statistics:" + "\n")
print("Total log entries:", total_count)
print("Failed authentication attempts:", failed_count)
print("Privileged access attempts:", privileged_count)
print("")
print("=============================" + "\n")


def parse_log_entry(line):

    parts = line.strip().split("\t")
    if len(parts) < 5:
        return None

    return {
        "timestamp": parts[0],
        "event": parts[1],
        "user": parts[2].replace("user=", ""),
        "ip": parts[3].replace("ip=", ""),
        "message": parts[4].replace("message=", "")
    }


def failed_login_patterns():
    failures_by_user = {}
    failures_by_ip = {}

    with open("sample_log.txt", "r", encoding="utf-8") as file:
        for entry in file:
            entry = parse_log_entry(entry)
            if entry is None:
                continue

            if entry["event"] == "AUTH_FAIL":
                user = entry["user"]
                ip = entry["ip"]

                if user not in failures_by_user:
                    failures_by_user[user] = 1
                else:
                    failures_by_user[user] += 1

                if ip not in failures_by_ip:
                    failures_by_ip[ip] = 1
                else:
                    failures_by_ip[ip] += 1

    print("Suspicious User Login Patterns:")
    print("")

    for user, count in failures_by_user.items():
        if count >= 5:
            print(
                f"User '{user}' had {count} failed login attempts. ")
            print("An excessive number of failed login attempts may be an attempt at malicious activity and should be investigated further." + "\n")

    print(" ")
    print("Suspicious IP activity \n")

    for ip, count in failures_by_ip.items():
        if count >= 3:
            print(
                f"IP address '{ip}' is associated with {count} failed login attempts. ")
            print(
                "Repeated and excessive failed login attempts should be investigated further. \n\n ")

    return failures_by_user, failures_by_ip


user_failures, ip_failures = failed_login_patterns()

print("")
print("===============================" + "\n")


def detailed_suspicious_entries():
    user_permission_changes = {}
    user_permission_ips = {}

    with open("sample_log.txt", "r", encoding="utf-8") as file:
        for line in file:
            entry = parse_log_entry(line)

            if entry is None:
                continue

            if entry["event"] == "PRIV_CHANGE":
                user = entry["user"]
                ip = entry["ip"]

                if user not in user_permission_changes:
                    user_permission_changes[user] = 1

                else:
                    user_permission_changes[user] += 1

                if user not in user_permission_ips:
                    user_permission_ips[user] = {ip}

                else:
                    user_permission_ips[user].add(ip)

    print("User Permission Changes: " + "\n")

    for user, count in user_permission_changes.items():
        user_ips = user_permission_ips[user]
        ip_str = ", ".join(user_ips)

        print(
            f"User '{user}' had {count} PRIV_CHANGE events. The IP addresses used: {ip_str}.")

    return user_permission_changes, user_permission_ips,


user_changes, user_ips = detailed_suspicious_entries()


def authorization_failed_attempts_log():
    user_authorization_counts = {}
    user_authorization_ips = {}

    with open("sample_log.txt", "r", encoding="utf-8") as file:
        for line in file:
            entry = parse_log_entry(line)

            if entry is None:
                continue

            if entry["event"] == "AUTH_FAIL":
                user = entry["user"]
                ip = entry["ip"]

                if user not in user_authorization_counts:
                    user_authorization_counts[user] = 1

                else:
                    user_authorization_counts[user] += 1

                if user not in user_authorization_ips:
                    user_authorization_ips[user] = {ip}

                else:
                    user_authorization_ips[user].add(ip)

    print("")
    print("==================================" + "\n")
    print("User Authorization Changes: " + "\n")

    for user, count in user_authorization_counts.items():
        user_ips = user_authorization_ips[user]
        ip_str = ", ".join(user_ips)

        print(
            f"User '{user}' had {count} AUTH_FAILED events. The IP addresses were: {ip_str}.")

    return user_authorization_counts, user_authorization_ips


auth_changes, auth_ips = authorization_failed_attempts_log()


def main():
    count_log_events()
    parse_log_entry(line)
    failed_login_patterns()
    detailed_suspicious_entries()
    authorization_failed_attempts_log()


# this is my code for Findings.txt file output


with open("Findings.txt", "w", encoding="utf-8") as out:
    out.write("Cybersecurity Log Analysis Report\n")
    out.write("prepared by: Barbara Adkins\n")
    out.write("Role: Jr. Security Analyst\n")
    out.write("================================\n\n")
    out.write("Log File Verification \n\n")
    out.write(first_line.strip() + "\n\n")
    out.write("=======================\n\n")
    out.write("Summary of Key Statistics \n\n")
    out.write(f"Total log entries: {total_count}\n")
    out.write(f"Failed authentication attempts: {failed_count}\n")
    out.write(f"Privilege change events: {privileged_count}\n\n")
    out.write("=======================\n\n")
    out.write("Suspicious User Login Patterns:\n\n")
    for user, count in user_failures.items():
        if count >= 5:
            out.write(
                f"User '{user}' had {count} failed login attempts. \n")
            out.write(
                "An excessive number of failed login attempts may be an attempt at malicious activity and should be investigated further. \n\n")

    out.write("=======================\n\n")
    out.write("Suspicious IP activity \n\n")
    for ip, count in ip_failures.items():
        if count >= 5:
            out.write(
                f"IP address '{ip}' was linked to {count} failed login attempts. \n")
            out.write(
                "Repeated failed login attempts should be investigated further. \n\n")
    out.write("")
    out.write("=======================\n\n")
    out.write("Privilege Change Events \n\n")
    out.write("=======================\n\n")
    for user, count in user_changes.items():
        out.write(
            f"User {user} had {count} Privilege Change events.  The ips that are associated with the event are: {user_ips[user]}." + "\n")
    out.write("")
    out.write("=======================\n\n")
    out.write("User Authorization Changes \n\n")
    out.write("=======================\n\n")
    for user, count in auth_changes.items():
        out.write(
            f"User {user} had {count} Authorization Change events.  The ips that are associated with the event are: {auth_ips[user]}." + "\n")


# if main == "__main__":
#     main()
