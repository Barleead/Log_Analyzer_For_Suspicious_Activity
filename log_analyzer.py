"""Reading sample log parsing, spliting"""
failed_count = 0
total_count = 0
privileged_count = 0
line_output = []

with open("sample_log.txt", "r", encoding="utf-8") as file:
    first_line = file.readline()
    for line in file:
        total_count += 1
        if "AUTH_FAIL" in line.upper():
            failed_count += 1
        elif "PRIV_CHANGE" in line.upper():
            privileged_count += 1

# next steps are to read each line into the internal structure on page 8
# and group them into mini sections with
# timestamp: extract the timestamp from each log entry for further analysis
# user: extract the user involved in each log entry for further analysis
# event: extract the event in each log entry for further analysis
# ip: extract the IP address from each log entry for further analysis
# message: extract the message from each log entry for further analysis
#  Then to analyze the data for patterns, trends, and store them into a
# document for analysis.  The document will be used to create a report for the client.

# Below is some of the output code.
print("First line of the log file:")
print(first_line.strip())
print("=======================")

print("Total log entries:", total_count)
print("Failed authentication attempts:", failed_count)
print("Privileged access attempts:", privileged_count)
