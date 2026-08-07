# Log Analyzer for Suspicious Activity

Analyst: Barbara Adkins

Role: Jr. Security Analyst

---

---

### Purpose of the project

I was given the task of building a log analysis tool that would go through log entries and identify suspicious events that had occured. These would include failed logins (AUTH_FAIL), questionable IP addresses and activity related to user privilege changes (PRIV_CHANGE).

### How to run the project

This program was created using Visual Studio Code and the Python programming language.

If you would like to run the project in a virtual environment:

In command prompt/terminal type:

**Windows**

1. python -m venv venv
2. source venv\Scripts\activate
3. pip install -r requirements.

**Linux/Mac0S**

1. python3 -m venv venv
2. source venv/bin/activate
3. pip install -r requirements.txt

Once in the project folder, from the terminal window type "python log_analyzer.py" and hit enter. You can also, select log_analyzer.py on the left side Explorer list and then use the play button which can be found in the upper right of the of the log_analyzer.py window.

As the program runs the search results are output to the file findings.txt and to the terminal screen.

### Detections and what they mean

#### Log file verification (line 6 of findings.txt)

This is purely informational as it is the first line of sample_log.txt. It provides the analyst with a visual representation of the types of information and the format it follows.

This provides information regarding the content in sample_log.txt. It gives the analyst the following information:

The total number of log entries in the text file. The analyst can use this to determine relevance based on the size sample.  
The total number of entries that have AUTH_FAIL (authorization failure) as the event.
The total number of PRIV_CHANGE (privilege change) events in the log file.
A cumulative total of both PRIV_CHANGE and AUTH_FAIL events, sorted by IP address
The number of IP addresses with PRIV_CHANGE and AUTH_FAIL events, respectfully.

Some of the data in findings.txt is simply for information as, in and of itself, it doesn't provide details, just values. However, some of the data gives a direction for further troubleshooting. Any excessive number could be a potential attack and should be investigated further. For example, on line 21 in findings.txt, 3 of the 4 IP addresses listed are internal addresses, however, the last IP address is most concerning because there are over twice as many authorization failures than are listed for the other three. Starting with line 146, which expands on line 21, the same IP address of 51.185.130.223 is used with individual usernames, 80 separate ones. Some of the usernames follow no standard format, for example, " @@@\*$)!^" is listed as a user with this IP address. Since this IP address is not internal, investigation into possible reasons for these attempts is needed because of the unusual number of users associated with one IP address.

NOTE: The IP addresses on line 21 are followed by the number of times the IP address was found. For example, "10.0.2.87" : 29.

#### Suspicious User Login Patterns (line 27)

This section displays any user that has five or more failed login attempts. All of these should be analyzed further but users "root" and "admin" are most concerning, because if an unauthorized person gains root or admin access to a network, they can cause loss of money, proprietary data, steal employees personal information.

#### Suspicious IP Activity (line 46)

IP addresses are paired with AUTH_FAIL events in this section. At a glance, the analyst can see if the results are unusual. This section provides a more verbose description of the IP information found in the Summary of Key Statistics section.

#### Privilege Change Events (line 62)

These events show the user, how many privilege change events each had and the IP addresses associated with each. This information on one line can help analysts by showing the information all at one time.

#### User Authorization Changes (line 139)

This will help analyst by keeping key information together and in a readable format. This section shows that the first five users correlate with different IP addresses with multiple attempts. This raises the question, why would any user be associated with separate IP addresses. The answer could be as simple as the use of a work laptop, phone and /or tablet. Having many users trying to log in from the same IP address is concerning as this may be indicators of a malicious attack.

### Required Files:

sample.txt

log_analyzer.py

python (needs to be installed on your computer. It can be found at python.org)

### Optional Features

The program's output, the same information that appears in the terminal, is sent to the findings.txt file so that it can be reviewed independently.

### Challenges and Next Steps

This was challenging because I wasn't sure of my programming skills and as I learned, my logic in the programming was sometimes unclear. The wrong variables were used in the wrong way. I used a badly titled variable as a list when a dictionary was needed and vice-versa.

I utilized the "try harder" mantra and didn't give up, as I was tempted to do. There was a lot of trial and error and asking myself many questions as to what wasn't working or researching error terms I didn't know right away. For example, I got an error telling me my variable wasn't declared but it was, I thought. The local library became my friend during my research.

For next steps, I am thinking about using sample.txt and writing the same program utilizing python, pandas and sql. That would be a fun project. Also, possibly expanding both with timestamp and message information which would provide more information for an analyst.
