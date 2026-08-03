# Log Analyzer for Suspicous Activity

Analyst: Barbara Adkins

Role: Jr. Security Analyst
________________________________

________________________________
### Purpose of the project

I was given the task to use Python and Visual Studio Code to build a log analysis tool that would go through log entries and identify suspicious events that occured. These would include failed logins (AUTH_FAIL), questionable IP addresses and activity related to user privilege (PRIV_CHANGE).  

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

Once in the project folder, from the terminal window type "python log_analyzer.py" and hit enter.  You can also, select log_analyzer.py on the left side Explorer list and then use the play button ![Play button](image.png) This can be found in the upper right of the of the log_analyzer.py window. 

As the program runs detections are output to the file findings.txt.  A description of each section can be found in the section of the readme entitled "

### DETECTIONS AND WHAT THEY MEAN


### Required Files:

sample.txt

log_analyzer.py

python (needs to be installed on your computer. It can be found at python.org)



### Optional Features
 
The programs output, the same information that appears in the terminal, is sent to the findings.txt file so that it can be reviewed independently.

### Challenges and Next Steps

before I turn it in.. out put the total number of ips, auth fail ips and priv change ips to findings.txt