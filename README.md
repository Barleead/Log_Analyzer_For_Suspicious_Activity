# Log Analyzer for Suspicous Activity

Analyst: Barbara Adkins

Role: Jr. Security Analyst

### Purpose of the project

I was given the task to use Python to build a log analysis tool that would go through log entries and find suspicious events that occured. These would include failed logins (AUTH_FAIL), questionable IP addresses and activiyt related to user privilege.

### How to run the project

I use VS Code as my editor. If you would like to download it, go to https://code.visualstudio.com/Download?_exp_download=fb315fc982 and click the download option for your OS.

If you have another program that will run .py files and read .txt files that will work as well.

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

go to github using this link https://github.com/Barleead/Log_Analyzer_For_Suspicious_Activity

Clone the project by clicking the arrow to the right of the code button and chose the option to clone (using the url) or clicking the link for downloading a .zip file.

To clone:

open command prompt/terminal navigate to where you would like to store the project and then type "git clone" and then paste the url and click enter.

To use the .zip file:
After chosing a location for download site. After it has finished downloading. Open VS Code, then chose File -> open folder and navigate to your download.

After it opens, chose the log_analyzer.py file and then run. The results appear in the terminal and are also saved to the findings.txt file for ease in reviewing.

### Challenges

###required files

you will need log_analyzer and sample.txt to run the project
###explanation of detections
###optional features implemented
