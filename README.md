\# WinLog Sentinel



WinLog Sentinel is a Python + Streamlit project for analyzing Windows Event Log `.evtx` files. It parses uploaded EVTX files, extracts event details, detects suspicious behavior, and shows a simple dashboard with findings, failed logons, and risk level.



\## Features



\- Upload Windows `.evtx` files

\- Parse Event ID and timestamp from EVTX records

\- Detect suspicious Windows and Sysmon events

\- Count failed logons

\- Show a risk summary

\- Export findings to CSV



\## Project Structure



```text

WinLogSentinel/

│

├── app.py

├── detector.py

├── detections.py

├── evtx\_parser.py

├── risk\_engine.py

├── report\_exporter.py

│

├── output/

├── sample\_logs/

│

├── requirements.txt

└── README.md

```



\## Supported Detections



Current detections include common Windows Security and Sysmon events such as:



\- 4624 — Successful Logon

\- 4625 — Failed Logon

\- 4661 — Sensitive Object Access

\- 4672 — Admin Privileges Assigned

\- 4720 — User Account Created

\- 4726 — User Account Deleted

\- 4732 — Added to Local Group

\- 4740 — Account Locked

\- 4798 — User Enumeration

\- 4799 — Group Enumeration

\- 7045 — Service Installed

\- 1102 — Audit Log Cleared

\- Sysmon 1, 3, 6, 10, 18



\## Installation



\### 1. Clone the repository



```bash

git clone https://github.com/YOUR-USERNAME/WinLogSentinel.git

cd WinLogSentinel

```



\### 2. Create a virtual environment



\#### Windows

```bash

python -m venv venv

venv\\Scripts\\activate

```



\#### Mac/Linux

```bash

python3 -m venv venv

source venv/bin/activate

```



\### 3. Install dependencies



```bash

pip install -r requirements.txt

```



\### 4. Run the app



```bash

streamlit run app.py

```



\## How to Use



1\. Launch the Streamlit app.

2\. Upload a `.evtx` file.

3\. Review the dashboard:

&#x20;  - Total Events

&#x20;  - Findings

&#x20;  - Failed Logons

&#x20;  - Risk Level

4\. Check detected threats and detailed findings.

5\. Export the report as CSV.



\## Sample Logs



You can place test `.evtx` files inside the `sample\_logs/` folder and use them to validate detections.



\## Output



Exported CSV reports are saved in the `output/` folder.



\## Why This Project



This project demonstrates:



\- Python scripting

\- Windows Event Log analysis

\- Basic detection engineering

\- Streamlit dashboard development

\- Cybersecurity portfolio building



\## Disclaimer



This tool is for educational and defensive security purposes only.

