\# AI SOC Agent



AI SOC Agent is a cybersecurity incident analysis tool built with Python.



\## Features



\- Detects Brute Force attacks

\- Detects SQL Injection attempts

\- Detects XSS attempts

\- Detects API Abuse

\- Detects Session Hijacking

\- Maps incidents to MITRE ATT\&CK

\- Generates recommended remediation actions

\- Exports incident reports to JSON



\## Run



```bash

python agent.py



\## MCP Integration



This project includes an MCP server exposing SOC analysis tools:



\- `soc\_map\_attack`

\- `soc\_calculate\_severity`

\- `soc\_map\_mitre`

\- `soc\_recommend\_actions`



The MCP client successfully calls the server and returns:



```text

Attack: Brute Force

Severity: High

MITRE: T1110 - Brute Force

Actions: Block source IP



\## Current MCP Test Output



The MCP client successfully analyzes multiple security incidents:



\- Brute Force

\- SQL Injection

\- XSS

\- API Abuse

\- Session Hijacking



Each incident returns:



\- Attack type

\- Severity

\- MITRE ATT\&CK technique

\- Recommended remediation actions

