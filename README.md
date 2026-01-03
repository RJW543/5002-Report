GitHub Link: https://github.com/RJW543/5002-Report.git
YouTube Link: 

1	Introduction 
1.1	Context and Situational Awareness 
This report examines a suspected security incident at Frothly, a brewing company. As a Security Operations Centre (SOC) analyst, I established situational awareness of potential malicious activity within the corporate network by analysing the BOTSv3 (Boss of the SOC) dataset [8] using Splunk Enterprise, a Security Information and Event Management (SIEM) platform. The BOTSv3 dataset simulates a realistic enterprise environment with logs from Windows Event Logs, Sysmon, Osquery, and network stream data.

1.2	Incident Management Framework 
Following the NCSC Incident Management lifecycle [9] (Identify → Protect → Detect → Respond), this investigation focuses on Detection and Analysis. IOCs were verified through cross-referenced log analysis rather than single data points.

1.3	Objectives
The specific objectives of this investigation were to:
 - Identify the initial access vector used by the threat actor to infiltrate the network.
 - Analyse the behaviour of the intruder, including lateral movement, privilege escalation, and persistence mechanisms.
 - Verify IOCs such as malicious file hashes, command and control (C2) traffic, and unauthorised user account creation.
 - Formulate evidence-based recommendations to contain the incident and eradicate the threat from the Frothly environment.
[10]

1.4	Scope and Assumptions 
 - Scope: The analysis is limited to the telemetry provided in the BOTSv3 dataset, specifically focusing on the timeframe surrounding August 2018, where anomalous activity was detected. Key assets investigated include the workstation FYODOR-L and the Linux server hoth.
 - Assumptions: It is assumed that the log ingestion is complete for the period of the attack, though potential gaps in specific logging capabilities (e.g., missing Sysmon events for certain actions) were noted and mitigated through pivot analysis. The analysis assumes the role of a Tier 2 SOC Analyst, responsible for deep-dive investigation following initial triage.
2	SOC Roles & Incident Handling Reflection
2.1	SOC Structure and Analyst Responsibilities
A modern SOC uses tiered roles to manage high-volume security telemetry. The BOTSv3 investigation required shifting between these tiers:
 - Tier 1 (Triage Specialist): Filtered high-volume logs to identify genuine anomalies, such as sifting through SMTP streams to locate the "Malware Alert Text.txt" attachment 
 - Tier 2 (Incident Responder): Conducted deep-dive analysis, correlating data points (e.g., linking excel.exe execution to hdoor.exe creation) to construct the attack timeline
 - Tier 3 (Threat Hunter): When automated alerts failed (missing Sysmon EventCode 11 for file creation), employed proactive hunting by searching C:\Windows\Temp*.exe, successfully uncovering embedded malware in temporary directories (Figure 1)

2.2	Incident Handling Methodology
Following the NCSC Incident Management framework [9] (Identify → Protect → Detect → Respond), the Frothly incident analysis reveals:
Prevention & Protection (Failure Analysis)
The macro-enabled spreadsheet (Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm) executed successfully, indicating inadequate endpoint security and email filtering failures.
Detection & Analysis
Detection identified abnormal network and endpoint behavior:
 - Network Artifacts: HxTsr.exe communications revealed the C2 channel
 - Endpoint Artifacts: EventCode 4720 [11] and 4732 [12] showed backdoor account svcvnc creation and Administrators group elevation
Response (Containment & Eradication)
Live SOC response would require:
1.	Isolate: FYODOR-L and hoth from the network to prevent lateral movement
2.	Block: C2 IP and port 1337 at the firewall
3.	Eradicate: Disable accounts svcvnc and tomcat7; remove hdoor.exe and 3791.exe binaries
Recovery & Post-Incident Activity
Compromised hosts should be reimaged rather than cleaned [9], as persistence mechanisms (scheduled tasks, registry keys) are difficult to fully remove. The organization must enforce "block all macros except digitally signed" policies to prevent recurrence.

3	Installation & Data Preparation (15%)
3.1	SOC Infrastructure & Architecture
The forensic environment simulated a SOC Analyst Workstation:
 - SIEM Platform: Splunk Enterprise 8.x on virtualised Kali Linux
 - Dataset: BOTSv3 containing pre-indexed telemetry from Frothly's simulated corporate network
Justification: Splunk's ability to ingest, index, and correlate unstructured machine data in real-time supports the NCSC Detect phase by enabling cross-layer correlation (e.g., linking network streams to process execution), which is impossible when analysing logs in isolation.

3.2	Dataset Ingestion Strategy 
The BOTSv3 dataset was ingested using a pre-indexed app to ensure data integrity and query performance:
1.	Installation: The BOTSv3 app was installed via Splunk Web Interface (Manage Apps > Install app from file), preserving original timestamps, sourcetypes, and host extractions 
2.	Index Segregation: All data was confined to index=botsv3, mirroring production SOC environments where investigation data is segregated to prevent cross-contamination and optimise search performance

3.3	Validation & Due Diligence
Prior to investigation, the dataset was verified to ensure completeness and prevent false negatives from logging gaps.
Validation Steps Taken:
 - Sourcetype Verification: Query index=botsv3 | stats count by sourcetype confirmed presence of critical log sources: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (endpoint visibility), stream:http (network visibility), and osquery:results (Linux visibility)
 - Timeframe Normalisation: Event timeline analysis identified a distinct activity cluster in August 2018, establishing the incident window and filtering background noise

3.4	Challenges & Field Extraction
Certain Splunk field extractions were inconsistent (e.g., DestinationPort in Sysmon EventCode 3 not automatically parsed), risking missed evidence. To mitigate this, the investigation employed Tier 3 Threat Hunting methodology, augmenting structured field searches with raw text searching (e.g., term("1337")) and regex-based extraction to ensure complete artifact discovery despite parsing failures. 

4	Investigation & Findings (40%)
This section details the forensic analysis conducted to answer the guided investigation questions (BOTSv3 300-level). Each finding is supported by a documented methodology, specific Splunk queries, and verified evidence.

4.1	Question 1: Initial Access (User Agent Identification)
Objective: Identify the User Agent string used by the attacker to upload the malicious document to the organisation's OneDrive storage.

Methodology:
The investigation began by analysing Cloud audit logs (ms:o365:management) to identify file upload events (Workload=OneDrive) related to the known malicious file. Once the specific upload event was isolated, the UserAgent field was examined to determine the source software used by the attacker. This distinguishes between legitimate browser-based uploads and automated scripts or non-standard clients.

Splunk Query: 
index=botsv3 sourcetype="ms:o365:management" Workload=OneDrive 
| stats count by Operation
| sort - count

index=“botsv3” sourcetype=”ms:o365:management” Workload=OneDrive
| spath
| search Operation=FileUploaded
| eval filename=coalesce(SourceFileName, Filename, ObjectId, ItemName)
| where match (filename, “\.lnk$”)
|  table _time UserId ClientIP Operation filename UserAgent
| sort 0 - _time

index=“botsv3” sourcetype=”ms:o365:management” Workload=OneDrive
| spath
| eval filename=coalesce(SourceFileName, Filename, ObjectId, ItemName)
| where match (filename, “\.lnk$”)
| eval ua=mvindex(UserAgent, 0)
| table _time UserID ClientIP filename ua

Evidence:

SOC Relevance:
User Agent analysis is a key component of "Situational Awareness". Identifying a non-standard or Linux-based User Agent (e.g., Mozilla/5.0...Linux...) accessing corporate OneDrive accounts is a high-fidelity Indicator of Compromise (IOC) that can be used to create detection rules for future anomalies.
Answer: Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1–2.5.rs3.0 NaenaraBrowser/3.5b4
4.2	Question 2: Delivery Vector (Malicious Attachment) - 335
Objective: Identify the malicious email attachment responsible for delivering the initial payload, using telemetry that records email/attachment metadata and contents.

Methodology:
1.	Pivoted to email telemetry in Splunk (stream:smtp) because the question stated the “attachment” was already discovered in the previous step.
2.	Filtered specifically for the attachment named Malware Alert Text.txt.
3.	Normalised the raw event (_raw) to make regex extraction reliable (removed \x0D, de-escaped backslashes, removed newlines).
4.	Extracted attachment filenames using rex on the MIME filename="..." field.
5.	Used a second rex to hunt inside the attachment content for macro-enabled Office document extensions (especially .xlsm), because the task hint explicitly pointed to macro-enabled extensions being useful.
6.	Confirmed the document name by decoding the Base64 blob of the attachment externally (terminal), then searching the decoded output for the .xlsm filename (as shown in Figure 3).

Splunk Query:
index=botsv3 sourcetype="stream:smtp"
| eval raw2=_raw
| eval raw2=replace(raw2,"\x0D","")
| eval raw2=replace(raw2,"\\\\","\\")
| eval raw2=replace(raw2,"\r\n","")
| rex field=raw2 "(?i)\bfilename=\"(?<attachment>[^\"]+)\""
| search attachment="Malware Alert Text.txt"
| rex max_match=0 field=raw2 "(?i)(?<macro_file>[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\.(?:docm|dotm|xlsm|xltm|pptm|potm|ppsm|sldm|ppam|doc|dot|xls|xlt|ppt|pot|pps))"
| mvexpand macro_file
| table _time attachment macro_file

Evidence:

SOC Relevance: 
 - Email triage & rapid containment: Identifying the exact malicious attachment (Malware Alert Text.txt) and the referenced macro-enabled document (Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm) lets the SOC immediately scope impact (who received it, who opened it) and take containment actions such as quarantining the message, blocking sender/domain, and purging the attachment from mailboxes.
 - Detection engineering: The presence of a macro-enabled Office file extension (.xlsm) is a high-signal indicator for phishing/malspam. SOC teams can build detections on:
o inbound emails with macro-enabled attachments,
o suspicious attachment names/subjects,
o Base64/MIME patterns linked to embedded content.
 - User awareness & reporting: Clear identification of the “what” and “how” supports user comms (“Do not open X / report emails containing Y”), improving organisational resilience and reducing dwell time.

Answer: Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm
4.3	Question 3: Installation (Embedded Executable) 
Objective: Determine the name of the executable embedded/dropped by the malware originating from the malicious Excel macro document.

Methodology:
1.	Started with Sysmon Operational logs as instructed (XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) and attempted to locate file creation events where Excel created/dropped an .exe (commonly Sysmon EventCode=11 for FileCreate).
2.	The initial Sysmon approach returned no results (likely due to field/value differences in the dataset and/or how the specific events were captured), so a broader pivot was required.
3.	Pivoted to a more generic dataset-wide approach by enumerating executables observed in the environment using the pn (process name) field.
4.	Counted all *.exe values in pn to identify suspicious/standout executables.
5.	Identified HxTsr.exe as a high-signal, unusual executable name.
6.	Confirmed by searching directly for pn="HxTsr.exe" and reviewing returned events to validate it was active on the compromised endpoint during the compromise window (as shown in Figure 4).
7.	Based on that pivot + confirmation, concluded the embedded/dropped payload executable name was HxTsr.exe.

Splunk Queries:

index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 Image="*excel.exe" TargetFilename="*.exe"

index=botsv3 pn=*.exe
| stats count by pn
| sort -count

index=botsv3 pn="HxTsr.exe"

Evidence:

Figure 7 shows:
 - The Sysmon-based attempt returning no results (justifying the pivot).
 - The pn=*.exe | stats count by pn enumeration where HxTsr.exe appears as a standout executable.
 - The focused search pn="HxTsr.exe" showing the supporting events that confirm it is present/active on the compromised endpoint.

SOC Relevance:
 - Endpoint containment & scoping: Knowing the dropped/embedded payload name (HxTsr.exe) gives the SOC a concrete pivot for endpoint response: isolate affected hosts, collect file artefacts, check persistence mechanisms, and identify lateral movement from processes spawned by that executable.
 - IOC-driven detection: The payload name can be turned into actionable detections across EDR/SIEM:
o	process execution (pn=HxTsr.exe),
o	file creation/write events (where available),
o	parent-child relationships (e.g., Office → payload),
o	command-line patterns associated with HxTsr.exe.
 - Kill chain linkage: Mapping “macro doc → dropped EXE” helps analysts document and prove the attack chain (initial access → execution → payload deployment), which is essential for incident reporting, timeline building, and eradication planning.
 - Hardening & prevention: This finding supports preventative controls such as blocking Office macro execution from the internet, tightening application allowlisting, and enforcing ASR rules (e.g., blocking Office from creating child processes) to prevent the same technique from succeeding again.

Answer: HxTsr.exe

4.4	Question 4: Persistence (Linux Account Creation)
Objective: Identify the password for the backdoor user account created by the root user on the Linux server hoth.

Methodology:
The investigation shifted to the Linux endpoint hoth, utilising Osquery logs to inspect command-line execution history. A search for account creation commands (useradd OR adduser) filtered by the root user revealed a command where the attacker inadvertently passed the password in plain text using the -p flag.

Splunk Query:
Code snippet
index=botsv3 host="hoth" useradd

Evidence:
SOC Relevance:
Capturing the password (ilovedavidverve) allows the SOC to check if this credential has been reused on other compromised systems (Credential Stuffing). It also highlights a critical OPSEC failure by the attacker and a training need for administrators regarding secure command-line practices.
Answer: ilovedavidverve

4.5	Question 5: Persistence (Windows Account Creation) – 107
Objective: Identify the name of the user account created on the compromised Windows endpoint to establish persistence.

Methodology:
Following the confirmation of the beaconing activity, the investigation focused on host-based persistence mechanisms. I queried the Windows Security Event Logs for Event Code 4720 ("A user account was created"). This search identified the anomalous creation of the user svcvnc by the compromised account FyodorMalteskesko.

Splunk Query:
Code snippet
index=botsv3 sourcetype="WinEventLog:Security" EventCode=4720

Evidence:
SOC Relevance:
The username svcvnc attempts to masquerade as a legitimate "Service VNC" account. Identifying this account allows the SOC to audit all actions performed by this specific Security ID (SID) to determine the full scope of lateral movement and data exfiltration.
Answer: svcvnc
4.6	Question 6: Privilege Escalation (Group Assignments) – 116
Objective: To identify the specific local groups the compromised user svcvnc was added to, indicating the level of privilege the attacker achieved.
Methodology: To determine the extent of the compromise, the investigation focused on Privilege Escalation (MITRE ATT&CK T1098). I queried the Windows Security Event Logs for Event Code 4732 ("A member was added to a security-enabled local group"). I filtered specifically for the user svcvnc to track group membership changes. The analysis revealed two distinct events where the user was added to the Users group (default) and, critically, the Administrators group.
Splunk Query:
index=botsv3 sourcetype="WinEventLog:Security" EventCode=4732 "svcvnc" 

Evidence: 

SOC Relevance: The addition of a user to the Administrators group is a critical severity event ("Game Over"). 
 - Impact: It indicates the attacker has achieved full system control, allowing them to disable antivirus, wipe logs, install rootkits, or dump credentials (e.g., Mimikatz).
 - Response: This triggers an immediate Tier 1 escalation. The machine must be taken offline and is generally considered untrusted/unrecoverable without a full re-image.
Answer: Administrators,User
4.7	Question 7: Command & Control (Backdoor Port) 
Objective: Determine the Process ID (PID) of the malicious process listening on the non-standard "leet" port (1337) on the Linux server.

Methodology:
To verify the active backdoor on the Linux host hoth, I utilised Osquery data, specifically the listening_ports table. I searched for local connections on port 1337 (a common "leet" speak reference). This allowed me to map the open network port directly to the specific process ID responsible for the connection.

Splunk Query:
Code snippet
index=botsv3 host="hoth" 1337
Evidence:
SOC Relevance:
Correlating network ports to Process IDs is a fundamental SOC skill. While a firewall log shows a connection, it does not identify the cause. By pivoting to Osquery, we confirmed that the open port was not a misconfigured service but a specific malicious process (likely netcat), necessitating immediate termination of that PID.
Answer: 14356

4.8	Question 8: Reconnaissance (Scanning Tool Identification) 
Objective: Identify the MD5 hash of the file downloaded to FYODOR-L and used to scan the Frothly network.
Methodology:
 - Phase 1 (Threat Hunting): Initial network analysis indicated scanning behaviour, but specific attribution was difficult. I pivoted to a file-system hunt, hypothesising that attackers often execute tools from temporary directories to bypass permissions. A search for executables in C:\Windows\Temp identified the suspicious binary hdoor.exe.
 - Phase 2 (Verification): To generate a verifiable IOC, I searched for the Sysmon "Process Create" event (Event Code 1) for this file, which contains the cryptographic hash.

Splunk Query:
Code snippet
index=botsv3 host="FYODOR-L" "C:\\Windows\\Temp" ".exe"

Evidence:
SOC Relevance:
Collecting the MD5 hash (586...5D7) allows the SOC to implement the Protect phase. This hash can be added to EDR blocklists to neutralise the tool across the entire enterprise, even if the attacker renames the file to evade detection.
Answer: 586EF56F4D8963DD546163AC31C865D7

5	Conclusion & Recommendations
5.1	Incident Summary
The BOTSv3 investigation confirmed a multi-stage intrusion with clear attack progression:
1.	Initial Access: Spear-phishing delivered macro-enabled Excel document (Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm)
2.	Execution & Installation: Macro dropped HxTsr.exe and hdoor.exe into C:\Windows\Temp to bypass permission checks
3.	Persistence & Privilege Escalation: Established persistence via svcvnc (Windows) and tomcat7 (Linux) accounts
4.	Command & Control: Backdoor on server hoth using port 1337 netcat listener
5.2	Key Lessons & SOC Strategy Implications - 54
The incident highlights critical "Protect" phase gaps. While "Detect" capabilities (Splunk, Osquery, Sysmon) enabled retroactive investigation, lack of proactive blocking allowed attack success.
Strategic Implications:
 - Situational Awareness: SOC lacked real-time alerting for high-fidelity IOCs (useradd by root, EventCode 4720 on workstations)
 - Defense in Depth: Unsigned macro execution indicates endpoint hardening failures requiring "Prevention-first" strategies

5.3	Improvements for Detection and Response 
Recommended improvements aligned with the incident lifecycle:
Protect (Hardening):
 - Enforce GPO to block macros in Office documents from the internet
 - Implement AppLocker to prevent binary execution from C:\Windows\Temp and %APPDATA%
Detect (SIEM Tuning):
 - Alert on HxTsr.exe, svchost.exe, or explorer.exe with parent process excel.exe or winword.exe
 - High-severity alert for EventCode 4732 on non-Domain Controller endpoints
Respond (Playbooks):
 - Automated isolation playbook to quarantine endpoints with C2 behavior (e.g., outbound port 1337)

6	References
1.	J. Chin, COMP5002 Module Handbook, University of Plymouth, 2025.
2.	J. Chin, "Lecture 01: Introduction to Situational Awareness," University of Plymouth, 2025.
3.	J. Chin, "Lecture 02: IDS and Prevention," University of Plymouth, 2025.
4.	J. Chin, "Lecture 03: Intruder Behaviour & TCP Basics," University of Plymouth, 2025.
5.	J. Chin, "Lecture 06: Network Traffic Analysis," University of Plymouth, 2025.
6.	J. Chin, "Lecture 09: Security Information and Event Management (SIEM)," University of Plymouth, 2025.
7.	J. Chin, "Lecture 11: Incident Handling," University of Plymouth, 2025.
8.	Splunk Inc., "Boss of the SOC (BOTSv3) Dataset," 2018. [Online]. Available: https://github.com/splunk/botsv3.
9.	NCSC, “Incident management,” ncsc.gov.uk, 2020. https://www.ncsc.gov.uk/collection/incident-management
10.	A. Nelson, S. Rekhi, M. Souppaya, and K. Scarfone, “Incident Response Recommendations and Considerations for Cybersecurity Risk Management”:, NIST, Apr. 2025, doi: https://doi.org/10.6028/nist.sp.800-61r3.
11.	vinaypamnani-msft, “4720(S) A user account was created. - Windows 10,” learn.microsoft.com, Sep. 07, 2021. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720
12.	vinaypamnani-msft, “4732(S) A member was added to a security-enabled local group. - Windows 10,” learn.microsoft.com, Sep. 07, 2021. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732
7	AI declaration








