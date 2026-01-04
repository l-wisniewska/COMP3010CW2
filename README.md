# COMP3010CW2
BOTSv3 Incident Analysis and Presentation

Introduction:

Introduction:
Modern organisations rely on Security Operations Centres, these can be defined as a centralised unit that deals with issues on an organisational level, plus a team primarily composed of security analysts organised to detect, analyse, respond to, report on and prevent Information Security (IS) incidents. [1] SOC teams use specialised tools to collect security logs from servers, laptops, cloud services and network devices so that suspicious activity can be detected and investigated quickly. The tool I will be using in this report, Splunk, is widely used in this area which allows analysts to search and visualise security data.
This report focuses on the use of the BOTSv3 (Boss of the SOC, Version 3) which is a pre indexed Capture the Flag (CTF) dataset created by Splunk. Botsv3 simulates a realistic multi-stage cyber-attack against the fictional organisation called Frothly, a global beverage company. The dataset includes extensive logs from network devices, authentication systems, endpoints, cloud platforms such as AWS and Azure, email systems and web infrastructure. In this report I will be analysing these logs using Splunk’s Search Processing Language (SPL) to reconstruct the attack chain and answer the guided questions provided along with the cyber kill chain methodology.
The objective of my investigation is to apply SOC principles, specifically detection, analysis and incident handling, to the Botsv3 dataset, the scope being limited to the 200-level Botsv3 investigative questions. I will be approaching this exercise as if it were affecting a genuine company and later I will expand on the business impact and cost modelling based on the security information I find in the questions provided.

SOC roles and incident handling reflection:

Security Operation Centres typically operate using a tiered model to ensure efficient assessment, escalation and analysis. The procedure is initially operated by Tier 1 analysts which are responsible for initial alert monitoring and basic investigations, they validate potential incidents, filter out any false positives and escalate any genuine issues that arise following these investigations. Within Botsv3, the tier 1 responsibilities would be identifying any suspicious authentication attempts, unusual process events or anomalous network patterns using simple SPL queries.
Following the escalation of any genuine issues tier 2 analysts, or incident responders, preform deeper investigations which entails correlating multiple log sources, determining attack scope and identifying the root causes. In Botsv3 this will looks like reconstructing the attackers actions across Frothly’s endpoint, cloud and network logs, for example connecting malicious AWS events to suspicious activity to understand lateral movement.

The last stage of this tiered model is the tier 3 analysts, also known as Threat Hunters and Detection engineers, these people focus on advanced analytics, detection rule creation, and uncovering behaviours that may bypass the standard alerting systems. In Botsv3 this can be reflected as identifying patterns which are not directly surfaced through the dashboard, such as abnormal API usage or persistence mechanisms.

SOCs operate according to a structed incident handling lifecycle, this begins with prevention, which includes hardening systems and configuring logging, this is represented in this report by Splunk installation and data ingestion. The ways of detection in the Botsv3 dataset is shown through the use of SPL queries to identify indicators of compromise and map them to the cyber kill chain. The next step is response; this involves interpreting the impact of the events that have been discovered and determining what containment methods would be most applicable such as locking accounts or isolating any compromised assets. The final steps are recovery and how to use such a breach as a learning point on where to strengthen security, improve monitoring or implementing better cloud governance to prevent a recurrence of such events. This Botsv3 exercise effectively mirrors these workflows by requiring multilayer analysis, cross-log correlation and an applied understanding of SOC roles and responsibilities. 

Installation and data preparation:

A functional Security Information and Event Management (SIEM) platform requires a reliable process for ingesting, normalising and validating security logs. In a real SOC environment, this ensures that analysts have full visibility of all running systems and can detect any malicious activity in a timely manner. The quality and proper structure of the indexed data needs to be properly maintained as any lacks or issues with the completeness of log data can severely impact the organisations’ ability to detect and respond to any security incidents occurring as well as even understanding what is occurring. This can have extreme consequences and may cause incorrect or worse, a lack of, effective remediation measures.
To conduct this security investigation, I established a controlled analysis environment using Splunk Enterprise, a SIEM solution widely deployed across a range of financial, healthcare and technology sectors for security monitoring and incident response. The installation was performed on a dedicated virtual machine, which provides an isolated environment that prevents any potential security risks from affecting production systems. This approach mirrors real world SOC practices where analysis od potentially malicious data is conducted in segregated environments to maintain operational security.

Splunk Enterprise was installed locally on Ubuntu and during installation a dedicated administrative account was configured, and the default web interface was enabled on port 8000. This setup mirrors the access model commonly used in SOCs, where analysis authenticate into Splunk Web for search, dashboard use and triage activities. The Botsv3 dataset was downloaded from the github link provided and copied into the splunk app through the ubuntu terminal, this dataset contains indexed security event data spanning multiple days of simulated operations. After data ingestion the command index=”botsv3” with the time span of “all time” was ran to insure data quality and that all of the data was showing, this was checked by making sure the number of events equalled 2,083,056. 

The screenshots provided demonstrate successful completing of both the Splunk installation (Figure 1) and the Botsv3 dataset upload (Figure 2), confirming all data was accessible and searchable through Splunk’s interface. 
Figure 1
![screenhot of virtual machine terminal downloading splunk](screenshots/SplunkDownload.png)

Figure 2
![screenshot of virtual machine terminal and splunk page uploading botsv3 successfully](screenshots/Botsv3Splunk.png)

Guided Questions:
Q1: IAM users who accessed AWS services
The first question asks to find all legitimate AWS users, so we have a baseline to identify any potential unauthorised access.
The SPL query used:
sourcetype="aws:cloudtrail"
| stats values(userIdentity.userName) AS users
This query filters all CloudTrail events and extracts unique usernames from the userIdentity.userName field. The stats values() function gets rid of any duplicates and provides a comprehensive list of all the users who accessed AWS services during the incident window, four IAM users were identified:
Answer: bstoll,btun,splunk_access,web_admin
I also have provided a bar chart visualisation of the volume of API calls per user which can help us identify which accounts exhibited unusual activity levels. In order to generate this the following SPL query was used: | stats count BY userIdentity.userName | sort -count

Q2: Field for detecting AWS API calls without MFA
In this question I have to find the field which indicates whether Multi-Factor Authentication (MFA) was used, as non-MFA authentication represents a security weakness. 
The SPL query used:
sourcetype="aws:cloudtrail" *MFA* 
MFA is a critical security feature that requires users to provide two forms of verification before accessing systems, attackers who are able to compromise credentials but lack the second factor are unable to access MFA protected resources. I searched through CloudTrail logs for fields related to MFA to determine how to detect authentication events lacking this protection. The query uses the wildcard search *MFA* which identifies all events containing MFA related information, by examining the available fields I identified the specific field that tracks MFA status for each API call, which was:
Answer: userIdentity.sessionContext.attributes.mfaAuthenticated
I have also attached a pie chart comparing MFA-authenticated vs non-MFA authenticated API calls, this highlights the proportion of potentially vulnerable sessions, this was created by using this SPL query: sourcetype="aws:cloudtrail" userIdentity.sessionContext.attributes.mfaAuthenticated=* | stats count BY userIdentity.sessionContext.attributes.mfaAuthenticated

Q3:  Processor number used on the web servers
In order to understand the product environment configurations and setup we must figure out the hardware specifications it is running on; this is relevant to security operations when analysing performance anomalies or when there are specific hardware vulnerabilities being targeted.
The SPL command used:
sourcetype="hardware"
| stats values(cpu) by host
When dealing with security incidents such as these it is helpful to know the technical specifications of the systems involved so that technical analysis and capacity planning is easier to carry out. I queried hardware monitoring logs to identify the CPU models deployed on Frothly’s webservers, it examined the hardware monitoring data and grouped CPU information by hostname, which gave me this:
Answer: E5-2676 (Intel Xeon)

Q4: Event ID enabling public S3 access
This question asks to determine which specific action made sensitive data publicly accessible, amazon S3 buckets are private by default, but can be maliciously configured to allow public access.
The SPL command used:
sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
I searched CloudTrail logs for an event called PutBucketAcl, this API call modifies a buckets Access Control List (ACL) which defines who can access the bucket, and in this case when public access was granted PUT TIME. The security implications of such an event occurring are critical and show a security control failure. In real life cloud environments, changing bucket ACLs to public should trigger immediate alerts and require management approval. In this specific scenario, this can happen due to an insider threat, compromised credentials or a misconfiguration by an administrator who did not understand the security implications.
Answer: ab45689d-69cd-41e7-8705-5350402cf7ac
Below I also have shown a timeline visualisation of when this critical security event occurred telative to any other suspicious activities, for this is used this query: sourcetype="aws:cloudtrail" eventName="PutBucketAcl" | timechart count BY eventName

Q5: Bud’s Username:
Here I will be finding out which account actually preformed the action that made the S3 bucket publicly accessible.
The SPL command used:
sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| stats values(userIdentity.userName)
Basing my SPL query loosely on what I did in the last question, I extracted the username associated with the PutBucketAcl event, to find the appropriate account. Referring back to the first question the account bstoll appeared in the initial user list which confirms it is a legitimate account that was compromised. When this happens in real scenarios the immediate steps would include interviewing the user, reviewing their recent activity across all systems and temporarily suspending the account, the user in question was:
Answer: bstoll
I have also produced an activity timeline for the user bstoll which shows the types and volumes of actions performed by this account over time.


Conclusion, references and presentation

[1]N. Miloslavskaya, “Security Operations Centers for Information Security Incident Management,” 2016 IEEE 4th International Conference on Future Internet of Things and Cloud (FiCloud), Aug. 2016, doi: https://doi.org/10.1109/ficloud.2016.26.
‌