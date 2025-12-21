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
SOCs operate according to a structed incident handling lifecycle, this begins with prevention, which includes hardening systems and configuring logging, this is represented in this report by Splunk installation and data ingestion. The ways of detection in the Botsv3 dataset is shown through the use of SPL queries to identify indicators of compromise and map them to the cyber kill chain. Response involves 



Installation and data preparation:


I have set up splunk the way shown in the video and i have downloaded and uploaded the BotsV3 dataset into splunk on my virtual machine:

![screenhot of virtual machine terminal downloading splunk](screenshots/SplunkDownload.png)

![screenshot of virtual machine terminal and splunk page uploading botsv3 successfully](screenshots/Botsv3Splunk.png)


Guided Questions:

Q1:
Search for 

![screenshot of searching botsV3 for IAM users that accessed AWS services](<screenshots/Screenshot 2025-12-01 235911.png>)

![screenshot of the names of the users that accessed the AWS services](<screenshots/Screenshot 2025-12-01 235935.png>)

Conclusion, references and presentation

[1]N. Miloslavskaya, “Security Operations Centers for Information Security Incident Management,” 2016 IEEE 4th International Conference on Future Internet of Things and Cloud (FiCloud), Aug. 2016, doi: https://doi.org/10.1109/ficloud.2016.26.
‌