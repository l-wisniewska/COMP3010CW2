BOTSv3 Incident Analysis Report
Youtube link: https://youtu.be/dMtsKXv5vzg 

Introduction:

Security Operations Centres (SOCs) serve as centralised units managing organisational security issues through teams of security analysts who detect, analyse, respond to, report on and prevent information security incidents [1]. These teams utilise specialised tools to aggregate security logs from servers, endpoints, cloud services and network devices, enabling rapid detection and investigation of suspicious activity [2], [3]. This report uses Splunk, an industry standard Security Information and Event Management (SIEM) platform used for log analysis and visualisation [5].

This investigation focuses on BOTSv3 (Boss of the SOC, Version 3), a pre-indexed Capture the Flag dataset created by Splunk that simulates realistic multi-stage cyber-attacks against Frothly, a fictional global beverage company. The dataset includes extensive logs from network devices, authentication systems, endpoints, cloud platforms (AWS and Azure), email systems and web infrastructure. Using Splunk’s Processing Language (SPL), I will analyse these logs to reconstruct the attack chain, answer guided investigative questions and map findings to the cyber kill chain methodology [7]. The objective is to apply SOC principles, specifically detection, analysis and incident handling to the BOTSv3 dataset, limited to the 200-level questions. This exercise simulates a genuine incident response scenario, including business impact assessment and cost modelling based on the discovered security events.

SOC roles and incident handling reflection:

SOCs employ a tiered operational model which ensures efficient triage, escalation and analysis. The first point of contact are Tier 1 analysts, which preform initial alert monitoring and basic investigations, validating incidents, filtering false positives, and escalating genuine threats, In BOTSv3, Tier 1 responsibilities include, identifying suspicious authentication attempts, unusual process execution, and anomalous network patterns using fundamental SPL queries.

Tier 2 analysts, or incident responders, preform deeper investigations, following the escalation of a threat, this entails correlating multiple log sources, determining attack scope and identifying the root causes. In Botsv3 this is like reconstructing the attackers’ actions across Frothly’s endpoint, cloud and network logs, for example connecting malicious AWS events to suspicious activity to understand lateral movement.

The last stage of this tiered model is the tier 3 analysts, also known as Threat Hunters and Detection engineers, these people focus on advanced analytics, detection rule creation, and uncovering behaviours that may bypass the standard alerting systems [4]. In Botsv3 this can be reflected as identifying patterns which are not directly surfaced through the dashboard, such as abnormal API usage or persistence mechanisms.
SOCs operate according to a structed incident handling lifecycle, this begins with prevention, which includes hardening systems and configuring logging, this is represented in this report by Splunk installation and data ingestion. The ways of detection in the Botsv3 dataset is shown through the use of SPL queries to identify indicators of compromise and map them to the cyber kill chain. The next step is response; this involves interpreting the impact of the events that have been discovered and determining what containment methods would be most applicable such as locking accounts or isolating any compromised assets. The final steps are recovery and how to use such a breach as a learning point on where to strengthen security, improve monitoring or implementing better cloud governance to prevent a recurrence of such events. This Botsv3 exercise effectively mirrors these workflows by requiring multilayer analysis, cross-log correlation and an applied understanding of SOC roles and responsibilities. 

Installation and data preparation:

A functional SIEM platform requires reliable processes for ingesting, normalising and validating security logs [5]. In real SOC environments, this ensures analysts have full system visibility enabling timely detection of malicious activity. Incomplete or improperly structured log data severely impacts an organisation’s ability to detect, understand and respond to security incidents, potentially causing ineffective or delayed remediation.

To conduct this investigation, I established a controlled analysis environment using Splunk Enterprise, an SIEM solution widely deployed across financial, healthcare and technology sectors. Installation was performed on a dedicated Ubuntu virtual machine, providing an isolated environment preventing potential security risks from affecting production systems, mirroring real world SOC practices. During installation, a dedicated administrative account was configured with the default web interface enabled on port 8000. The BOTSv3 dataset was downloaded from the provided GitHub repository and ingested via the Ubuntu terminal into the Splunk application, this dataset contains indexed security event data spanning multiple days of simulated operations.

After ingestion, data quality validation was preformed using the command index=”botsv3” with the time span “all time” to verify complete data availability. I confirmed the installation and ingestion was successful by ensuring the event count equalled 2,083,056 events. 
The screenshots provided demonstrate successful completing of both the Splunk installation (Figure 1) and the Botsv3 dataset upload (Figure 2), confirming all data was accessible and searchable through Splunk’s interface. 

Figure 1: ![Splunk Download](screenshots/SplunkDownload.png)
 
Figure 2: ![Botsv3 ingestion](screenshots/Botsv3Splunk.png)

Guided Questions:

Q1: IAM users who accessed AWS services.

The first question asks to find all legitimate AWS users, so we have a baseline to identify any potential unauthorised access.

The SPL query used:
sourcetype="aws:cloudtrail"
| stats values(userIdentity.userName) AS users

This query filters all CloudTrail events and extracts unique usernames from the userIdentity.userName field. The stats values() function gets rid of any duplicates and provides a comprehensive list of all the users who accessed AWS services during the incident window, four IAM users were identified:

Answer: bstoll,btun,splunk_access,web_admin

![Q1](<screenshots/Screenshot 2026-01-05 181446.png>)
 
Q2: Field for detecting AWS API calls without MFA.

The SPL query used:
sourcetype="aws:cloudtrail" *MFA*

Multi-Factor Authentication (MFA) requires the user to provide two forms of verification, preventing attackers who compromise credentials but lack the second factor from accessing protected resources. I searched through CloudTrail logs for fields related to MFA to determine how to detect authentication events lacking this protection. The query uses the wildcard search *MFA* which identifies all events containing MFA related information, by examining the available fields I identified the specific field that tracks MFA status for each API call, which was:

Answer: userIdentity.sessionContext.attributes.mfaAuthenticated

![Q2](<screenshots/Screenshot 2026-01-05 181911.png>)
 
This showed me that there were 2,155 unauthenticated API calls made. 

Q3:  Processor number used on the web servers

To understand the production environment configuration, I queried hardware monitoring logs using the query below.

sourcetype="hardware"
| stats values(cpu) by host

With this query I was able to determine that Frothly’s servers utilise Intel Xeon E5-2676 processors. While primarily operational, this information becomes relevant when analysing performance anomalies potentially caused by malware.

Answer: E5-2676 (Intel Xeon)

![Q3](<screenshots/Screenshot 2026-01-05 182430.png>)
 
Q4: Event ID enabling public S3 access.

sourcetype="aws:cloudtrail" eventName="PutBucketAcl"

I searched CloudTrail logs for an event called PutBucketAcl, this API call modifies a buckets Access Control List (ACL) which defines who can access the bucket, and in this case when public access was granted at 2:01:46PM. This represents a critical security control failure; properly governed cloud environments should trigger immediate alerts an require management approval for such changes. In this specific scenario, this can happen due to an insider threat, compromised credentials or a misconfiguration by an administrator who did not understand the security implications [6].

Answer: ab45689d-69cd-41e7-8705-5350402cf7ac

![Q4](<screenshots/Screenshot 2026-01-05 182739.png>)
 
Q5: Bud’s Username:

The SPL query used:
sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| stats values(userIdentity.userName)

I extracted the username associated with the PutBucketAcl evet using the previous query with added user extraction. The account bstoll, which I identified in Q1 as a legitimate user, preformed the action. In real scenarios, the immediate response to such issues would include, user interview, activity review and account suspension pending investigation.
Answer: bstoll

![Q5](<screenshots/Screenshot 2026-01-05 182946.png>)
 
I have also produced an activity timeline for the user bstoll which shows the types and volumes of actions performed by this account over time, this was done with the following SPL query: 

sourcetype="aws:cloudtrail" userIdentity.userName="bstoll" | timechart count BY eventName

![Q5 Bar Chart](<screenshots/Screenshot 2026-01-05 183118.png>)
 
Q6: Publicly accessible S3 bucket name:

Determining which specific data repository was exposed is crucial in determining how severe the data breach that occurred was and to know what steps are appropriate following the breach.

The SPL query used:
sourcetype="aws:cloudtrail" eventName=PutBucketAcl
| table requestParameters.bucketName userIdentity.userName

I clarified the search I used for the previous question so that it extracted with the bucket name and the user responsible from the PutBucketAcl event, this provided me with a clear picture of who exposed what, the name of the bucket exposed was:

Answer: Frothlywebcode

![Q6](<screenshots/Screenshot 2026-01-05 183228.png>)
 
The name of the bucket suggests that it could contain application source code or web assets, public exposure of such information can reveal API keys, hardcoded credentials or security vulnerabilities that attackers can exploit, meaning this data breach could have had severe consequences, both financial and operational.

Q7: File uploaded while bucket was still public:

I analysed S3 access logs to identify data accessed during the exposure window using the query below:

sourcetype="aws:s3:accesslogs" 
"200" "frothlywebcode” *PUT* | table _time _raw

Filtering successful (200) uploads to frothlywebcode, a message from the attacker confirmed unauthorised access, the file in question is:

Answer: OPEN_BUCKET_PLEASE_FIX.txt

![Q7](<screenshots/Screenshot 2026-01-05 184110.png>)
 
Q8: Endpoint with non-standard configuration:

Maintaining consistency in operating system configurations is important for security management and patch deployment, any anomalies may indicate compromise or policy violations.

SPL query used:
sourcetype="winhostmon"
| stats count BY host, OS

Using the query shown above I analysed windows host monitoring data to identify systems running different operating system editions than the standard enterprise deployment, this showed that the hostname was BSTOLL-L and when I looked further into the windows security event logs using this SPL query: 
index=botsv3 host=bstoll-l sourcetype=wineventlog:security 

for the host BSTOLL-L showed the ComputerName field with the following name:

Answer: BSTOLL-L.frothly.ly

![Q8.1](<screenshots/Screenshot 2026-01-05 184539.png>)
 
![Q8.2](<screenshots/Screenshot 2026-01-05 184726.png>)

Conclusion:
To conclude, the investigation reveals a critical security breach at Frothly resulting from the compromised bstoll user account, which modified S3 bucket permissions (event id: ab45689d-69cd-41e7-8705-5350402cf7ac) exposing the frothlywebcode bucket to the public internet. The file “OPEN_BUCKET_PLEASE_FIX.txt” confirms unauthorised external access and successful data exfiltration of propriety source code. Due to this strengths and gaps in the SOC operational model were highlighted. In a SOC environment the tiered escalation structure as I mentioned towards the beginning of the report would have proved effective. Tier 1 analysts would have detected the anomalous PutBucketAcl event, tier 2 would have successfully correlated cloud and endpoint data, reconstructed the attack chain, and finally tier 3 would have identified the non-standard endpoint configuration pattern. This unfortunately did not happen, as an absence of real-time alerting on public S3 bucket creation and a lack of mandatory MFA enabled the breach.

In a more business-based point of view, exposure of application source code presents severe consequences, including compromised intellectual property, and creations of secondary attack vectors, and regulatory implications requiring potential breach disclosure under GDPR or CCPA. Based on the Ponemon Institute’s 2024 Cost of a Data Breach Report, similar incidents average $4.45 million in total costs including incident response ($50,000-$150,000), legal and regulatory compliance ($100,000-$300,000), system remediation ($200,000-$500,000), and potential regulatory fines ($50,000-$1,000,000) [9]. In addition to this, indirect costs such as reputational damage or customer churn potentially may exceed these direct costs.

Strategic recommendations to mitigate such attacks in the future include, implementing AWS Service Control Policies preventing public S3 bucket creation, over the whole organisation. Enforcing mandatory MFA for all privileged AWS operations through IAM conditional access, as well as deploying AWS config rules for automatic detection and remediation of S3 permission changes. Establishing endpoint security baselines would also prove useful in order to prevent unauthorised OS modifications. To ensure these configurations and proper security remain in place, quarterly exercises that simulate cloud security incidents should be ran as well as regular access revies ensuring least-privilege principles.
Overall, the BOTSv3 investigation and guided questions successfully demonstrated SOC principles applied to a realistic multi-stage cyber-attack, revealing critical insights into cloud security, incident response and challenges faced in modern security operations [8]. The recommendations I stated proved a strategic roadmap in order to enhance Frothly’s security, ensuring such attacks are flagged and stopped before any real damage is done. As organisations are increasingly migrating to cloud infrastructure, technical expertise, and mitigative measures remain essential to protect modern digital organisations.


References:
[1] N. Miloslavskaya, “Security Operations Centers for Information Security Incident Management,” 2016 IEEE 4th International Conference on Future Internet of Things and Cloud (FiCloud), Aug. 2016, doi: https://doi.org/10.1109/ficloud.2016.26.

[2] M. Vielberth, F. Bohm, I. Fichtinger, and G. Pernul, “Security Operations Center: A Systematic Study and Open Challenges,” IEEE Access, vol. 8, pp. 227756–227779, 2020, doi: https://doi.org/10.1109/access.2020.3045514. 

[3] A. Skendzic, B. Kovacic, and B. Balon, “Management and Monitoring Security Events in a Business Organization - SIEM system,” 2022 45th Jubilee International Convention on Information, Communication and Electronic Technology (MIPRO), May 2022, doi: https://doi.org/10.23919/mipro55190.2022.9803428. 

[4] C. Feng, S. Wu, and N. Liu, “A user-centric machine learning framework for cyber security operations center,” 2017 IEEE International Conference on Intelligence and Security Informatics (ISI), Jul. 2017, doi: https://doi.org/10.1109/isi.2017.8004902.  

[5] S. Bhatt, P. K. Manadhata, and L. Zomlot, “The Operational Role of Security Information and Event Management Systems,” IEEE Security & Privacy, vol. 12, no. 5, pp. 35–41, Sep. 2014, doi: https://doi.org/10.1109/msp.2014.103. 

[6] O. Podzins and A. Romanovs, “Why SIEM is Irreplaceable in a Secure IT Environment?,” IEEE Xplore, Apr. 01, 2019. https://ieeexplore.ieee.org/document/8732173 

[7] E. Hutchins, M. Cloppert, and R. Amin, “Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains,” Lockheed Martin Corporation, 2011. Available: https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf 

[8] N. Sun, J. Zhang, P. Rimba, S. Gao, Y. Xiang, and L. Y. Zhang, “Data-driven cybersecurity incident prediction: A survey,” IEEE Communications Surveys & Tutorials, pp. 1–1, 2018, doi: https://doi.org/10.1109/comst.2018.2885561. 

‌[9] “CrowdStrike 2025 Global Threat Report,” Crowdstrike.com, 2025. https://go.crowdstrike.com/2025-global-threat-report.html?utm_campaign=thih&utm_content=crwd-thih-eur-uki-en-psp-x-x-x-tct-x_x_x_gtr-x&utm_medium=sem&utm_source=goog&utm_term=threat%20report%20cyber&utm_languageen-gb&cq_cmp=12208318263&cq_plac= 
‌

