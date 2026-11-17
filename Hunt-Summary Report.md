Incident Summary Report

**To:** Executive Leadership Team, LOGN PACIFIC, LLC (p. 1\)  
**From:** Cyber Security Incident Response Team (CSIRT)  
**Date:** June 11, 2026 (p. 4\)  
**Incident Reference:** INC-20260611-01  
**Severity:** Critical 

* **Tools:** Microsoft Sentinel & KQL (p. 1\)  
* **Target:** LOGN PACIFIC, LLC (p. 1\)  
* **Compromised Account:** m.smith@lognpacific.org (p. 1\)  
* **Attacker IP:** 103.69.224.136 (Netherlands/Linux/Spoofed Chrome 149\) (p. 1\)

Executive Summary

* **Incident Overview**: On June 11, 2026, threat actors targeted LOGN PACIFIC, LLC, compromising the account of m.smith@lognpacific.org via a malicious IP footprint (103.69.224.136) (p. 1).  
* **Attack Vector**: The attacker leveraged session hijacking (cookie theft) to bypass traditional MFA protections, gaining unauthorized access to cloud assets and directory frameworks (pp. 15, 21).  
* **Impact & Exfiltration**: The intruder exfiltrated financial profile datasets, intercepted high-value business communications between internal staff, stole VPN structural credentials, and blasted a company-wide phishing campaign inside Microsoft Teams (pp. 5, 7, 10, 14).  
* **Current Status**: Core internal corporate networks remain uncompromised; however, localized mailbox persistence and data exfiltration pathways have been successfully established (pp. 7, 11).  
* **Immediate Strategy**: Rapid deployment of the NIST-based containment protocol is required to revoke compromised sessions, purge internal mailbox forwarding rules, rotate corporate VPN profiles, and transition the infrastructure to a risk-based Zero-Trust identity posture (pp. 18-20).

---

Detection & Analysis 

📊 Initial Scoping & Table Breakdown

Cross-table KQL search query executed for the malicious IP address: (p. 1\)

kusto  
search in (\*) "103.69.224.136"  
\| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))

\| summarize RecordCount \= count() by \$table \| sort by RecordCount desc

Use code with caution.

* **AADNonInteractiveUserSignInLogs (542):** Automated background token refreshes and API application access. (p. 2\)  
* **MicrosoftGraphActivityLogs (146):** Direct programmatic cloud queries (emails, files, users, directory). (p. 2\)  
* **IdentityLogonEvents (87):** Defender for Identity tracking logon attempts across infrastructure. (p. 3\)  
* **SigninLogs (42):** Interactive user authentications and front-door login requests. (p. 3\)  
* **BehaviorAnalytics (42):** UEBA enrichment flagging anomalous behaviors, baseline shifts, and risk scores. (p. 3\)  
* **OfficeActivity (35):** Exchange Online, SharePoint/OneDrive actions (mail reads, file downloads). (p. 3\)  
* **CloudAppEvents (35):** Defender for Cloud Apps SaaS log detailing clicks, edits, and reads. (p. 3\)  
* **AADGraphActivityLogs (2):** Legacy Azure AD Graph API queries used by older tools/scripts for directory recon. (p. 4\)

---

📅 Technical Timeline (June 11, 2026\)

**1\. Initial Access & Sign-In Failures (03:15:23 AM)**

Interactive login to One Outlook Web using m.smith's credentials hit sign-in interrupt status (ResultType 50140). (p. 4\)

kusto  
SigninLogs \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))  
\| where IPAddress \== "103.69.224.136"

\| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, ResultDescription, ConditionalAccessStatus, SessionId, CorrelationId \| sort by TimeGenerated asc

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.1)* (p. 5\)

**2\. Successful Login & Automated Harvesting (03:15:45 AM)**

Successful Outlook Web login. (p. 5\) At 03:15:21 AM, they pivoted to an automated script (UserType \== Application) scraping three financial emails: (p. 5\)

1. Q1 Vendor Payment Schedule (p. 5\)  
2. Update banking Details \- Pacific IT Monthly (p. 5\)  
3. Urgent Wire Transfer Request (p. 6\)

kusto  
SigninLogs \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T04:50:00Z))

\| where IPAddress \== "103.69.224.136" \| summarize TotalAttempts \= count() by ResultType, ResultDescription

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.3)* (p. 6\)

**3\. Malicious Mailbox Interception Rules (03:28 AM – 03:32 AM)**

Persistence/exfiltration routes built via two inbox rules to silently monitor coworker j.reynolds@lognpacific.org: (p. 7\)

kusto  
OfficeActivity \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))

\| where Operation in ("New-InboxRule", "Set-InboxRule") \| where UserId \=\~ "m.smith@lognpacific.org"  
\| project TimeGenerated, Operation, UserId, Client\_IPAddress, Parameters

Use code with caution.  
**Rule 1: "Backup Copy" (03:28:22 AM):** (p. 7\)  
json  
\[{"Name":"AlwaysDeleteOutlookRulesBlob","Value":"False"},{"Name":"Force","Value":"False"},{"Name":"ForwardTo":"merovingian1337@proton.me"},{"Name":"From","Value":"j.reynolds@lognpacific.org"},{"Name":"Name","Value":"Backup Copy"},{"Name":"StopProcessingRules","Value":"True"}\]

* Use code with caution.

**Rule 2: "Invoice Processing" (03:32:31 AM):** (p. 8\)  
json  
\[{"Name":"AlwaysDeleteOutlookRulesBlob","Value":"False"},{"Name":"Force","Value":"False"},{"Name":"From","Value":"j.reynolds@lognpacific.org"},{"Name":"MoveToFolder","Value":"Archive"},{"Name":"Name","Value":"Invoice Processing"},{"Name":"StopProcessingRules","Value":"True"}\]

* Use code with caution.

**4\. Data Staging inside \\Drafts Folder (03:35 AM)**

Stolen profiles formatted and hidden inside m.smith's \\Drafts directory to bypass outbound filters, building internal BEC payloads. (p. 8\)

kusto  
OfficeActivity \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))

\| where UserId \=\~ "m.smith@lognpacific.org" or Client\_IPAddress \== "103.69.224.136" \| where OfficeWorkload \=\~ "Exchange"  
\| where Item has\_any ("Vendor Payment", "Banking Details", "Wire Transfer") or Parameters has\_any ("Vendor Payment", "Banking Details", "Wire Transfer")

\| project TimeGenerated, Operation, Client\_IPAddress, UserType, Item, Parameters, AffectedItems \| sort by TimeGenerated asc

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.14)* (p. 9\)

**5\. OneDrive Data Exfiltration Breach (03:37:22 AM)**

Script exfiltrated critical infrastructure credentials from m.smith's personal OneDrive: (p. 10\)

* VPN-Access-Credentials.txt (Exfiltrated) (p. 10\)  
* Vendor-Banking-Details.txt (Exfiltrated) (p. 10\)  
* yomark.pdf (Accessed, not downloaded) (p. 10\)

kusto  
OfficeActivity \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))  
\| where UserId \== "m.smith@lognpacific.org" or Client\_IPAddress \== "103.69.224.136"  
\| where Operation in ("FileDownloaded", "FileAccessed", "FileViewed")

\| project TimeGenerated, Operation, OfficeWorkload, SourceFileName, SourceRelativeUrl \| sort by TimeGenerated asc

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.10)* (p. 11\)

Firewall check confirmed the attacker has **not** pivoted internally using these stolen credentials yet: (p. 11\)

kusto  
CommonSecurityLog \| where TimeGenerated \> datetime(2026-06-11T03:37:00Z)  
\| where DeviceAction \== "Accept" or DeviceAction \== "LogIn"  
\| where SourceIP \== "103.69.224.136" or DestinationUserName has "m.smith"  
\| project TimeGenerated, DeviceAction, SourceIP, DestinationUserName, Message

Use code with caution.

**6\. Attempted Privilege Escalation Loop (03:45:33 AM)**

Script targeted directory infrastructure licenses, sparking rapid updates within the same second. Tenant parameters rejected changes, resulting in a net-zero system modification. (p. 12\)

kusto  
AuditLogs \| where TimeGenerated between (datetime(2026-06-11T03:45:00Z) .. datetime(2026-06-11T03:46:00Z))

\| where TargetResources has "m.smith@lognpacific.org" \| extend ModifiedProperties \= TargetResources.modifiedProperties  
\| mv-expand ModifiedProperties \| project TimeGenerated, OperationName, PropertyName \= ModifiedProperties.displayName, OldValue \= ModifiedProperties.oldValue, NewValue \= ModifiedProperties.newValue

Use code with caution.

💾 *Log Proof:* \[{"displayName":"LicenseAssignmentDetail","oldValue":"\[...\]","newValue":"\[...\] "}\] (p. 13\)

**7\. Azure Portal Step-Up MFA Challenge Failure (04:16:11 AM)**

Login to Azure Management Portal failed (ResultType 50074\) because Entra ID required an active Strong Authentication challenge. (p. 14\)

💾 *Log Proof: (Hunt-Sec... p.3)* (p. 14\)

**8\. Company-Wide Microsoft Teams Phishing Blast (04:17:56 AM)**

Attacker accessed Microsoft Teams and pushed a mass phishing message into the standard "General" channel of the main "LOGN PACIFIC, LLC" team. (p. 14\)

kusto  
OfficeActivity \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))

\| where UserId \=\~ "m.smith@lognpacific.org" \| where OfficeWorkload \=\~ "MicrosoftTeams"  
\| where Operation in\~ ("MessageSent", "ChatCreated", "ChannelMessageSent")

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.19)* (p. 15\)

**9\. MFA Token Hijacking Bypass via Cookie Theft (04:21:29 AM)**

Attacker bypassed challenges on the next Azure Portal connection by presenting a session token with an existing MFA claim ("Previously satisfied"). (p. 15\)

kusto  
union SigninLogs, AADNonInteractiveUserSignInLogs  
\| where TimeGenerated between (datetime(2026-06-11T04:10:00Z) .. datetime(2026-06-11T04:20:00Z))

\| where IPAddress \== "103.69.224.136" \| extend AuthMethod \= tostring(AuthenticationDetails), AuthResult \= tostring(AuthenticationDetails)  
\| project TimeGenerated, AppDisplayName, ResultType, AuthenticationRequirement, AuthMethod, AuthResult \| sort by TimeGenerated asc

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.4)* (p. 16\)

**10\. Automated Internal Reconnaissance Profile (Ongoing)**

Script ran background queries against backend API nodes mapping groups, user configurations, and permissions boundaries. (p. 17\)

kusto  
MicrosoftGraphActivityLogs \| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))

\| where IPAddress \== "103.69.224.136" \| where RequestUri has\_any ("/users", "/groups", "/directoryRoles", "/administrativeUnits")  
\| project TimeGenerated, RequestMethod, RequestUri, ResponseStatusCode \| sort by TimeGenerated asc

Use code with caution.

💾 *Log Proof: (Hunt-Sec... p.5)* (p. 17\)

---

🛡️ NIST-Based Action Plan: Containment & Recovery

**Phase 1: Containment (Stop the Leak Instantly)**

1. **Block Outbound Mail Traffic:** Build a tenant-wide Exchange Transport Rule blocking outbound mail to merovingian1337@proton.me or any proton.me address. (p. 18\)  
2. **Invalidate Session Tokens:** In Entra Admin Center, select "Revoke sessions" for m.smith@lognpacific.org. Complete this process for j.reynolds@lognpacific.org and Jay immediately. (p. 18\)  
3. **Reset Account Credentials:** Force a secure password reset on m.smith@lognpacific.org. (p. 18\)

**Purge Interception Mailbox Rules:** Execute Exchange PowerShell commands to wipe forwarding mechanisms: (p. 18\)  
powershell  
Remove-InboxRule \-Mailbox "m.smith@lognpacific.org" \-Identity "Backup Copy" \-Confirm:\$false  
Remove-InboxRule \-Mailbox "m.smith@lognpacific.org" \-Identity "Invoice Processing" \-Confirm:\$false

4. Use code with caution.  
5. **Scrub Teams Phishing Blast:** In Teams Admin Center ➔ Manage Channels ➔ LOGN PACIFIC, LLC \-\> General, Hard Delete the message sent at 04:17:56 UTC. (p. 19\)

**Phase 2: Recovery (Restore Secure Operations)**

1. **Revoke Stolen VPN Infrastructure:** Rotate and invalidate all corporate VPN certificates, credentials, and firewall gateway profiles related to the stolen VPN-Access-Credentials.txt. (p. 19\)  
2. **Audit Intercepted Mailboxes:** Review m.smith's Archive folder for unread financial files hidden by attacker rules during compromise. (p. 19\)  
3. **Accounting Verification:** Have the finance team verbally verify invoice updates or wire requests involving j.reynolds@lognpacific.org over the last 48 hours. (p. 19\)  
4. **Compliance Logging:** File a formal data breach log with risk/legal departments regarding the exfiltrated credential sheets. (p. 19\)

*The containment playbook is ready for deployment. Confirm token revocation completion.* (p. 20\)

---

📊 Phase 3: Post-Incident Activity & Lessons Learned 

Audit administrative and architectural gaps to move the tenant from static defenses to an Identity-Zero Trust posture. (p. 20\)

**🔑 Critical Lessons Learned**

1. **Static Security Defaults are Blind to Token Theft:** Default baseline security policies marked the connections as successes. They validate interactive logons but fail to inspect session anomalies, impossible travel, or headless browser automation. (pp. 20-21)  
2. **Session Hijacking Renders Traditional MFA Useless:** Stolen session cookies bypassed interactive challenges using a "Previously satisfied" claim. Traditional push notifications/SMS fail against automated scripts presenting hijacked tokens. (p. 21\)  
3. **Attackers Prioritize Communication Silos Over Domain Access:** Swift construction of twin inbox rules shows threat actors target communications pipelines. Siting between m.smith and j.reynolds created a ghost sandbox siphoning data while keeping users blind. (p. 21\)

**🛠️ Post-Incident Security Hardening (Preventative Roadmap)**

Execute these upgrades immediately to close defensive gaps: (p. 22\)

1. **Implement Risk-Based Conditional Access Policies:** Upgrade to Microsoft Entra ID P2 Conditional Access. (p. 22\)  
   * *Policy:* Check User Risk and Sign-in Risk. (p. 22\)  
   * *Enforcement:* If high risk triggers (e.g., unmanaged Linux OS, impossible travel proxy), block access or force a secure re-authentication loop to kill tokens instantly. (p. 22\)  
2. **Enforce Device Compliance Gatekeeping:** Isolate unmanaged endpoints. (p. 22\)  
   * *Policy:* Require authentication exclusively from Hybrid Azure AD Joined or Microsoft Intune Compliant machines. (p. 23\)  
   * *Result:* Linux footprint scripts are blocked at the door regardless of stolen usernames, passwords, or tokens. (p. 23\)  
3. **Restrict Directory Administration Frameworks:** Isolate planes from regular users. (p. 23\)  
   * *Policy:* Restrict management entry points to Azure Management Portal and Entra Admin Center. (p. 23\)  
   * *Enforcement:* Block non-admin accounts from viewing portal resources. Require phishing-resistant MFA (FIDO2, Windows Hello) from strict corporate IP whitelists for admin tiers. (p. 23\)  
4. **Enable Continuous Access Evaluation (CAE):** Reduce lifespan of compromised tokens. (p. 24\)  
   * *Configuration:* Activate Continuous Access Evaluation organization-wide. (p. 24\)  
   * *Result:* Monitors session state in real time. Token perimeter shifts trigger invalidation within minutes, killing the standard 1-to-2 hour expiration window. (p. 24\)  
5. **Deploy Outbound Anti-Forwarding Transport Rules:** Break data-harvesting mechanisms. (p. 24\)  
   * *Configuration:* Build an Exchange Admin Center Anti-Spam Outbound Policy blocking automated external email forwarding. (p. 24\)  
   * *Result:* Future malicious rules fail; Exchange drops outbound text and alerts security before data hits external mailboxes. (p. 25\)

     **Report Prepared By: LOGN PACIFIC CSIRT Operations** \- **Htain Ney**

