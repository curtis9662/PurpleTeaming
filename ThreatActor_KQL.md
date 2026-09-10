# Scattered Spider (UNC3944 / Octo Tempest) Advanced Hunting

This repository contains Microsoft Defender XDR Advanced Hunting queries designed to detect the signature behaviors of Scattered Spider within an O365/Entra ID environment.

## Threat Hunting Table

| Goal / Tactic | Target Table | Concise KQL Query | Detection Logic |
| :--- | :--- | :--- | :--- |
| **1. Rogue MFA Enrollment** | `CloudAppEvents` | `CloudAppEvents \| where ActionType in ("User registered security info", "Update user - Add authentication method")` | Detects when a threat actor adds a new FIDO2 key, authenticator app, or phone number to an account after compromising it. |
| **2. Conditional Access Tampering** | `CloudAppEvents` | `CloudAppEvents \| where ActionType has_any ("Update conditional access policy", "Delete conditional access policy")` | Identifies attempts to downgrade or disable Conditional Access policies to bypass MFA or IP restrictions. |
| **3. Helpdesk Social Engineering** | `CloudAppEvents` | `CloudAppEvents \| where ActionType in ("Reset user password", "Update user") \| where InitiatingUserOrAppType == "Admin"` | Flags Helpdesk or Admin accounts initiating password resets, which may indicate a successful vishing campaign. |
| **4. eDiscovery Data Exfiltration** | `CloudAppEvents` | `CloudAppEvents \| where ActionType in ("New-ComplianceSearch", "Start-ComplianceSearch")` | Detects the creation of bulk compliance searches, a tactic UNC3944 uses to silently aggregate and exfiltrate sensitive data. |
| **5. Service Principal Tampering** | `CloudAppEvents` | `CloudAppEvents \| where ActionType has_any ("Add service principal credentials", "Certificates and secrets management")` | Monitors for the addition of new client secrets to App Registrations, allowing attackers to maintain persistent API access. |
| **6. Privileged Role Escalation** | `IdentityDirectoryEvents` | `IdentityDirectoryEvents \| where ActionType == "Add member to role" \| where AdditionalFields has_any ("Global Administrator", "Privileged Authentication Administrator")` | Identifies when an attacker elevates a compromised account to a highly privileged Entra ID directory role. |
| **7. Malicious Mailbox Forwarding** | `CloudAppEvents` | `CloudAppEvents \| where Application == "Microsoft Exchange Online" \| where ActionType in ("New-InboxRule", "Set-Mailbox") \| where RawEventData has_any ("ForwardTo", "ForwardingSmtpAddress")` | Detects the creation of auto-forwarding rules used for reconnaissance and stealing inbound MFA tokens or alerts. |
| **8. Atypical / Risky Sign-ins** | `AADSignInEventsBeta` | `AADSignInEventsBeta \| where ErrorCode == 0 \| where RiskLevelDuringSignIn in ("High", "Medium") or IsRisky == 1` | Flags *successful* sign-ins that Entra ID Identity Protection has identified as originating from residential proxies, Tor, or anomalous IPs. |
| **9. Federation Trust Manipulation** | `CloudAppEvents` | `CloudAppEvents \| where ActionType has_any ("Set federation settings on domain", "Add domain", "cross-tenant access policy")` | Detects cross-tenant synchronization abuse or the creation of rogue federated domains to forge authentication tokens. |
| **10. Suspicious BYOD Registration** | `IdentityDirectoryEvents` | `IdentityDirectoryEvents \| where ActionType == "Device registration" \| where AdditionalFields has_any ("Android", "iOS")` | Identifies the registration of unmanaged mobile devices, often used by Scattered Spider to bypass MFA push fatigue. |

---

## Advanced Hunting Console Block

Copy and paste the block below directly into `security.microsoft.com/v2/advanced-hunting`. Highlight the specific block of code you want to run to execute them individually.

```kusto
// 1. Rogue MFA Enrollment
CloudAppEvents
| where ActionType in ("User registered security info", "Update user - Add authentication method")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, CountryCode

// 2. Conditional Access Tampering
CloudAppEvents
| where ActionType has_any ("Update conditional access policy", "Delete conditional access policy")
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress

// 3. Helpdesk Social Engineering (Password Resets by Admins)
CloudAppEvents
| where ActionType in ("Reset user password", "Update user")
| where InitiatingUserOrAppType == "Admin"
| project Timestamp, InitiatingUserOrAppType, AccountDisplayName, ActionType, TargetAccountDisplayName

// 4. eDiscovery Data Exfiltration Searches
CloudAppEvents
| where ActionType in ("New-ComplianceSearch", "Start-ComplianceSearch")
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress

// 5. Service Principal Tampering (New Secrets)
CloudAppEvents
| where ActionType has_any ("Add service principal credentials", "Certificates and secrets management")
| project Timestamp, AccountDisplayName, ActionType, TargetAccountDisplayName, IPAddress

// 6. Privileged Role Escalation
IdentityDirectoryEvents
| where ActionType == "Add member to role"
| where AdditionalFields has_any ("Global Administrator", "Privileged Authentication Administrator")
| project Timestamp, AccountDisplayName, ActionType, TargetAccountDisplayName, AdditionalFields

// 7. Malicious Mailbox Forwarding Rules
CloudAppEvents
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-Mailbox")
| where RawEventData has_any ("ForwardTo", "ForwardingSmtpAddress")
| project Timestamp, AccountDisplayName, ActionType, RawEventData, IPAddress

// 8. Atypical / Risky Sign-ins (Successful)
AADSignInEventsBeta
| where ErrorCode == 0
| where RiskLevelDuringSignIn in ("High", "Medium") or IsRisky == 1
| project Timestamp, AccountDisplayName, RiskLevelDuringSignIn, IsRisky, IPAddress, Location

// 9. Federation Trust / Cross-Tenant Manipulation
CloudAppEvents
| where ActionType has_any ("Set federation settings on domain", "Add domain", "cross-tenant access policy")
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress

// 10. Suspicious BYOD Registration (Mobile Platforms)
IdentityDirectoryEvents
| where ActionType == "Device registration"
| where AdditionalFields has_any ("Android", "iOS")
| project Timestamp, AccountDisplayName, ActionType, DeviceName, AdditionalFields
```
---

# Advanced Threat Hunting & Purple Team Detections (Part 2: Tactics 11–20)

This module provides 10 advanced queries leveraging anomaly detection, statistical baselining, and cross-domain telemetry correlation within Microsoft Defender XDR (`security.microsoft.com/v2/advanced-hunting`).

## Purple Team Risk & Threat Discovery Matrix

| Goal / Purple Team Technique | Target Table(s) | Detection Logic | Threat / Asset Risk |
| :--- | :--- | :--- | :--- |
| **11. Primary Refresh Token (PRT) Theft & Session Replay** | `AADSignInEventsBeta` | Compares device trust status against IP and session context to find high-privilege tokens replayed from non-compliant/unmanaged devices. | Credential dumping, token relay, bypassing device-based Conditional Access. |
| **12. Illicit OAuth Consent & High-Privilege Graph Grants** | `CloudAppEvents` | Inspects `Consent to application` actions for high-impact Microsoft Graph permissions (`*.All`, `RoleManagement.*`). | Persistent API-based access, automated lateral movement without password dependencies. |
| **13. Audit Log Disablement & Defense Evasion** | `CloudAppEvents` | Flags changes to Exchange admin audit logging or Purview auditing (`Set-AdminAuditLogConfig`, tampering with diagnostic streams). | Adversary anti-forensics, suppressing SOC visibility prior to exfiltration. |
| **14. Dormant Identity & Stale Service Principal Re-activation** | `CloudAppEvents`, `AADSignInEventsBeta` | Identifies accounts inactive for >30 days that suddenly authenticate and execute configuration modifications. | Re-activated backdoor accounts, unmonitored technical debt, dormant credential reuse. |
| **15. Cross-Domain Pivot: Endpoint LSASS Dump to Cloud Admin Action** | `DeviceProcessEvents`, `CloudAppEvents` | Correlates endpoint LSASS access/credential dumping with Entra/O365 administrative activity by the same user within 60 minutes. | Full identity compromise lifecycle starting from endpoint access to cloud tenant takeover. |
| **16. PIM Elevation Without Approval Followed by Sensitive Actions** | `CloudAppEvents`, `IdentityDirectoryEvents` | Links Privileged Identity Management (PIM) role activations directly to rapid configuration edits within a narrow window. | Exploitation of temporary privileged access, internal insider threat, compromised approval flows. |
| **17. Mailbox Search & Hard-Delete Operations (Anti-Forensics)** | `CloudAppEvents` | Detects `Search-Mailbox -DeleteContent` or bulk hard-delete operations executed via administrative sessions. | Destruction of evidence, targeted wiping of compromise notifications or audit reports. |
| **18. Cloud Runbook & Automation Credential Harvesting** | `CloudAppEvents` | Flags updates or exports to Azure Automation runbooks, webhooks, or management certificates. | Persistence in Azure Automation accounts, theft of service account certificates or hybrid worker tokens. |
| **19. Anomalous Mass Download / Ransomware Staging Spike** | `CloudAppEvents` | Employs statistical aggregation (`bin()`, `summarize count()`) to locate spikes exceeding normal user operational baselines. | Mass data exfiltration, preparation for double-extortion ransomware, automated bulk harvesting. |
| **20. Atypical Graph API Directory Enumeration Burst** | `CloudAppEvents` | Detects sudden spikes in sensitive directory reconnaissance operations (`Get-User`, `List directoryRoles`) from non-service identities. | Automated discovery tooling (e.g., BloodHound Azure/Roadrecon) surveying the Entra ID fabric. |

---

## Advanced Hunting Console Block (Queries 11–20)

Copy and paste the block below directly into `security.microsoft.com/v2/advanced-hunting`. Highlight the specific query block you wish to evaluate.

```kusto
// 11. PRT Theft / Session Token Replay on Unmanaged Devices
// Identifies successful logins using privileged accounts where token claims indicate unmanaged endpoints
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where AccountDisplayName has_any ("admin", "adm-", "svc") or RiskLevelDuringSignIn in ("High", "Medium")
| where DeviceTrustType !in ("ServerAd", "Workplace", "AzureAdJoined") 
| extend AuthenticationRequirement = tostring(parse_json(AuthenticationDetails)[0].authenticationRequirement)
| where AuthenticationRequirement has "multiFactorAuthentication"
| project Timestamp, AccountDisplayName, IPAddress, Country, DeviceTrustType, UserAgent, ResourceDisplayName

// 12. Illicit OAuth App Consent Grants with High-Impact Graph Permissions
// Flags authorization of dangerous delegated/application scopes
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Consent to application", "Add app role assignment to service principal")
| extend AppInfo = parse_json(RawEventData)
| extend TargetApp = tostring(AppInfo.Parameters[0].Value)
| extend Scopes = tostring(AppInfo.ModifiedProperties)
| where Scopes has_any (
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
)
| project Timestamp, ActionType, Initiator = AccountDisplayName, TargetApp, Scopes, IPAddress

// 13. Tenant Audit Log Disablement and Tampering (Defense Evasion)
// Detects suppression of Microsoft 365 Unified Audit Logging and diagnostic logging
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Set-AdminAuditLogConfig", "Remove-DiagnosticSetting", "Set-MailboxAuditBypassAssociation")
    or RawEventData has_any ("UnifiedAuditLogIngestionEnabled", "AuditDisabled", "AuditBypass")
| project Timestamp, ActionType, Initiator = AccountDisplayName, IPAddress, ObjectName, RawEventData

// 14. Dormant Identity Re-activation with Immediate Configuration Impact
// Baselines sign-ins to catch dormant users (>30 days) executing administrative actions
let PrivilegedActions = CloudAppEvents
| where Timestamp > ago(3d)
| where ActionType in ("Add member to role", "Add service principal credentials", "Update conditional access policy")
| project PrivTimestamp = Timestamp, AccountObjectId, ActionType, IPAddress;
let PriorActivity = AADSignInEventsBeta
| where Timestamp between (ago(33d) .. ago(3d))
| summarize HistoricalSignIns = count() by AccountObjectId;
PrivilegedActions
| join kind=leftouter PriorActivity on AccountObjectId
| where isempty(HistoricalSignIns) or HistoricalSignIns == 0
| project PrivTimestamp, AccountObjectId, ActionType, IPAddress, HistoricalSignIns

// 15. Purple Team Pivot: Endpoint Credential Access (LSASS) to Cloud Action
// Correlates local LSASS dump alerts/processes with cloud administrative activity from the same user
let CompromisedUsers = DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("lsass.exe", "sekurlsa", "procdump", "comsvcs.dll")
| project EndpointTimestamp = Timestamp, AccountName, DeviceName, ProcessCommandLine;
CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType has_any ("Add member to role", "Set-Mailbox", "Reset user password")
| project CloudTimestamp = Timestamp, Initiator = tolower(AccountDisplayName), ActionType, IPAddress
| join kind=inner (
    CompromisedUsers
    | extend Initiator = tolower(AccountName)
) on Initiator
| where CloudTimestamp between (EndpointTimestamp .. (EndpointTimestamp + 1h))
| project EndpointTimestamp, CloudTimestamp, Initiator, DeviceName, ProcessCommandLine, ActionType, IPAddress

// 16. Just-In-Time Elevation Anomaly (PIM Activation -> Swift Policy Tampering)
// Identifies accounts activating PIM roles and altering policies inside a rapid 15-minute window
let PIMActivations = IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Add member to role in PIM completed"
| project PIMTime = Timestamp, TargetAccountDisplayName = tostring(TargetAccountDisplayName), RoleName = tostring(AdditionalFields.RoleName);
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Update conditional access policy", "Add domain", "Set federation settings on domain")
| project ActionTime = Timestamp, TargetAccountDisplayName = AccountDisplayName, ActionType, ObjectName, IPAddress
| join kind=inner PIMActivations on TargetAccountDisplayName
| where ActionTime between (PIMTime .. (PIMTime + 15m))
| project ActionTime, PIMTime, TargetAccountDisplayName, RoleName, ActionType, ObjectName, IPAddress

// 17. Mailbox Anti-Forensics & Search-and-Purge Activity
// Hunts for commands historically used to purge forensic evidence from Exchange Online
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("Search-Mailbox", "New-ComplianceSearchAction")
| extend Parameters = parse_json(RawEventData).Parameters
| where RawEventData has_any ("-DeleteContent", "PurgeType", "HardDelete")
| project Timestamp, ActionType, AccountDisplayName, Parameters, IPAddress

// 18. Azure Automation Runbook / Webhook Modification
// Discovers lateral movement and credential exposure via Runbook tampering
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in (
    "Set-AzureRmAutomationRunbook", 
    "New-AzureRmAutomationWebhook", 
    "Publish-AzureAutomationRunbook", 
    "Update automation account"
)
| project Timestamp, ActionType, Initiator = AccountDisplayName, ObjectName, RawEventData, IPAddress

// 19. Statistical Spike: Bulk Data Access / Exfiltration Anomalies
// Identifies statistical volume shifts in file downloads per user over 1-hour intervals
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileDownloaded", "FileExported")
| summarize HourlyDownloadCount = count() by bin(Timestamp, 1h), AccountDisplayName
| summarize AvgVolume = avg(HourlyDownloadCount), StdVolume = stdev(HourlyDownloadCount), MaxVolume = max(HourlyDownloadCount) by AccountDisplayName
| where MaxVolume > (AvgVolume + (3 * StdVolume)) and MaxVolume > 200
| project AccountDisplayName, AvgVolume, MaxVolume, Threshold = (AvgVolume + (3 * StdVolume))

// 20. Atypical Graph API Directory Enumeration Burst
// Detects high-velocity reconnaissance attempts sweeping users, roles, or group structures
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Get-User", "Get-DirectoryRole", "Get-AzureADUser", "Get-AzureADGroup")
| summarize ReconOpsCount = count() by bin(Timestamp, 10m), AccountDisplayName, IPAddress
| where ReconOpsCount > 100
| project Timestamp, AccountDisplayName, IPAddress, ReconOpsCount

```
---

```
BY: http://curtis9662.github.io/
```
