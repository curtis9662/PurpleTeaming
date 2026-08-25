# Runbook: Automated AD Forest Recovery & Identity Resilience
## Disaster Recovery & Business Continuity (DRBC) & RTO Fulfillment

**Document Version:** 1.0
**Target Audience:** IAM Engineers, Active Directory Administrators, Disaster Recovery Specialists
**Objective:** Provide engineering configuration and step-by-step admin guidance to achieve rapid Recovery Time Objectives (RTO) for identity infrastructure, surpassing traditional, manual 150+ page Microsoft guidelines.

---

## 1. Automated AD Forest Recovery
*Replacing Microsoft's manual 150+ page guide with a streamlined, wizard-driven workflow.*

### The Challenge
Manual AD forest recovery involves isolating DCs, seizing FSMO roles, cleaning up metadata, resetting machine account passwords, and rebuilding SYSVOL—a highly error-prone process taking days.

### Admin Configuration & Execution Steps
**Pre-requisite Configuration (Day 0):**
1. Deploy the designated AD Recovery Tool (e.g., Quest RMAD, Semperis ADFR) management server in an isolated management VLAN.
2. Install lightweight agents on all Tier-0 Domain Controllers.
3. Configure Backup Storage: Ensure the repository is immutable and physically/logically isolated from the primary AD domain.

**Execution Phase (Wizard-Driven Recovery):**
1. **Launch the Recovery Console:** Access the isolated recovery management server.
2. **Select Forest Recovery Project:** Load the pre-configured Forest Recovery template.
3. **Select the Backup State:** Choose the last known good backup (pre-encryption/pre-compromise).
4. **Define Recovery Scope:**
   - Select which DCs will be restored from backup (typically one per domain).
   - Select which DCs will be rebuilt via DCPromo (Install from Media / Replication).
5. **Execute Workflow:** Click **Start Recovery**. The tool will automatically:
   - Isolate the network (if integrated with hypervisor APIs).
   - Restore the initial DCs from backup.
   - Automatically seize FSMO roles to the primary restored DC.
   - Perform metadata cleanup for non-restored DCs.
   - Reset the `krbtgt` password twice.
   - Rebuild SYSVOL authoritatively.
6. **Validate:** Monitor the wizard dashboard for the "Forest Recovery Complete" state. Run `dcdiag /v` on the primary restored DC.

---

## 2. Unified Multi-IdP Protection
*Centralized protection and recovery across Active Directory, Entra ID, and Okta.*

### The Challenge
A compromised on-prem AD rapidly laterally moves to Entra ID (via AD Connect) or Okta (via delegated authentication), requiring a synchronized recovery approach.

### Admin Configuration Steps
1. **API Integration Setup:**
   - **Entra ID:** Create an Enterprise Application. Grant `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All`, and `AuditLog.Read.All` MS Graph API permissions. Generate a Client Secret/Certificate.
   - **Okta:** Create an API Token with `Super Administrator` or dedicated custom admin privileges.
2. **Connect the DR Platform:**
   - Navigate to the Identity DR Console -> **Connections**.
   - Add **Entra ID** Tenant using the Application ID, Tenant ID, and Secret.
   - Add **Okta** Tenant using the Okta Domain URL and API Token.
3. **Configure Cross-Platform Backup Policies:**
   - Set sync intervals to 15-minutes for critical Tier-0 assets (Conditional Access Policies, Privileged Roles, Okta Sign-On Policies).
   - Set daily backups for standard user attributes.
4. **Recovery Mapping:** Configure mapping rules to ensure that if an on-prem AD user is restored to a previous state, their correlated Entra ID/Okta account (via `immutableId` or UPN) is evaluated for unauthorized role changes.

---

## 3. Beyond VM-Level Backups
*Why standard backups fall short during forest recovery, and how to ensure application-consistent restores.*

### The Problem with VM Snapshots
Restoring a Domain Controller from a standard VM snapshot or crash-consistent backup causes **USN Rollback**. The DC becomes unaware of changes made by other DCs, leading to lingering objects, replication failures, and a corrupted AD database.

### Engineering Solution: Application-Consistent Backups
1. **Configure VSS (Volume Shadow Copy Service):**
   - Ensure your backup agent utilizes the **Active Directory VSS Writer**.
   - Verify writer status by running: `vssadmin list writers` on the DC. Ensure "NTDS" shows as `State: [1] Stable`.
2. **Backup Profile Configuration:**
   - Configure the backup job to capture **System State** and **Bare Metal Recovery (BMR)**, not just the VM disk configuration.
   - Enable AD-specific indexing within the backup software to allow object-level reading of the `.dit` file inside the backup repository.
3. **Verification:**
   - Schedule a weekly automated test restore. The system must mount the `.dit` file and verify its structural integrity (`esentutl /g`) without fully booting a DC.

---

## 4. Surgical Restoration
*Instantly recover specific users, groups, or even individual attributes and their complex relationships.*

### The Challenge
Malicious actors often do not destroy the forest; they subtly alter group memberships (e.g., adding a backdoor user to `Domain Admins`) or modify attributes (e.g., `adminCount`, `sIDHistory`). Rolling back the entire forest violates RTO for normal operations.

### Admin Configuration & Execution Steps
1. **Enable Continuous Tracking:**
   - Configure the DR tool to read the AD replication stream (DirSync) or Security Event Logs to track object changes in real-time.
2. **Executing a Granular Restore:**
   - Open the Granular Restore module.
   - Search for the affected object (e.g., `CN=John Doe,OU=Admins,DC=corp,DC=local`).
   - Open the **Attribute Timeline** view.
3. **Attribute-Level Rollback:**
   - Identify the unauthorized change (e.g., `memberOf` changed at 02:00 AM).
   - Select the specific attribute and click **Restore to Previous Value**.
   - The tool will execute an LDAP bind as a privileged service account and overwrite *only* the selected attribute, leaving the user's password (if changed legitimately) intact.
4. **Group Relationship Recovery:** If an OU was deleted, select the OU, and check "Restore child objects and group memberships." The tool will recreate the objects and re-link them to their respective groups across the domain.

---

## 5. Clean Room Recovery
*Best practices for restoring to an isolated, uncompromised environment to eliminate reinfection risk.*

### The Challenge
Restoring DCs back into the production network can result in immediate re-infection if the ransomware or persistence mechanisms are still active on other member servers.

### Admin Configuration Steps (Isolated Recovery Environment - IRE)
1. **Architecture Setup:**
   - Provision an entirely isolated Virtual Private Cloud (VPC) or hypervisor cluster (the "Clean Room").
   - Ensure **ZERO** inbound routing from the production network. Outbound routing should be restricted strictly to the immutable backup repository via a dedicated port (e.g., port 443 for API access).
2. **Executing the Clean Room Restore:**
   - Launch the automated Forest Recovery wizard (from Section 1).
   - Change the target destination from "In-Place" to "Alternate Hypervisor/Cloud".
   - Provide API credentials for the Clean Room VMware/Hyper-V/Cloud environment.
3. **Phase 1: Identity Scrubbing (The Quarantine Phase):**
   - The tool restores the DC.
   - An automated script halts the inbound replication and network adapters.
   - EDR/Antivirus tools are automatically deployed to the restored DC to run a deep memory and file-system scan before the network is enabled.
4. **Phase 2: Re-introduction:**
   - Once marked "Clean," the DC's IP is reassigned, or DNS is updated.
   - Critical applications are moved into the Clean Room sequentially, authenticated against the guaranteed-clean DC, and validated before bridging back to the production core.
