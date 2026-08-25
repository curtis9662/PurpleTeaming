## 1. Executive Summary

This runbook defines the Business Continuity and Disaster Recovery (DRBC) procedures for critical identity infrastructure. It replaces legacy, manual recovery processes (such as Microsoft's 150+ page AD Forest Recovery guide) with a modern, automated approach. This document covers the unified protection and recovery of Active Directory (AD), Microsoft Entra ID, and Okta.

---

## 2. Why Standard VM-Level Backups Fall Short

Before executing recovery procedures, it is critical to understand why restoring Identity Providers (IdPs) from standard VM backups is dangerous:

*   **USN Rollback & Replication Issues:** Restoring a domain controller (DC) from a VM snapshot without proper VSS (Volume Shadow Copy Service) integration causes Update Sequence Number (USN) rollbacks, permanently breaking replication.
*   **Lingering Objects:** VM snapshots can introduce lingering objects (tombstoned objects that resurrect during incomplete synchronizations).
*   **Malware Persistence:** Ransomware often compromises the system state. Restoring a full VM restores the dormant malware.
*   **Solution:** This runbook utilizes **Application-Consistent Backups** specifically designed for Identity Providers, decoupling identity data from the underlying potentially compromised operating system.

---

## 3. Unified Multi-IdP Protection Strategy

A catastrophic event (e.g., ransomware, malicious insider) rarely targets a single system. Our DRBC strategy mandates centralized protection across all major identity planes:

1.  **On-Premises Active Directory:** Automated state backups (System State + Bare Metal Recovery where applicable, decoupled from OS state during restore).
2.  **Microsoft Entra ID (Cloud):** Continuous backup of Conditional Access policies, Enterprise App registrations, Role assignments, and user attributes.
3.  **Okta (Cloud):** Automated backups of Okta rules, policies, application integrations, and directory profiles.

*Always verify that cross-IdP sync engines (e.g., Entra ID Connect) are suspended during a recovery scenario to prevent compromised on-premise data from overriding clean cloud data.*

---

## 4. Phase 1: Automated AD Forest Recovery

*Objective: Recover the entire AD Forest using a streamlined, wizard-driven workflow instead of manual metadata cleanup.*

**Step 1: Declare the Incident & Isolate**
*   Sever external network connections to the compromised forest.
*   Shutdown all existing/compromised Domain Controllers.

**Step 2: Initialize the Recovery Wizard**
*   Launch the automated AD Recovery Console from the isolated DR vault.
*   Select the most recent known-good backup.

**Step 3: Execute the Automated Workflow**
*   The wizard will automatically handle the steps that traditionally required manual `ntdsutil` commands:
    *   Restoring the primary DC from backup.
    *   Seizing all FSMO (Flexible Single Master Operations) roles.
    *   Raising the RID pool by 100,000 to prevent overlapping SIDs.
    *   Resetting the `krbtgt` password twice.
    *   Cleaning up metadata for all other (non-restored) DCs.

**Step 4: Redeploy Replica DCs**
*   Once the primary DC is validated, use the recovery tool to automatically promote clean, freshly installed VMs into replica DCs using Install from Media (IFM) or direct replication.

---

## 5. Phase 2: Clean Room Recovery (Eliminating Reinfection Risk)

*Objective: Restore identity services to an isolated environment to ensure malware is not reintroduced.*

**Step 1: Provision the Clean Room**
*   Deploy fresh Windows Server VMs in a completely isolated, uncompromised hypervisor/VPC environment (the "Clean Room").

**Step 2: Bare Metal/Phase Restore**
*   Instead of doing a bare-metal restore of the old, infected OS, utilize the recovery tool's **Phase Restore** capability.
*   Restore *only* the Active Directory DIT database, SYSVOL, and registry configurations onto the fresh OS layer.

**Step 3: Validation and Quarantine**
*   Perform automated vulnerability and malware scans on the restored AD database before connecting it back to the production network.
*   Verify authentication locally within the Clean Room.

---

## 6. Phase 3: Surgical Restoration

*Objective: Instantly recover specific objects without taking the directory offline.*

In scenarios involving accidental deletion or targeted malicious modifications (e.g., a privileged group membership is wiped out), do not perform a full forest recovery.

**Workflow:**
1.  Open the Unified Identity Recovery dashboard.
2.  **Search:** Locate the compromised entity (User, Group, Organizational Unit, or Entra/Okta Application).
3.  **Compare:** Run a differential analysis between the current live state and the backup state to highlight unauthorized changes (e.g., unexpected users added to `Domain Admins`).
4.  **Restore:** Select "Restore Selected Attributes."
    *   *Note: Ensure the restoration tool maintains complex relationships (e.g., restoring a user must automatically restore their group memberships, manager relationships, and nested permissions).*
5.  **Audit:** Document the recovery action in the ITSM tool (e.g., ServiceNow/Jira).

---

## 7. Post-Recovery Checklist & Re-integration

Once the primary Identity Providers (AD, Entra, Okta) are stable in the Clean Room:

*   [ ] Verify DNS resolution for the restored AD zones.
*   [ ] Re-enable Entra ID Connect / Okta Provisioning agents.
*   [ ] Force a delta sync and verify logs for abnormal mass-deletions.
*   [ ] Rotate all Service Account passwords and IdP integration secrets.
*   [ ] Gradually reconnect business applications (Tier 1 -> Tier 2 -> Tier 3).
*   [ ] Conduct a post-mortem to update this runbook based on actual recovery times.
