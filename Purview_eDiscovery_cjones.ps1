<#
.SYNOPSIS
    Authenticates via Service Principal to read all Purview eDiscovery Hold members, 
    audit their complete Entra ID identity access, and calculate their OneDrive storage size.
.DESCRIPTION
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    Recommended Application Permissions (with Admin Consent):
    - eDiscovery.Read.All (Plus SP added to Purview 'eDiscovery Manager' / Case Admin)
    - User.Read.All
    - GroupMember.Read.All (or Directory.Read.All)
    - RoleManagement.Read.Directory
    - AuditLog.Read.All
    - Reports.Read.All
    - Files.Read.All / Sites.Read.All (for direct /users/{id}/drive quota lookup)
#>

[CmdletBinding()]
param (
    [string]$TenantId     = "Tenant_ID",
    [string]$ClientId     = "CLient_ID",
    [string]$ClientSecret = "CLient_Secret",
    [string]$ExportPath   = ".\Purview_Hold_Members_Identity_Access.csv"
)

# Enforce TLS 1.2 for Windows PowerShell 5.1 compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Resolve safe working directory whether run as a .ps1 file or pasted interactively
$WorkDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { $PWD.Path }
if (-not [System.IO.Path]::IsPathRooted($ExportPath)) {
    $ExportPath = Join-Path -Path $WorkDir -ChildPath ($ExportPath -replace '^\.[\\/]', '')
}

# Structured Verbose Console Logger
function Write-Status {
    param (
        [string]$Stage,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    $timestamp = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$timestamp][$Stage] $Message" -ForegroundColor $Color
}

# Helper function for Graph API pagination with verbose page tracking
function Get-GraphPagedItems {
    param (
        [string]$Uri,
        [string]$ContextLabel = "GraphQuery"
    )
    $items   = @()
    $nextUri = $Uri
    $pageNum = 1

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        Write-Verbose "[$ContextLabel] Fetching page $pageNum -> $nextUri"
        $resp = Invoke-MgGraphRequest -Method GET -Uri $nextUri -Headers @{ "ConsistencyLevel" = "eventual" } -ErrorAction Stop
        if ($null -ne $resp.value) {
            $items += $resp.value
        }
        $nextUri = $resp.'@odata.nextLink'
        $pageNum++
    }
    return $items
}

Write-Status -Stage "INIT" -Message "Starting Purview eDiscovery Hold Identity & OneDrive Sizing Auditor..." -Color Cyan

# ==============================================================================
# 1. Authenticate to Microsoft Graph using Service Principal (Client Credentials)
# ==============================================================================
try {
    Write-Status -Stage "AUTH" -Message "Authenticating to Tenant [$TenantId] with App ClientId [$ClientId]..." -Color Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    $secSecret  = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop

    $mgContext = Get-MgContext
    $activeScopes = $mgContext.Scopes
    Write-Status -Stage "AUTH" -Message "Connected successfully as App-Only Service Principal." -Color Green
    Write-Status -Stage "AUTH" -Message "Active JWT Application Roles: $($activeScopes -join ', ')" -Color DarkGray

    # Audit required permissions in token
    $expectedRoles = @("eDiscovery.Read.All", "User.Read.All", "GroupMember.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All", "Reports.Read.All", "Files.Read.All")
    foreach ($reqRole in $expectedRoles) {
        if ($activeScopes -notcontains $reqRole) {
            Write-Status -Stage "WARN" -Message "JWT token is missing recommended role '$reqRole'. Related queries may return 403 Forbidden." -Color DarkYellow
        }
    }
}
catch {
    Write-Error "[FATAL] Microsoft Graph Service Principal authentication failed: $_"
    return
}

try {
    # ==============================================================================
    # 2. Pre-Load M365 OneDrive Usage Report Cache (Fallback for OneDrive Sizing)
    # ==============================================================================
    $OneDriveReportCache = @{} # Key: Lowercase UPN, Value: Report Row
    Write-Status -Stage "ONEDRIVE-CACHE" -Message "Pre-fetching M365 OneDrive Usage Report (getOneDriveUsageAccountDetail) as fallback cache..." -Color Cyan
    try {
        $ReportUri   = "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='D7')"
        $TempCsvPath = Join-Path -Path $WorkDir -ChildPath "Temp_OneDriveUsageReport.csv"
        Invoke-MgGraphRequest -Method GET -Uri $ReportUri -OutputFilePath $TempCsvPath -ErrorAction Stop

        if (Test-Path -Path $TempCsvPath) {
            $CsvLines = @(Get-Content -Path $TempCsvPath)
            $HeaderLine = $CsvLines | Select-String -Pattern "Report Refresh Date" | Select-Object -First 1
            $CleanCsv = if ($HeaderLine) {
                $CsvLines[($HeaderLine.LineNumber - 1)..($CsvLines.Length - 1)] | ConvertFrom-Csv
            } else {
                $CsvLines | ConvertFrom-Csv
            }
            foreach ($row in $CleanCsv) {
                $rowUpn = $row.'User Principal Name'
                if (-not [string]::IsNullOrWhiteSpace($rowUpn)) {
                    $OneDriveReportCache[$rowUpn.Trim().ToLower()] = $row
                }
            }
            Remove-Item -Path $TempCsvPath -ErrorAction SilentlyContinue
            Write-Status -Stage "ONEDRIVE-CACHE" -Message "Cached $($OneDriveReportCache.Count) tenant OneDrive usage records from Reporting API." -Color Green
        }
    }
    catch {
        Write-Status -Stage "ONEDRIVE-CACHE" -Message "Reporting API cache skipped or unavailable ($($_.Exception.Message)). Will rely on direct /users/{id}/drive queries." -Color DarkYellow
    }

    # ==============================================================================
    # 3. Retrieve Purview eDiscovery Cases & Hold Members
    # ==============================================================================
    Write-Status -Stage "EDISCOVERY" -Message "Querying Purview eDiscovery Cases (/v1.0/security/cases/ediscoveryCases)..." -Color Cyan
    $HoldMembers = @{} # Key: Lowercase Email/UPN, Value: Array of Hold Strings

    $cases = @()
    try {
        $cases = @(Get-GraphPagedItems -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases" -ContextLabel "eDiscoveryCases")
        Write-Status -Stage "EDISCOVERY" -Message "Discovered $($cases.Count) Purview eDiscovery Case(s)." -Color Green
    }
    catch {
        Write-Error "[!] Failed to query eDiscovery Cases: $($_.Exception.Message). Ensure 'eDiscovery.Read.All' is granted AND the Service Principal is assigned to 'eDiscovery Manager' in Purview."
        return
    }

    $caseIndex = 0
    foreach ($case in $cases) {
        $caseIndex++
        $caseId   = $case.id
        $caseName = $case.displayName
        Write-Status -Stage "CASE $caseIndex/$($cases.Count)" -Message "Inspecting Case: '$caseName' (ID: $caseId | Status: $($case.status))" -Color Yellow

        # 3a. Check Legal Hold Policies & User Sources
        $holds = @()
        try {
            $holds = @(Get-GraphPagedItems -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/legalHolds" -ContextLabel "LegalHolds")
            Write-Status -Stage "CASE $caseIndex/$($cases.Count)" -Message "  -> Found $($holds.Count) Legal Hold policy(ies) in case '$caseName'." -Color Gray
        }
        catch {
            Write-Status -Stage "CASE $caseIndex/$($cases.Count)" -Message "  -> [!] Could not read legalHolds for '$caseName': $($_.Exception.Message)" -Color DarkYellow
        }

        foreach ($hold in $holds) {
            $holdId     = $hold.id
            $holdName   = $hold.displayName
            $holdStatus = $hold.status
            Write-Status -Stage "HOLD" -Message "     Analyzing Hold Policy: '$holdName' (ID: $holdId | Status: $holdStatus)" -Color DarkCyan

            # Check User Sources on the Hold
            try {
                $userSources = @(Get-GraphPagedItems -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/legalHolds/$holdId/userSources" -ContextLabel "UserSources")
                Write-Status -Stage "HOLD" -Message "       + Retrieved $($userSources.Count) userSource(s) in hold '$holdName'." -Color Gray

                foreach ($src in $userSources) {
                    if (-not [string]::IsNullOrWhiteSpace($src.email)) {
                        $upn = $src.email.Trim().ToLower()
                        if (-not $HoldMembers.ContainsKey($upn)) { $HoldMembers[$upn] = @() }
                        $HoldMembers[$upn] += "$caseName ($holdName [HoldUID: $holdId])"
                    }
                }
            }
            catch {
                Write-Status -Stage "HOLD" -Message "       ! Could not query userSources for hold '$holdName': $($_.Exception.Message)" -Color DarkYellow
            }
        }

        # 3b. Check Case Custodians on Hold
        try {
            $custodians = @(Get-GraphPagedItems -Uri "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/$caseId/custodians" -ContextLabel "Custodians")
            Write-Status -Stage "CASE $caseIndex/$($cases.Count)" -Message "  -> Found $($custodians.Count) total Custodian(s) in case '$caseName'." -Color Gray

            $heldCustodianCount = 0
            foreach ($cust in $custodians) {
                if (($cust.holdStatus -match "applied|applying") -and (-not [string]::IsNullOrWhiteSpace($cust.email))) {
                    $heldCustodianCount++
                    $upn = $cust.email.Trim().ToLower()
                    if (-not $HoldMembers.ContainsKey($upn)) { $HoldMembers[$upn] = @() }
                    $HoldMembers[$upn] += "$caseName (Custodian Hold: $($cust.holdStatus))"
                }
            }
            Write-Status -Stage "CASE $caseIndex/$($cases.Count)" -Message "  -> Matched $heldCustodianCount Custodian(s) with active/applying hold status." -Color Gray
        }
        catch {
            Write-Status -Stage "CASE $caseIndex/$($cases.Count)" -Message "  -> [!] Could not read custodians for '$caseName': $($_.Exception.Message)" -Color DarkYellow
        }
    }

    Write-Status -Stage "DISCOVERY-SUMMARY" -Message "Total unique Purview Hold Members discovered: $($HoldMembers.Count)" -Color Green

    if ($HoldMembers.Count -eq 0) {
        Write-Warning "No hold members were discovered across any Purview eDiscovery cases. Exiting."
        return
    }

    # ==============================================================================
    # 4. Audit Entra Identity Access & OneDrive Sizing for Each Hold Member
    # ==============================================================================
    $IdentityReport = @()
    $memberIndex    = 0
    $totalMembers   = $HoldMembers.Count

    foreach ($upn in $HoldMembers.Keys) {
        $memberIndex++
        $pct = [math]::Round(($memberIndex / $totalMembers) * 100, 0)
        Write-Progress -Activity "Auditing Purview Hold Members" -Status "Processing $upn ($memberIndex of $totalMembers)" -PercentComplete $pct
        Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "Auditing Identity & OneDrive for Hold Member: $upn" -Color Yellow

        try {
            # 4a. User Profile & SignInActivity (User.Read.All, AuditLog.Read.All)
            Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "  [4a] Querying Entra User Profile & SignInActivity..." -Color Gray
            $user    = $null
            $encodedUpn = [System.Uri]::EscapeDataString($upn)
            $userUri = "https://graph.microsoft.com/v1.0/users/$encodedUpn`?`$select=id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,createdDateTime,signInActivity"

            try {
                $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
            }
            catch {
                # Fallback if Purview returned primary SMTP address instead of UPN
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       Direct UPN lookup failed; trying OData mail/UPN filter fallback for '$upn'..." -Color DarkYellow
                $filterUri = "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$upn' or userPrincipalName eq '$upn'&`$select=id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,createdDateTime,signInActivity"
                $filterResp = Invoke-MgGraphRequest -Method GET -Uri $filterUri -ErrorAction Stop
                if ($filterResp.value -and $filterResp.value.Count -gt 0) {
                    $user = $filterResp.value[0]
                } else {
                    throw "User '$upn' not found in Entra ID via direct lookup or mail filter."
                }
            }

            $userId       = $user.id
            $resolvedUpn  = $user.userPrincipalName
            Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       Resolved User: $($user.displayName) (ObjectId: $userId | Enabled: $($user.accountEnabled))" -Color Green

            # 4b. Transitive Group Memberships (GroupMember.Read.All)
            Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "  [4b] Querying Transitive Security Group Memberships..." -Color Gray
            $securityGroups = "None"
            try {
                $groupsUri = "https://graph.microsoft.com/v1.0/users/$userId/transitiveMemberOf/microsoft.graph.group?`$select=displayName,securityEnabled"
                $groups = @(Get-GraphPagedItems -Uri $groupsUri -ContextLabel "UserGroups")
                $secGroupList = @($groups | Where-Object { $_.securityEnabled -eq $true } | ForEach-Object { $_.displayName })
                if ($secGroupList.Count -gt 0) {
                    $securityGroups = $secGroupList -join "; "
                }
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       Found $($secGroupList.Count) Security Group(s) (out of $($groups.Count) total groups)." -Color Gray
            }
            catch {
                $securityGroups = "Error/Insufficient Permissions"
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       [!] Group lookup failed: $($_.Exception.Message)" -Color DarkYellow
            }

            # 4c. Directory Role Assignments (RoleManagement.Read.Directory)
            Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "  [4c] Querying Entra Directory Role Assignments..." -Color Gray
            $assignedRoles = "None (Standard User)"
            try {
                $rolesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$userId'&`$expand=roleDefinition(`$select=displayName)"
                $roles = @(Get-GraphPagedItems -Uri $rolesUri -ContextLabel "DirectoryRoles")
                $roleList = @($roles | ForEach-Object { $_.roleDefinition.displayName } | Where-Object { $_ } | Select-Object -Unique)
                if ($roleList.Count -gt 0) {
                    $assignedRoles = $roleList -join "; "
                }
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       Directory Roles Assigned: $assignedRoles" -Color Gray
            }
            catch {
                $assignedRoles = "Error/Insufficient Permissions"
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       [!] Role assignment lookup failed: $($_.Exception.Message)" -Color DarkYellow
            }

            # 4d. Authentication Methods & MFA Status (Reports.Read.All)
            Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "  [4d] Querying MFA & Authentication Method Registration Details..." -Color Gray
            $mfaRegistered = "Unknown"
            $isAdminStatus = "Unknown"
            try {
                $mfaUri  = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/$userId"
                $mfaData = Invoke-MgGraphRequest -Method GET -Uri $mfaUri -ErrorAction Stop
                if ($null -ne $mfaData) {
                    $mfaRegistered = $mfaData.isMfaRegistered
                    $isAdminStatus = $mfaData.isAdmin
                }
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       MFA Registered: $mfaRegistered | IsAdmin Flag: $isAdminStatus" -Color Gray
            }
            catch {
                Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       [!] MFA status lookup unavailable: $($_.Exception.Message)" -Color DarkYellow
            }

            # 4e. OneDrive Storage Size & Quota Lookup (Files.Read.All / Sites.Read.All + Reports.Read.All Fallback)
            Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "  [4e] Querying OneDrive Storage Size & Quota..." -Color Gray
            $oneDriveUrl       = "N/A"
            $oneDriveUsedBytes = 0
            $oneDriveUsedMB    = "N/A"
            $oneDriveUsedGB    = "N/A"
            $oneDriveQuotaGB   = "N/A"
            $oneDriveState     = "Unprovisioned / Not Found"

            try {
                $driveUri  = "https://graph.microsoft.com/v1.0/users/$userId/drive?`$select=id,webUrl,quota"
                $driveResp = Invoke-MgGraphRequest -Method GET -Uri $driveUri -ErrorAction Stop

                if ($null -ne $driveResp) {
                    $oneDriveUrl = if ($driveResp.webUrl) { $driveResp.webUrl } else { "Provisioned (No URL)" }
                    if ($null -ne $driveResp.quota) {
                        $oneDriveUsedBytes = [int64]$driveResp.quota.used
                        $oneDriveUsedMB    = [math]::Round(($driveResp.quota.used / 1MB), 2)
                        $oneDriveUsedGB    = [math]::Round(($driveResp.quota.used / 1GB), 4)
                        $oneDriveQuotaGB   = [math]::Round(($driveResp.quota.total / 1GB), 2)
                        $oneDriveState     = if ($driveResp.quota.state) { $driveResp.quota.state } else { "Normal (Graph Drive API)" }
                    }
                    Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       [Direct Drive API] OneDrive Size: $oneDriveUsedMB MB ($oneDriveUsedGB GB / $oneDriveQuotaGB GB Quota) | URL: $oneDriveUrl" -Color Green
                }
            }
            catch {
                # Fallback to cached M365 Usage Report if direct /drive endpoint fails or returns 403/404
                $lookupKey = if ($resolvedUpn) { $resolvedUpn.Trim().ToLower() } else { $upn }
                if ($OneDriveReportCache.ContainsKey($lookupKey)) {
                    $cachedOd = $OneDriveReportCache[$lookupKey]
                    $usedB = if (-not [string]::IsNullOrWhiteSpace($cachedOd.'Storage Used (Byte)')) { [double]$cachedOd.'Storage Used (Byte)' } else { 0 }
                    $allocB = if (-not [string]::IsNullOrWhiteSpace($cachedOd.'Storage Allocated (Byte)')) { [double]$cachedOd.'Storage Allocated (Byte)' } else { 0 }

                    $oneDriveUrl       = $cachedOd.'Site URL'
                    $oneDriveUsedBytes = [int64]$usedB
                    $oneDriveUsedMB    = [math]::Round(($usedB / 1MB), 2)
                    $oneDriveUsedGB    = [math]::Round(($usedB / 1GB), 4)
                    $oneDriveQuotaGB   = [math]::Round(($allocB / 1GB), 2)
                    $oneDriveState     = "Resolved via M365 Usage Report"
                    Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       [Report Cache Fallback] OneDrive Size: $oneDriveUsedMB MB ($oneDriveUsedGB GB)" -Color Green
                }
                else {
                    Write-Status -Stage "AUDIT $memberIndex/$totalMembers" -Message "       [!] Could not resolve OneDrive size for $resolvedUpn : $($_.Exception.Message)" -Color DarkYellow
                }
            }

            # 4f. Assemble Report Object
            $lastInteractive    = if ($user.signInActivity) { $user.signInActivity.lastSignInDateTime } else { $null }
            $lastNonInteractive = if ($user.signInActivity) { $user.signInActivity.lastNonInteractiveSignInDateTime } else { $null }

            $IdentityReport += [PSCustomObject]@{
                UserPrincipalName      = $resolvedUpn
                DisplayName            = $user.displayName
                AccountEnabled         = $user.accountEnabled
                Department             = $user.department
                JobTitle               = $user.jobTitle
                ActivePurviewHolds     = ($HoldMembers[$upn] | Select-Object -Unique) -join " | "
                OneDriveUrl            = $oneDriveUrl
                OneDriveUsedBytes      = $oneDriveUsedBytes
                OneDriveUsedMB         = $oneDriveUsedMB
                OneDriveUsedGB         = $oneDriveUsedGB
                OneDriveQuotaGB        = $oneDriveQuotaGB
                OneDriveStatus         = $oneDriveState
                EntraDirectoryRoles    = $assignedRoles
                SecurityGroupAccess    = $securityGroups
                IsMfaRegistered        = $mfaRegistered
                IsAdmin                = $isAdminStatus
                LastInteractiveSignIn  = $lastInteractive
                LastNonInteractiveAuth = $lastNonInteractive
            }
        }
        catch {
            Write-Warning "[!] Could not resolve Entra identity for hold member '$upn' : $_"
            # Preserve the hold member in the report even if their Entra user object was deleted
            $IdentityReport += [PSCustomObject]@{
                UserPrincipalName      = $upn
                DisplayName            = "Unresolved / Deleted User"
                AccountEnabled         = "N/A"
                Department             = "N/A"
                JobTitle               = "N/A"
                ActivePurviewHolds     = ($HoldMembers[$upn] | Select-Object -Unique) -join " | "
                OneDriveUrl            = "N/A"
                OneDriveUsedBytes      = 0
                OneDriveUsedMB         = "N/A"
                OneDriveUsedGB         = "N/A"
                OneDriveQuotaGB        = "N/A"
                OneDriveStatus         = "User Not Found in Entra"
                EntraDirectoryRoles    = "N/A"
                SecurityGroupAccess    = "N/A"
                IsMfaRegistered        = "N/A"
                IsAdmin                = "N/A"
                LastInteractiveSignIn  = "N/A"
                LastNonInteractiveAuth = "N/A"
            }
        }
    }

    Write-Progress -Activity "Auditing Purview Hold Members" -Completed

    # ==============================================================================
    # 5. Output to Console & Export to CSV
    # ==============================================================================
    if ($IdentityReport.Count -gt 0) {
        Write-Host "`n==========================================================================================================" -ForegroundColor Yellow
        Write-Host "               PURVIEW EDISCOVERY HOLD MEMBERS - IDENTITY & ONEDRIVE SIZING REPORT                        " -ForegroundColor Yellow
        Write-Host "==========================================================================================================" -ForegroundColor Yellow

        $IdentityReport | Format-Table `
            UserPrincipalName, `
            AccountEnabled, `
            OneDriveUsedMB, `
            OneDriveUsedGB, `
            OneDriveQuotaGB, `
            EntraDirectoryRoles, `
            IsMfaRegistered, `
            ActivePurviewHolds -AutoSize

        $IdentityReport | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Status -Stage "EXPORT" -Message "Successfully exported $($IdentityReport.Count) hold member record(s) to: $ExportPath" -Color Green
    }
    else {
        Write-Status -Stage "EXPORT" -Message "No records were generated to export." -Color Red
    }
}
finally {
    Write-Status -Stage "CLEANUP" -Message "Disconnecting Microsoft Graph session..." -Color Cyan
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Status -Stage "COMPLETE" -Message "Audit execution finished." -Color Green
}