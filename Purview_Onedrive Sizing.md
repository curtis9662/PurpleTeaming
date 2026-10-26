# View Onedrive Sizing

.SYNOPSIS
    Discovers OneDrive sizes (> 1000 Bytes) using Microsoft Graph App-Only authentication.
.DESCRIPTION
    Compatible with Windows PowerShell 5.1+.
    Requires an Entra ID App Registration with Client Secrets and Application permissions:
    - Reports.Read.All
    - Files.Read.All
    Note: To prevent masked User Principal Names in the CSV report, ensure 
    "Display concealed user, group, and site names in all reports" is unchecked 
    in M365 Admin Center > Settings > Org settings > Services > Reports.
```
<#
.SYNOPSIS
    Discovers OneDrive sizes (> 1000 Bytes) using Microsoft Graph App-Only authentication.
.DESCRIPTION
    Compatible with Windows PowerShell 5.1+.
    Requires an Entra ID App Registration with Client Secrets and Application permissions:
    - Reports.Read.All
    - Files.Read.All
    Note: To prevent masked User Principal Names in the CSV report, ensure 
    "Display concealed user, group, and site names in all reports" is unchecked 
    in M365 Admin Center > Settings > Org settings > Services > Reports. ← L👀K
#>
# Ensure TLS 1.2 is enforced for Windows PowerShell 5.1 (.NET Framework)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Resolve working directory safely whether run as a .ps1 file or pasted into PS 5.1 console/ISE
$WorkDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { $PWD.Path }
# 1. Configuration Parameters (Replace with your actual Tenant & App credentials)
$TenantId     = "Your Actual Entra Tenant ID"
$ClientId     = "The Actual Enterprise App ID"
$ClientSecret = "4Hy7O~***********************724bjkb433002"
# Target Scope Configuration: > 1000 OneDrive bytes (Update bytes as you deem fit) 1,000,000 bytes = 1MB
$MinStorageBytes = 1000
# Optional: Leave empty @() to evaluate all tenant OneDrive accounts > 1000 bytes, 
# or populate specific UPNs to restrict to both the UPN list AND > 1000 bytes.
$PurviewHoldUserUPNs = @()
Write-Host "`n[INIT] Initializing Microsoft Graph Purview OneDrive Size Discovery Tool..." -ForegroundColor Cyan
# 2. Validate prerequisites and connect
Write-Host "[AUTH] Authenticating to Microsoft Graph using Client Credentials (App-Only)..." -ForegroundColor Yellow
try {
    $secSecret  = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
    $context = Get-MgContext
    Write-Host "[SUCCESS] Authenticated successfully!" -ForegroundColor Green
    Write-Host "          - Tenant ID : $($context.TenantId)" -ForegroundColor DarkGray
    Write-Host "          - App ID    : $($context.ClientId)" -ForegroundColor DarkGray
}
catch {
    Write-Error "[FATAL] Authentication failed: $_"
    return
}
try {
    # 3. Pull the per-user OneDrive account report stream with progress animation
    Write-Host "`n[GRAPH] Querying M365 Reporting API (Reports.Read.All)..." -ForegroundColor Yellow
    Write-Host "        Target Endpoint: getOneDriveUsageAccountDetail(period='D7')" -ForegroundColor DarkGray
    $ReportUri   = "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='D7')"
    $TempCsvPath = Join-Path -Path $WorkDir -ChildPath "OneDriveUsageReport_Raw.csv"
    Write-Progress -Activity "Microsoft Graph Data Acquisition" -Status "Downloading raw OneDrive storage stream..." -PercentComplete 30
    # Execute the Graph request and write stream to disk
    Invoke-MgGraphRequest -Method GET -Uri $ReportUri -OutputFilePath $TempCsvPath -ErrorAction Stop
    Write-Progress -Activity "Microsoft Graph Data Acquisition" -Status "Download complete. Processing payload..." -PercentComplete 60
    if (Test-Path -Path $TempCsvPath) {
        Write-Host "[PARSE] Sanitizing CSV structure and cleaning report headers..." -ForegroundColor Yellow
        $CleanCsvPath = Join-Path -Path $WorkDir -ChildPath "OneDriveUsageReport_Clean.csv"
        $CsvContent   = @(Get-Content -Path $TempCsvPath)
        $HeaderMatch = $CsvContent | Select-String -Pattern "Report Refresh Date" | Select-Object -First 1
        if ($HeaderMatch) {
            $StartIndex = $HeaderMatch.LineNumber - 1
            $CsvContent[$StartIndex..($CsvContent.Length - 1)] | Out-File -FilePath $CleanCsvPath -Encoding utf8
        } else {
            $CsvContent | Out-File -FilePath $CleanCsvPath -Encoding utf8
        }
        $OneDriveReport = @(Import-Csv -Path $CleanCsvPath)
        Write-Host "[SUCCESS] Successfully parsed $($OneDriveReport.Count) total tenant user records." -ForegroundColor Green
        # 4. Filter and process records (Target Scope: > 1000 OneDrive Bytes)
        Write-Host "`n[PROCESS] Filtering records against Target Scope (> $MinStorageBytes OneDrive bytes)..." -ForegroundColor Yellow
        if ($PurviewHoldUserUPNs.Count -gt 0) {
            Write-Host "          Scope: Storage Used > $MinStorageBytes bytes AND in Purview Hold UPN list ($($PurviewHoldUserUPNs.Count) users)..." -ForegroundColor DarkGray
        } else {
            Write-Host "          Scope: All discovered OneDrive records with Storage Used > $MinStorageBytes bytes." -ForegroundColor DarkGray
        }
        $Results = $OneDriveReport | ForEach-Object {
            # Parse raw Storage Used into bytes
            $usedBytes = if (-not [string]::IsNullOrWhiteSpace($_.'Storage Used (Byte)')) {
                [double]$_.'Storage Used (Byte)'
            } elseif (-not [string]::IsNullOrWhiteSpace($_.'Storage Used (MB)')) {
                [double]$_.'Storage Used (MB)' * 1MB
            } else { 0 }
            $allocBytes = if (-not [string]::IsNullOrWhiteSpace($_.'Storage Allocated (Byte)')) {
                [double]$_.'Storage Allocated (Byte)'
            } elseif (-not [string]::IsNullOrWhiteSpace($_.'Storage Allocated (MB)')) {
                [double]$_.'Storage Allocated (MB)' * 1MB
            } else { 0 }
            $upnMatches = ($PurviewHoldUserUPNs.Count -eq 0) -or ($PurviewHoldUserUPNs -contains $_.'User Principal Name')
            # Enforce Target Scope: > 1000 bytes (and optional UPN list if populated)
            if ($usedBytes -gt $MinStorageBytes -and $upnMatches) {
                $displayName = if ($_.PSObject.Properties['Owner Display Name']) {
                    $_.'Owner Display Name'
                } else {
                    $_.'Display Name'
                }
                [PSCustomObject]@{
                    UserPrincipalName  = $_.'User Principal Name'
                    DisplayName        = $displayName
                    SiteUrl            = $_.'Site URL'
                    StorageUsedBytes   = [int64]$usedBytes
                    StorageUsedGB      = [math]::Round(($usedBytes / 1GB), 4)
                    StorageAllocatedGB = [math]::Round(($allocBytes / 1GB), 2)
                    ActiveFileCount    = $_.'Active File Count'
                    LastActivityDate   = $_.'Last Activity Date'
                    IsDeleted          = $_.'Is Deleted'
                }
            }
        }
        # Safely count the results in PS 5.1 (handles $null, single object, or array)
        $ProcessedCount = if ($null -ne $Results) { @($Results).Count } else { 0 }
        Write-Progress -Activity "Microsoft Graph Data Acquisition" -Status "Processing finished." -PercentComplete 100
        Start-Sleep -Milliseconds 500
        Write-Progress -Activity "Microsoft Graph Data Acquisition" -Completed
        Write-Host "[Written By Curtis J] BiG MiChael Michael ABCDEFG I need M-O-N-E-Y Oh Meee" -ForegroundColor Yellow
        Sleep 1
        Write-Host "...1" -ForegroundColor Cyan
        Sleep 1
        Write-Host "...2" -ForegroundColor Green
        Sleep 1
        Write-Host "...3" -ForegroundColor Blue
        
        # 5. Output results
        if ($ProcessedCount -gt 0) {
            Write-Host "`n[EXPORT] Matching OneDrive records (> $MinStorageBytes bytes) found: $ProcessedCount" -ForegroundColor Green
            $ExportFile = Join-Path -Path $WorkDir -ChildPath "PurviewHold_OneDrive_Sizes.csv"
            $Results | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
            Write-Host "         - CSV Report Exported : $ExportFile" -ForegroundColor Cyan
            Write-Host "         - Launching interactive Grid View window..." -ForegroundColor Yellow
            $Results | Out-GridView -Title "OneDrive Storage Sizes - Target Scope > $MinStorageBytes Bytes ($ProcessedCount Users)"
        } else {
            Write-Warning "[WARNING] No matching OneDrive records found with Storage Used > $MinStorageBytes bytes."
        }
        Remove-Item -Path $TempCsvPath -ErrorAction SilentlyContinue
        Remove-Item -Path $CleanCsvPath -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Error "`n[ERROR] An exception occurred during execution: $_"
}
finally {
    Write-Host "`n[CLEANUP] Disconnecting current Graph session..." -ForegroundColor Cyan
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[COMPLETE] Script execution finished.`n" -ForegroundColor Green
}

```

Expected Output:
<img width="872" height="1964" alt="image" src="https://github.com/user-attachments/assets/cd899961-28ca-438c-b456-41285c2ff829" />

Power🐚Console Example:
<img width="1028" height="674" alt="image" src="https://github.com/user-attachments/assets/4639d123-7afc-4a65-8a06-aa766eb218ab" />

