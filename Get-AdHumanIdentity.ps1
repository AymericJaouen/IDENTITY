<#
.SYNOPSIS
    Audits Active Directory users and service accounts across one or more domains,
    with per-OU or domain-level summaries and CSV/HTML export.

.DESCRIPTION
    This script connects to one or more Active Directory domains and retrieves a unified view
    of user and service account metadata. It calculates totals and classifies accounts by:
        - Activity (Active, Inactive, Never Logged In)
        - Managed Service Accounts (MSA)
        - Group Managed Service Accounts (gMSA)
        - PasswordNeverExpires flag
        - Naming pattern matches (optional)

    You can:
        - Target specific domains or scan the full forest
        - Provide wildcard-based name patterns to flag service accounts
        - Choose per-OU or summary reporting view
        - Automatically export results to a timestamped CSV and HTML report

.PARAMETER SpecificDomains
    Optional. An array of fully qualified domain names to audit (e.g., "corp.domain.local").
    If omitted, the script audits all domains in the current forest.

.PARAMETER UserServiceAccountNamesLike
    Optional. Wildcard patterns (e.g., "*svc*", "*_bot") to match account names that represent
    service accounts. Used to classify matching users under ServiceAccountsPatternMatched.

.PARAMETER Mode
    Required. Selects output format:
        - 'UserPerOU': detailed counts per Organizational Unit (OU)
        - 'Summary': consolidated view per domain

.EXAMPLE
    .\Get-AdAudit.ps1 -SpecificDomains "corp.domain.local" -UserServiceAccountNamesLike "*svc*","*_bot" -Mode UserPerOU

    This command:
        - Targets only corp.domain.local
        - Scans for accounts whose Name matches "*svc*" or "*_bot"
        - Classifies and counts users by OU
        - Outputs results to .\ADReports\ADAudit_UserPerOU_<timestamp>.csv and HTML report

.EXAMPLE
    .\Get-AdAudit.ps1 -Mode Summary

    This command:
        - Targets all domains in the forest
        - Skips name-based pattern matching
        - Summarizes and counts users by domain
        - Outputs results to .\ADReports\ADAudit_Summary_<timestamp>.csv and HTML report

.NOTES
    Script Requirements:
        - PowerShell 5.1 or later
        - RSAT: Active Directory module installed (ActiveDirectory)
        - Appropriate permissions to query each domain

    Culture is temporarily forced to en-US during execution to ensure consistent timestamp parsing.
#>
param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [string[]]$SpecificDomains,
    [ValidateSet("UserPerOU", "Summary")]
    [string]$Mode = "UserPerOU"
)

# === Logging Setup ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\ADReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

$logPath = Join-Path $outputPath "AD_Audit_$timestamp.log"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "WHITE"
    )
    $formatted = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $formatted
    Write-Host $Message -ForegroundColor $Color
}

function Initialize-Prerequisites {
    $requiredPSVersion = [Version]"5.1"
    $moduleName = "ActiveDirectory"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" -Level "ERROR" -Color "RED"
        exit
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Required module '$moduleName' not found. Please install RSAT: Active Directory Tools." -Level "ERROR" -Color "RED"
            exit
        }
        Import-Module $moduleName -ErrorAction Stop
    } catch {
        Write-Log "Failed to import '$moduleName'. Ensure it's installed and accessible. $_" -Level "ERROR" -Color "RED"
        exit
    }

    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Prerequisites validated. Environment initialized." -Color "Green"
}

Initialize-Prerequisites

# =====================
# Helper Functions
# =====================

function Get-OUFromDN {
    param ([string]$dn)
    ($dn -split '(?<!\\),')[1..($dn.Count - 1)] -join ','
}

function Test-ManagedServiceAccount {
    param ([string]$SamAccountName, [string[]]$MSASet)
    return $MSASet -contains $SamAccountName
}

function Test-GroupManagedServiceAccount {
    param ([string]$SamAccountName, [string[]]$GMSASet)
    return $GMSASet -contains $SamAccountName
}

function Test-NonExpiringUser {
    param ([string]$SamAccountName, [string[]]$NoExpireSet)
    return $NoExpireSet -contains $SamAccountName
}

function Test-PatternMatchedUser {
    param ([string]$SamAccountName, [string[]]$PatternSet)
    return $PatternSet -contains $SamAccountName
}

function Get-UsersAsServiceAccount {
    param (
        [string[]]$NamePatterns,
        [string]$Domain
    )

    if (-not $NamePatterns -or $NamePatterns.Count -eq 0) {
        return @()
    }

    $subs = @()
    foreach ($pattern in $NamePatterns) {
        Write-Log "[$Domain] Searching for users like '$pattern'..." -ForegroundColor Yellow
        try {
            $usersFound = Get-ADUser -Server $Domain -Filter "Name -like '$($pattern.Trim())'" `
                -Properties Name, SamAccountName, DistinguishedName, Enabled, LastLogonTimestamp, PasswordNeverExpires, ServicePrincipalName |
                Select-Object Name, SamAccountName, DistinguishedName, Enabled,
                    @{Name="LastLogonDate";Expression={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
                    PasswordNeverExpires,
                    @{Name="ServicePrincipalNames";Expression={($_.ServicePrincipalName -join ";")}}

            $subs += $usersFound
        } catch {
            Write-Warning "[$Domain] Error searching pattern '$pattern': $_"
        }
    }
    return $subs
}

#————————————————————————————————————————
# 1. DATA COLLECTION & AGGREGATION
#————————————————————————————————————————

function Get-ADUserData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $DomainsToAudit,
        [Parameter(Mandatory = $false)]
        [string[]] $ServicePattern = @()
    )

    begin {
        Write-Log "Initializing data collection..." -Color Green
        $summary = [System.Collections.Generic.List[PSCustomObject]]::new()
        $logonThreshold = (Get-Date).AddDays(-180)
    }

    process {
        foreach ($domain in $DomainsToAudit) {
            Write-Log "Auditing domain: $domain" -Color Cyan

            try {
                # Preload reference data for the domain
                $msaSet = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' } | Select-Object -ExpandProperty SamAccountName -ErrorAction SilentlyContinue)
                $gmsaSet = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' } | Select-Object -ExpandProperty SamAccountName -ErrorAction SilentlyContinue)
                $noExpireSet = @(Get-ADUser -Server $domain -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } | Select-Object -ExpandProperty SamAccountName -ErrorAction SilentlyContinue)
                $patternSet = @(Get-UsersAsServiceAccount -NamePatterns $ServicePattern -Domain $domain | Select-Object -ExpandProperty SamAccountName)
                
                # Get all user and service account objects
                $userAccounts = Get-ADUser -Server $domain -Filter * -Properties SamAccountName, DistinguishedName, LastLogonTimestamp, Enabled, PasswordNeverExpires -ErrorAction Stop
                $msaObjects = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' })
                $gmsaObjects = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' })
                
                # Combine all objects into a single collection
                $users = $userAccounts + $msaObjects + $gmsaObjects
                
                foreach ($user in $users) {
                    $sam = $user.SamAccountName
                    $ou  = Get-OUFromDN $user.DistinguishedName

                    $entry = $summary | Where-Object { $_.Domain -eq $domain -and $_.OU -eq $ou } | Select-Object -First 1
                    if (-not $entry) {
                        $entry = [PSCustomObject]@{
                            Domain                              = $domain
                            OU                                  = $ou
                            TotalUsers                          = 0
                            ActiveUsers                         = 0
                            InactiveUsers                       = 0
                            NeverLoggedInUsers                  = 0
                            ServiceAccountsManaged              = 0
                            ServiceAccountsGroupManaged         = 0
                            ServiceAccountsPasswordNeverExpires = 0
                            ServiceAccountsPatternMatched       = 0
                        }
                        $summary.Add($entry)
                    }

                    $entry.TotalUsers++
                    
                    if ($user.LastLogonTimestamp) {
                        if ([DateTime]::FromFileTime($user.LastLogonTimestamp) -ge $logonThreshold) {
                            $entry.ActiveUsers++
                        } else {
                            $entry.InactiveUsers++
                        }
                    } else {
                        $entry.NeverLoggedInUsers++
                    }

                    if (Test-ManagedServiceAccount $sam $msaSet) { $entry.ServiceAccountsManaged++ }
                    if (Test-GroupManagedServiceAccount $sam $gmsaSet) { $entry.ServiceAccountsGroupManaged++ }
                    if (Test-NonExpiringUser $sam $noExpireSet) { $entry.ServiceAccountsPasswordNeverExpires++ }
                    if (Test-PatternMatchedUser $sam $patternSet) { $entry.ServiceAccountsPatternMatched++ }
                }
            } catch {
                Write-Log "Failed to process domain $($domain): $_" -Level "ERROR" -Color Red
            }
        }
    }

    end {
        Write-Log "Finished data collection. Found $($summary.Count) summary records." -Color Green
        return $summary
    }
}

#————————————————————————————————————————
# 2. HEADERS
#————————————————————————————————————————
function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("UserPerOU", "Summary")]
        [string] $Mode
    )

    switch ($Mode) {
        'UserPerOU' {
            return [PSCustomObject]@{
                Domain = 'Domain'
                OU = 'Organizational Unit'
                TotalUsers = 'Total Users'
                ActiveUsers = 'Active Users'
                InactiveUsers = 'Inactive Users'
                NeverLoggedInUsers = 'Never Logged In Users'
                ServiceAccountsManaged = 'Managed Service Accounts (MSA)'
                ServiceAccountsGroupManaged = 'Group Managed Service Accounts (gMSA)'
                ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
                ServiceAccountsPatternMatched = 'Service Account Pattern Matched'
            }
        }
        'Summary' {
            return [PSCustomObject]@{
                Domain = 'Domain'
                TotalUsers = 'Total Users'
                ActiveUsers = 'Active Users'
                InactiveUsers = 'Inactive Users'
                NeverLoggedInUsers = 'Never Logged In Users'
                ServiceAccountsManaged = 'Managed Service Accounts (MSA)'
                ServiceAccountsGroupManaged = 'Group Managed Service Accounts (gMSA)'
                ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
                ServiceAccountsPatternMatched = 'Service Account Pattern Matched'
            }
        }
    }
}

#————————————————————————————————————————
# 3. EXPORTERS (CSV + HTML)
#————————————————————————————————————————
function Export-CsvReport {
    param(
        [Parameter(Mandatory)]
        [string] $FileName,
        [Parameter(Mandatory)]
        [object[]] $Data,
        [Parameter(Mandatory)]
        [PSCustomObject] $Columns,
        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName
    $calculatedProperties = @()
    foreach ($name in $Columns.PSObject.Properties.Name) {
        $header = $Columns."$name"
        $calculatedProperties += @{ Name = $header; Expression = [scriptblock]::Create("`$_.`"$name`"") }
    }

    try {
        $Data | Select-Object -Property $calculatedProperties | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Log "Successfully exported CSV report to $fullPath." "INFO" "Green"
    }
    catch {
        Write-Log "Could not export CSV report to $fullPath. Error: $_" "ERROR" "RED"
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory)]
        [string] $FileName,
        [Parameter(Mandatory)]
        [string] $Title,
        [Parameter(Mandatory)]
        [object[]] $Data,
        [Parameter(Mandatory)]
        [PSCustomObject] $Columns,
        [Parameter()]
        [string] $SecondReportTitle,
        [Parameter()]
        [object[]] $SecondReportData,
        [Parameter()]
        [PSCustomObject] $SecondReportColumns,
        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    try {
        function New-HtmlTable {
            param(
                [Parameter(Mandatory)]
                [string] $TableTitle,
                [Parameter(Mandatory)]
                [object[]] $TableData,
                [Parameter(Mandatory)]
                [PSCustomObject] $TableColumns
            )
            $svgContent = '<svg xmlns="http://www.w3.org/2000/svg" height="72" width="72" viewBox="-8 -35000 278050 403334" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" image-rendering="optimizeQuality" fill-rule="evenodd" clip-rule="evenodd"><path fill="#ea3e23" d="M278050 305556l-29-16V28627L178807 0 448 66971l-448 87 22 200227 60865-23821V80555l117920-28193-17 239519L122 267285l178668 65976v73l99231-27462v-316z"/></svg>'
            $html = "<div class='table-header'><div class='table-header-logo'>$svgContent</div><h2>$TableTitle</h2></div>"
            $html += '<table><thead><tr>'
            foreach ($header in $TableColumns.PSObject.Properties.Value) { $html += "<th>$header</th>" }
            $html += '</tr></thead><tbody>'
            foreach ($row in $TableData) {
                $isTotalRow = ($row.OU -eq 'TOTAL' -or $row.Domain -eq 'TOTAL')
                $rowClass = ""
                if ($isTotalRow) { $rowClass = ' class="total"' }
                $html += "<tr$rowClass>"
                foreach ($colName in $TableColumns.PSObject.Properties.Name) {
                    $value = $row."$colName"
                    $html += "<td>$value</td>"
                }
                $html += '</tr>'
            }
            $html += '</tbody></table>'
            return $html
        }

        $logoHtml = "<img src='data:image/svg+xml;base64,PGRpdiBjbGFzcz0ndGFibGUtZ2VuZXJhdG9yLWxvZ28nPgo8c3ZnIHhtbG5zPSdodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZycgaGVpZ2h0PSI3MiIgd2lkdGg9IjcyIiB2aWV3Qm94PSItOCAtMzUwMDAgMjc4MDUwIDQwMzMzNCIgc2hhcGUtcmVuZGVyaW5nPSJnZW9tZXRyaWNQcmVjaXNpb24iIHRleHQtcmVuZGVyaW5nPSJnZW9tZXRyaWNQcmVjaXNpb24iIGltYWdlLXJlbmRlcmluZz0ib3B0aW1pemVRdWFsaXR5IiBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCI+CiAgPGc+CiAgICA8cGF0aCBmaWxsPSIjZWEzZTIzIiBkPSJNMjYyNTcwIDMxOTUxNmwtMjkgLTE2VjE2OTYyOEwyNjE0NTEgNTM5MjkgMTI3NzM1IDAgMTI3NzE0IDIxTDI4NDg2IDc3MDExIDEwMDA5OSA1NDU3MFYxODU3NTFMMTM1MDkgMjY2NDY1bDE5MDc0OSAxMjQ2NTMgMTMzOTUgMjYxMjVMMjA1MzYyIDI3NTgxOVYxMjczODZMMjQzNjkzIDI1MDYyNiAyNDM3MDkgMjUzOTM5IDMxMjc0MiAyOTk5MTEgMzEyNzU4IDMwMDU0OSAzMTE0NDUgMzM1NjE2IDI0Mzg3NCAzNjUwNDQgMjQ0MDk1IDQ1NDM2NSAyOTQ5MzkgNDU0Mzc0IDM5NDI3NSAzNTY3NjggMzg2NzQyIDMzOTczMyAyNjY3OTUgMzM4ODQ2IDI2NzM0MSAxMjkzNzQgMzUyODczVjM1MzE0OSAzNTA2MjQgMzA1NzA5bC0zMTI3MzYgOTc2NDNMMjczODcgMzk4MzEzdi0yMDc4MDZMMjAwNTI0IDEwOTg4NCAtMTE4NTkgMTQ5MDE5LTEyNzc3NSAtMTMyNzUyIDQzNzM4IDIxNDAzMSAxNDQ2MzcgMjAzNjM0IDIyNTcxNyAyNzY4NTdWMjk3NTMyeiIvPgogIDwvZz4KPC9zdmc+CgocL2Rpdj4K" class='header-svg' alt='Rubrik Logo' />"
        $css = @"
<style>
    body { font-family: Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 0; }
    .report-container { max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
    .header { background-color: #0d47a1; color: #fff; padding: 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; display: flex; align-items: center; justify-content: flex-start; }
    .table-header { display: flex; align-items: center; gap: 15px; border-bottom: 2px solid #e0e6ed; padding-bottom: 10px; margin-bottom: 20px; }
    .header h1 { margin: 0; font-size: 24px; margin-left: 20px; }
    .header-svg { height: 45px; width: auto; }
    h2 { color: #0d47a1; font-size: 20px; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; margin-top: 30px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    th, td { padding: 12px; text-align: center; border: 1px solid #ddd; }
    thead th { background-color: #2c3e50; color: white; font-weight: bold; text-transform: uppercase; font-size: 13px; border: 1px solid #2c3e50; }
    tbody tr:nth-child(odd) { background-color: #f9f9f9; }
    tbody tr:nth-child(even) { background-color: #fff; }
    tbody tr:hover { background-color: #e8f4fd; }
    tr.total { font-weight: bold; background-color: #2c3e50 !important; color: #fff; }
    .footer { text-align: center; padding: 15px; font-size: 12px; color: #888; border-top: 1px solid #ddd; margin-top: 20px; }
</style>
"@
        $htmlBody = @"
<html>
<head>
    <title>Active Directory Audit Report</title>
    $css
</head>
<body>
    <div class="report-container">
        <div class="header">
            $logoHtml
            <h1>Active Directory Audit Report</h1>
        </div>
        <br>
"@
        $htmlBody += New-HtmlTable -TableTitle $Title -TableData $Data -TableColumns $Columns
        if ($SecondReportData) {
            $htmlBody += "<br>"
            $htmlBody += New-HtmlTable -TableTitle $SecondReportTitle -TableData $SecondReportData -TableColumns $SecondReportColumns
        }
        $htmlBody += @"
        <div class="footer">
            Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        </div>
    </div>
</body>
</html>
"@
        $htmlBody | Out-File -FilePath $fullPath -Encoding UTF8
        Write-Log "Successfully exported HTML report to $fullPath" "INFO" "Green"
    }
    catch {
        Write-Log "Could not export to HTML file $fullPath. Error: $_" "ERROR" "RED"
    }
}

# =====================
# Main Logic
# =====================

$domainsToAudit = if ($SpecificDomains) {
    $SpecificDomains
} else {
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
}

# The Get-ADUserData function now returns the fully aggregated summary object
$summary = Get-ADUserData -DomainsToAudit $domainsToAudit -ServicePattern $UserServiceAccountNamesLike

# Generate reports based on mode
$reportColumns = Get-ReportHeaders -Mode $Mode
$csvFileName = "ADAudit_${Mode}_$timestamp.csv"
$htmlFileName = "ADAudit_${Mode}_$timestamp.html"

switch ($Mode) {
    "UserPerOU" {
        Write-Log "Generating OU Summary Report..." -Color "Green"
        $reportData = $summary | Sort-Object Domain, OU
        $reportData | Format-Table -AutoSize # For console output
        Export-CsvReport -FileName $csvFileName -Data $reportData -Columns $reportColumns -OutputPath $outputPath
        Export-HtmlReport -FileName $htmlFileName -Title 'Active Directory Audit: User Per OU' -Data $reportData -Columns $reportColumns -OutputPath $outputPath
    }
    "Summary" {
        $summaryGrouped = $summary |
            Group-Object Domain |
            ForEach-Object {
                [PSCustomObject]@{
                    Domain = $_.Name
                    TotalUsers = ($_.Group | Measure-Object TotalUsers -Sum).Sum
                    ActiveUsers = ($_.Group | Measure-Object ActiveUsers -Sum).Sum
                    InactiveUsers = ($_.Group | Measure-Object InactiveUsers -Sum).Sum
                    NeverLoggedInUsers = ($_.Group | Measure-Object NeverLoggedInUsers -Sum).Sum
                    ServiceAccountsManaged = ($_.Group | Measure-Object ServiceAccountsManaged -Sum).Sum
                    ServiceAccountsGroupManaged = ($_.Group | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
                    ServiceAccountsPasswordNeverExpires = ($_.Group | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
                    ServiceAccountsPatternMatched = ($_.Group | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
                }
            }
        
        Write-Log "Generating Domain Summary Report..." -Color "Green"
        $reportData = $summaryGrouped | Sort-Object Domain
        $reportData | Format-Table -AutoSize # For console output
        Export-CsvReport -FileName $csvFileName -Data $reportData -Columns $reportColumns -OutputPath $outputPath
        Export-HtmlReport -FileName $htmlFileName -Title 'Active Directory Audit: Domain Summary' -Data $reportData -Columns $reportColumns -OutputPath $outputPath
    }
}

Write-Log "AD reports generation completed. Results saved to $outputPath." -Color "Green"
Write-Log "Please send all the files within the directory to your Rubrik Sales representative." -Color "Green"

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture
