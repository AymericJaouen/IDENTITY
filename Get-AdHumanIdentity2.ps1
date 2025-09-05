<#
.SYNOPSIS
    Audits Active Directory users and service accounts across one or more domains,
    with per-OU, domain-level, or detailed per-user summaries and CSV/HTML export.

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
        - Choose per-OU, summary, or detailed per-user reporting view
        - Automatically export results to a timestamped CSV and HTML report

.PARAMETER SpecificDomains
    Optional. An array of fully qualified domain names to audit (e.g., "corp.domain.local").
    If omitted, the script audits all domains in the current forest.

.PARAMETER UserServiceAccountNamesLike
    Optional. Wildcard patterns (e.g., "*svc*", "*_bot") to match account names that represent
    service accounts. Used to classify matching users under ServiceAccountsPatternMatched.

.PARAMETER Mode
    Required. Selects output format:
        - 'Full': detailed counts per Organizational Unit (OU)
        - 'Summary': consolidated view per domain
        - 'Detailed': a flat list of every user with their properties

.EXAMPLE
    .\Get-AdAudit.ps1 -SpecificDomains "corp.domain.local" -UserServiceAccountNamesLike "*svc*","*_bot" -Mode Full

    This command:
        - Targets only corp.domain.local
        - Scans for accounts whose Name matches "*svc*" or "*_bot"
        - Classifies and counts users by OU
        - Outputs results to .\ADReports\ADAudit_Full_<timestamp>.csv and HTML report

.EXAMPLE
    .\Get-AdAudit.ps1 -Mode Detailed

    This command:
        - Targets all domains in the forest
        - Skips name-based pattern matching
        - Outputs a detailed list of every account found in the forest
        - Outputs results to .\ADReports\ADAudit_Detailed_<timestamp>.csv and HTML report

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
    [ValidateSet("Full", "Summary", "Detailed")]
    [string]$Mode = "Full"
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

# === Log the command that started the script ===
try {
    $commandString = $MyInvocation.MyCommand.Name
    foreach ($param in $MyInvocation.BoundParameters.GetEnumerator()) {
        $paramName = $param.Key
        $paramValue = $param.Value

        $formattedValue = ""
        if ($paramValue -is [System.Array]) {
            # Format array parameters like "val1", "val2"
            $formattedValue = '"' + ($paramValue -join '", "') + '"'
        } elseif ($paramValue -is [string] -and $paramValue.Contains(" ")) {
            # Quote strings with spaces
            $formattedValue = """$paramValue"""
        } else {
            # Simple strings, numbers, booleans
            $formattedValue = $paramValue.ToString()
        }
        $commandString += " -$paramName $formattedValue"
    }
    Write-Log "Script started with command: $commandString" "INFO" "Magenta"
}
catch {
    Write-Log "Could not log the command line. Error: $_" "WARNING" "Yellow"
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

    Write-Log "Successfully validated prerequisites. Environment initialized." -level "INFO" -Color "Green"
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
# 1. DATA COLLECTION (NO AGGREGATION)
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
        Write-Log "Initializing data collection..." -level "INFO" -Color Cyan
        $allUserData = [System.Collections.Generic.List[PSCustomObject]]::new()
        $logonThreshold = (Get-Date).AddDays(-180)
    }

    process {
        foreach ($domain in $DomainsToAudit) {
            Write-Log "Auditing domain: $domain" -Color Cyan

            try {
                # Get all user-like objects (users, MSAs, and gMSAs) in one go
                $users = Get-ADObject -Server $domain -Filter "ObjectClass -eq 'user' -or ObjectClass -eq 'msDS-ManagedServiceAccount' -or ObjectClass -eq 'msDS-GroupManagedServiceAccount'" `
                    -Properties SamAccountName, DistinguishedName, LastLogonTimestamp, Enabled, PasswordNeverExpires, ObjectClass -ErrorAction Stop
                
                # Build a lookup table for pattern matches
                $patternMatchedSet = @()
                if ($ServicePattern.Count -gt 0) {
                    $patternMatchedSet = @($users | Where-Object { $ServicePattern | Where-Object { $_.SamAccountName -like $_ } } | Select-Object -ExpandProperty SamAccountName)
                }

                # Process the unique list of objects
                foreach ($user in $users) {
                    $sam = $user.SamAccountName
                    $ou  = Get-OUFromDN $user.DistinguishedName
                    
                    # Correctly handle LastLogonTimestamp
                    $lastLogonTimestampValue = if ($user.LastLogonTimestamp) { $user.LastLogonTimestamp } else { 0 }
                    $lastLogonDate = [DateTime]::FromFileTime($lastLogonTimestampValue)

                    # Safely get PasswordNeverExpires for user objects only
                    $passwordNeverExpiresValue = 0
                    try {
                        if ($user.ObjectClass -eq 'user') {
                            $passwordNeverExpiresValue = [int]$user.PasswordNeverExpires
                        }
                    } catch {
                        # Ignore the error if the property is not found
                    }

                    # Add the formatted user data to the list
                    $allUserData.Add([PSCustomObject]@{
                        Domain = $domain
                        SamAccountName = $sam
                        DistinguishedName = $user.DistinguishedName
                        OU = $ou
                        LastLogonDate = $lastLogonDate
                        LastLogonTimestamp = $lastLogonTimestampValue
                        Enabled = [int]$user.Enabled
                        MSA = if ($user.ObjectClass -eq 'msDS-ManagedServiceAccount') { 1 } else { 0 }
                        GMSA = if ($user.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 1 } else { 0 }
                        PasswordNeverExpires = $passwordNeverExpiresValue
                        PatternMatched = if ($patternMatchedSet -contains $sam) { 1 } else { 0 }
                    })
                }
            } catch {
                Write-Log "Failed to process domain $($domain): $_" -Level "ERROR" -Color RED
            }
        }
    }

    end {
        Write-Log "Finished data collection. Found $($allUserData.Count) user records." -level "INFO" -Color Green
        return $allUserData
    }
}

#————————————————————————————————————————
# 2. HEADERS
#————————————————————————————————————————
function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Full", "Summary", "Detailed")]
        [string] $Mode
    )
    switch ($Mode) {
        'Full' {
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
        'Detailed' {
             return [PSCustomObject]@{
                Domain = 'Domain'
                SamAccountName = 'SAM ACCOUNTNAME'
                OU = 'Organizational Unit'
                Active = 'Active'
                Inactive = 'Inactive'
                NeverLoggedIn = 'Never Logged In'
                MSA = 'Is MSA'
                GMSA = 'Is GMSA'
                PasswordNeverExpires = 'Password Never Expires'
                PatternMatched = 'Is Pattern Matched'
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
        Write-Log "Could not export CSV report to $fullPath. Error: $_" "ERROR" -Color "RED"
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

        $logoHtml = "<img src='data:image/svg+xml;base64,PGRpdiBjbGFz"
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
        Write-Log "Could not export to HTML file $fullPath. Error: $_" "ERROR" -Color "RED"
    }
}

# =====================
# Main Logic
# =====================

$logonThreshold = (Get-Date).AddDays(-180)
$domainsToAudit = if ($SpecificDomains) {
    $SpecificDomains
} else {
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
}

# 1. Collect all user data as a flat list
Write-Log "Collecting User Data..." -Color "Cyan"
$allUserData = Get-ADUserData -DomainsToAudit $domainsToAudit -ServicePattern $UserServiceAccountNamesLike

# 2. Aggregate the data for reporting purposes
$summary = $allUserData | Group-Object -Property Domain, OU | ForEach-Object {
    $group = $_.Group
    $ouName = if ($_.Name.Split(',').Count -gt 1) { $_.Name.Split(',')[1].Trim() } else { "Unknown" }
    
    # Define a special date for users who have never logged in
    $neverLoggedInDate = [DateTime]::FromFileTime(0)

    [PSCustomObject]@{
        Domain = $_.Name.Split(',')[0].Trim()
        OU = $ouName
        TotalUsers = $group.Count
        ActiveUsers = ($group | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -ge $logonThreshold -and $_.LastLogonDate -ne $neverLoggedInDate }).Count
        InactiveUsers = ($group | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -lt $logonThreshold -and $_.LastLogonDate -ne $neverLoggedInDate }).Count
        NeverLoggedInUsers = ($group | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -eq $neverLoggedInDate }).Count
        ServiceAccountsManaged = ($group | Where-Object { $_.MSA -eq 1 }).Count
        ServiceAccountsGroupManaged = ($group | Where-Object { $_.GMSA -eq 1 }).Count
        ServiceAccountsPasswordNeverExpires = ($group | Where-Object { $_.PasswordNeverExpires -eq 1 }).Count
        ServiceAccountsPatternMatched = ($group | Where-Object { $_.PatternMatched -eq 1 }).Count
    }
}

# Generate reports based on mode
$reportColumns = Get-ReportHeaders -Mode $Mode
$csvFileName = "ADAudit_${Mode}_$timestamp.csv"
$htmlFileName = "ADAudit_${Mode}_$timestamp.html"

switch ($Mode) {
    "Full" {
        Write-Log "Generating Full Report..." -level "INFO" -Color "Cyan"
        $reportData = $summary | Sort-Object Domain, OU
        
        # Add total row
        $totalRow = [PSCustomObject]@{
            Domain = 'TOTAL'
            OU = ''
            TotalUsers = ($reportData | Measure-Object TotalUsers -Sum).Sum
            ActiveUsers = ($reportData | Measure-Object ActiveUsers -Sum).Sum
            InactiveUsers = ($reportData | Measure-Object InactiveUsers -Sum).Sum
            NeverLoggedInUsers = ($reportData | Measure-Object NeverLoggedInUsers -Sum).Sum
            ServiceAccountsManaged = ($reportData | Measure-Object ServiceAccountsManaged -Sum).Sum
            ServiceAccountsGroupManaged = ($reportData | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
            ServiceAccountsPasswordNeverExpires = ($reportData | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
            ServiceAccountsPatternMatched = ($reportData | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
        }
        $reportData += $totalRow
        
        #$reportData | Format-Table -AutoSize # For console output
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

        # Force the output to be an array before adding the total row
        $reportData = @($summaryGrouped | Sort-Object Domain)

        # Add total row to the end of the sorted data
        $totalRow = [PSCustomObject]@{
            Domain = 'TOTAL'
            TotalUsers = ($reportData | Measure-Object TotalUsers -Sum).Sum
            ActiveUsers = ($reportData | Measure-Object ActiveUsers -Sum).Sum
            InactiveUsers = ($reportData | Measure-Object InactiveUsers -Sum).Sum
            NeverLoggedInUsers = ($reportData | Measure-Object NeverLoggedInUsers -Sum).Sum
            ServiceAccountsManaged = ($reportData | Measure-Object ServiceAccountsManaged -Sum).Sum
            ServiceAccountsGroupManaged = ($reportData | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
            ServiceAccountsPasswordNeverExpires = ($reportData | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
            ServiceAccountsPatternMatched = ($reportData | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
        }
        $reportData += $totalRow

        Write-Log "Generating Domain Summary Report..." -level "INFO" -Color "Cyan"
        #$reportData | Format-Table -AutoSize # For console output
        Export-CsvReport -FileName $csvFileName -Data $reportData -Columns $reportColumns -OutputPath $outputPath
        Export-HtmlReport -FileName $htmlFileName -Title 'Active Directory Audit: Domain Summary' -Data $reportData -Columns $reportColumns -OutputPath $outputPath
    }
"Detailed" {
    Write-Log "Generating Detailed Per-User Report..." -level "INFO" -Color "Cyan"
    $neverLoggedInDate = [DateTime]::FromFileTime(0)
    $reportData = $allUserData | Select-Object `
        Domain, `
        SamAccountName, `
        OU, `
        @{
            Name = "Active"
            Expression = { if ($_.Enabled -eq 1 -and $_.LastLogonDate -ge $logonThreshold -and $_.LastLogonDate -ne $neverLoggedInDate) { 1 } else { 0 } }
        }, `
        @{
            Name = "Inactive"
            Expression = { if ($_.Enabled -eq 1 -and $_.LastLogonDate -lt $logonThreshold -and $_.LastLogonDate -ne $neverLoggedInDate) { 1 } else { 0 } }
        }, `
        @{
            Name = "NeverLoggedIn"
            Expression = { if ($_.Enabled -eq 1 -and $_.LastLogonDate -eq $neverLoggedInDate) { 1 } else { 0 } }
        }, `
        @{
            Name = "MSA"
            Expression = { if ($_.MSA -eq 1) { 1 } else { 0 } }
        }, `
        @{
            Name = "GMSA"
            Expression = { if ($_.GMSA -eq 1) { 1 } else { 0 } }
        }, `
        @{
            Name = "PasswordNeverExpires"
            Expression = { if ($_.PasswordNeverExpires -eq 1) { 1 } else { 0 } }
        }, `
        @{
            Name = "PatternMatched"
            Expression = { if ($_.PatternMatched -eq 1) { 1 } else { 0 } }
        } | Sort-Object Domain, OU, SamAccountName

        # Add total row
        $totalRow = [PSCustomObject]@{
            Domain = 'TOTAL'
            SamAccountName = ''
            OU = ''
            Active = ($reportData | Measure-Object Active -Sum).Sum
            Inactive = ($reportData | Measure-Object Inactive -Sum).Sum
            NeverLoggedIn = ($reportData | Measure-Object NeverLoggedIn -Sum).Sum
            MSA = ($reportData | Measure-Object MSA -Sum).Sum
            GMSA = ($reportData | Measure-Object GMSA -Sum).Sum
            PasswordNeverExpires = ($reportData | Measure-Object PasswordNeverExpires -Sum).Sum
            PatternMatched = ($reportData | Measure-Object PatternMatched -Sum).Sum
        }
        $reportData += $totalRow

        #$reportData | Format-Table -AutoSize # For console output
        Export-CsvReport -FileName $csvFileName -Data $reportData -Columns $reportColumns -OutputPath $outputPath
        Export-HtmlReport -FileName $htmlFileName -Title 'Active Directory Audit: Detailed Per-User List' -Data $reportData -Columns $reportColumns -OutputPath $outputPath
    }
}

Write-Log "Successfully generated AD reports. Results saved to $outputPath." -level "INFO" -Color "Green"

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture
