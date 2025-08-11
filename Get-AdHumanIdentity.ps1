<#
.SYNOPSIS
    Audits Active Directory users and service accounts across one or more domains,
    with per-OU or domain-level summaries and CSV export.

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
        - Automatically export results to a timestamped CSV

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
    .\Get-AdHumainIdentity.ps1 -SpecificDomains "corp.domain.local" -UserServiceAccountNamesLike "*svc*","*_bot" -Mode UserPerOU

    This command:
        - Targets only corp.domain.local
        - Scans for accounts whose Name matches "*svc*" or "*_bot"
        - Classifies and counts users by OU
        - Outputs results to .\ADReports\UserAudit_UserPerOU_<timestamp>.csv

.EXAMPLE
    .\Get-AdHumainIdentity.ps1

    This default call:
        - Targets all domains in the forest
        - Skips name-based pattern matching
        - Defaults to UserPerOU mode
        - Outputs results to .\ADReports\UserAudit_UserPerOU_<timestamp>.csv

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
        [string]$Level = "INFO"
    )
    $formatted = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $formatted
    Write-Host $Message
}

function Initialize-Prerequisites {
    $requiredPSVersion = [Version]"5.1"
    $moduleName = "ActiveDirectory"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)"
        exit
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Required module '$moduleName' not found. Please install RSAT: Active Directory Tools."
            exit
        }
        Import-Module $moduleName -ErrorAction Stop
    } catch {
        Write-Log "Failed to import '$moduleName'. Ensure it's installed and accessible. $_"
        exit
    }

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Prerequisites validated. Environment initialized." -ForegroundColor Green
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
        return @()  # nothing to do
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
# 1. HEADERS
#————————————————————————————————————————
# This function generates the headers for the report based on the type of report requested.
# It can generate headers for both user-based and domain-based reports.

function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("UserPerOU", "Summary")]
        [string] $Mode
    )

    switch ($Mode) {
        'UserPerOU' {
            # These properties must match the output of your $summary object when Mode is UserPerOU
            return [PSCustomObject]@{
                Domain                              = 'Domain'
                OU                                  = 'Organizational Unit'
                TotalUsers                          = 'Total Users'
                ActiveUsers                         = 'Active Users'
                InactiveUsers                       = 'Inactive Users'
                NeverLoggedInUsers                  = 'Never Logged In Users'
                ServiceAccountsManaged              = 'Managed Service Accounts (MSA)'
                ServiceAccountsGroupManaged         = 'Group Managed Service Accounts (gMSA)'
                ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
                ServiceAccountsPatternMatched       = 'Service Account Pattern Matched'
            }
        }
        'Summary' {
            # These properties must match the output of your $summaryGrouped object when Mode is Summary
            return [PSCustomObject]@{
                Domain                              = 'Domain'
                TotalUsers                          = 'Total Users'
                ActiveUsers                         = 'Active Users'
                InactiveUsers                       = 'Inactive Users'
                NeverLoggedInUsers                  = 'Never Logged In Users'
                ServiceAccountsManaged              = 'Managed Service Accounts (MSA)'
                ServiceAccountsGroupManaged         = 'Group Managed Service Accounts (gMSA)'
                ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
                ServiceAccountsPatternMatched       = 'Service Account Pattern Matched'
            }
        }
    }
}


#————————————————————————————————————————
# 4. EXPORTERS (CSV + HTML)
#————————————————————————————————————————
# This function exports the report data to a CSV file with custom headers.
# It uses the headers generated by Get-ReportHeaders to ensure the output matches the expected format.

function Export-CsvReport {
    param(
        [Parameter(Mandatory)]
        [string]   $FileName,

        [Parameter(Mandatory)]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [PSCustomObject] $Columns, # This will be the output from Get-ReportHeaders

        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    # Construct the full path
    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    # Create an array of calculated properties for custom headers
    $calculatedProperties = @()
    foreach ($name in $Columns.PSObject.Properties.Name) {
        $header = $Columns."$name" # Get the custom header text (the value from the PSCustomObject)

        # Add a new calculated property to the array
        $calculatedProperties += @{
            Name       = $header
            Expression = [scriptblock]::Create("`$_.`"$name`"")
        }
    }

    try {
        # Select the properties and export to a CSV with custom headers
        $Data | Select-Object -Property $calculatedProperties | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8 -Force

        Write-Log "Successfully exported CSV report to $fullPath." "INFO"
    }
    catch {
        Write-Log "Could not export CSV report to $fullPath. Error: $_" "ERROR"
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory)]
        [string]   $FileName,

        [Parameter(Mandatory)]
        [string]   $Title,

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

    # Construct the full path
    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    try {
        # Internal function to build an HTML table from data and columns
        function New-HtmlTable {
            param(
                [Parameter(Mandatory)]
                [string] $TableTitle,

                [Parameter(Mandatory)]
                [object[]] $TableData,

                [Parameter(Mandatory)]
                [PSCustomObject] $TableColumns
            )
            # Rubrik SVG Logo
            $svgContent = @"
<svg xmlns="http://www.w3.org/2000/svg" height="72" width="72" viewBox="-8 -35000 278050 403334" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" image-rendering="optimizeQuality" fill-rule="evenodd" clip-rule="evenodd">
    <path fill="#ea3e23" d="M278050 305556l-29-16V28627L178807 0 448 66971l-448 87 22 200227 60865-23821V80555l117920-28193-17 239519L122 267285l178668 65976v73l99231-27462v-316z"/>
</svg>
"@

            $html = "<div class='table-header'>"
            $html += "<div class='table-header-logo'>$svgContent</div>"
            $html += "<h2>$TableTitle</h2>"
            $html += "</div>"
            $html += '<table>'

            # Add headers
            $html += '<thead><tr>'
            foreach ($header in $TableColumns.PSObject.Properties.Value) {
                $html += "<th>$header</th>"
            }
            $html += '</tr></thead>'
            $html += '<tbody>'

            # Add data rows
            foreach ($row in $TableData) {
                # Check if this is the total row based on the keys used in your script
                $isTotalRow = ($row.OU -eq 'TOTAL' -or $row.Domain -eq 'TOTAL')
                
                $rowClass = ""
                if ($isTotalRow) {
                    $rowClass = ' class="total"'
                }
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

        # The Rubrik logo as a Base64 data URI
        $base64DataUri = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjM4IiB2aWV3Qm94PSIwIDAgMTIwIDM4IiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTk1LjczMzMgMTIuNjkyMkM5NC4zMzE1IDEyLjY5MjIgOTMuNjk5NCAxMy4wOTcxIDkyLjQwMTggMTQuNzE3VjE0LjAxNzZDOTIuNDAxOCAxMy4xNzA2IDkyLjI5NjQgMTMuMDYwNiA5MS40ODk3IDEzLjA2MDZIOTAuODI0MkM5MC4wMTc2IDEzLjA2MDYgODkuOTEyMSAxMy4xNzA2IDg5LjkxMjEgMTQuMDE3NlYyNy4zNzc3Qzg5LjkxMjEgMjguMjI0NyA5MC4wMTc2IDI4LjMzNDcgOTAuODI0MiAyOC4zMzQ3SDkxLjQ4OTdDOTIuMjk2NCAyOC4zMzQ3IDkyLjQwMTggMjguMjI0NyA5Mi40MDE4IDI3LjM3NzdWMjAuMjc0MkM5Mi40MDE4IDE4LjQzMzggOTIuNTc3NiAxNy4zMzAzIDkyLjkwNTIgMTYuNTk0M0M5My40OTU4IDE1LjU3OCA5NC42NTU4IDE1LjA2ODcgOTUuNzI4NSAxNS4yMjU5Qzk1Ljk3ODggMTUuMjYxOSA5Ni4yIDE1LjM1MDQgOTYuNDM4MiAxNS40MzQ1Qzk2LjUyNjcgMTUuNDY1MyA5Ni42Mjg1IDE1LjQ4ODYgOTYuNzE2NCAxNS40NDg1Qzk2LjgwNjEgMTUuNDA3MiA5Ni44NzY0IDE1LjMzMjggOTYuOTM1MiAxNS4yNTI3Qzk3LjA3NzYgMTUuMDYxMiA5Ny4xNjk3IDE0LjgzMDEgOTcuMjc4MiAxNC42MTY2Qzk3LjM0NzMgMTQuNDc5MyA5Ny40MTY0IDE0LjM0MiA5Ny40ODY3IDE0LjIwMTFDOTcuNjI4NSAxMy45MDY2IDk3LjczMzMgMTMuNjg2MSA5Ny43MzMzIDEzLjU3NkM5Ny43NjczIDEzLjA5NzEgOTYuODI2MiAxMi42OTIyIDk1LjczMzMgMTIuNjkyMloiIGZpbGw9IiMwNzBGNTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0M1MS40MTcyIDEyLjY5MjJDNTAuMDE1MiAxMi42OTIyIDQ5LjM4MzEgMTMuMDk3MSA0OC4wODU4IDE0LjcxN1YxNC4wMTc2QzQ4LjA4NTggMTMuMTcwNiA0Ny45ODA2IDEzLjA2MDYgNDcuMTczNiAxMy4wNjA2SDQ2LjUwNzVDNDUuNzAwNiAxMy4wNjA2IDQ1LjU5NTcgMTMuMTcwNiA0NS41OTU3IDE0LjAxNzZWMjcuMzc3N0M0NS41OTU3IDI4LjIyNDcgNDUuNzAwNiAyOC4zMzQ3IDQ2LjUwNzUgMjguMzM0N0g0Ny4xNzM2QzQ3Ljk4MDYgMjguMzM0NyA0OC4wODU4IDI4LjIyNDcgNDguMDg1OCAyNy4zNzc3VjIwLjI3NDJDNzguMDg1OCAxOC40MzM4IDQ4LjI2MDcgMTcuMzMwMyA0OC42NDY2IDE2LjU5NDNDNDkuMTc4OCAxNS41NzggNTAuMzM5MyAxNS4wNjg3IDUxLjQxMTggMTUuMjI1OUM1MS42NjE4IDE1LjI2MTkgNTEuODgzNiAxNS4zNTA0IDUyLjEyMTUgMTUuNDM0NUM1Mi4yMDk1IDE1LjQ2NTMgNTIuMzExNSAxNS40ODg2IDUyLjM5OTUgMTUuNDQ4NUM1Mi40ODg5IDE1LjQwNzIgNTIuNTU5OCAxNS4zMzI4IDUyLjYxODUgMTUuMjUyN0M1Mi43NjEgMTUuMDYxMiA1Mi44NTMzIDE0LjgzMDEgNTIuOTYxMiAxNC42MTY2QzUzLjAzMDMgMTQuNDc5MyA1My4wOTk5IDE0LjM0MiA1My4xNzA0IDE0LjIwMTFDNTMuMzExMyAxMy45MDY2IDUzLjQxNjIgMTMuNjg2MSA1My40MTYyIDEzLjU3NkM1My40NTE0IDEzLjA5NzEgNTIuNTA0NCAxMi42OTIyIDUxLjQxNzIgMTIuNjkyMloiIGZpbGw9IiMwNzBGNTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI01NOC42MzAyIDIxLjk2NjlDNTguNjMwMiAyMy40MDE5IDU4Ljc3MDcgMjQuMTc1NyA1OS4wODU3IDI0LjgzODJjNTkuNTc2NCAyNS43OTU1IDYwLjY2MzggMjYuMzg0MSA2MS45MjYzIDI2LjM4NDFDNjMuMTUzNSAyNi4zODQxIDY0LjI0MDggMjUuNzk1NSA2NC43MzIzIDI0LjgzODJjNjUuMDQ3NSAyNC4xNzU3IDY1LjE4ODEgMjMuNDAxOSA2NS4xODgxIDIxLjk2NjlWMTQuMDE3M0M2NS4xODgxIDEzLjE3MDQgNjUuMjkzNSAxMy4wNjA0IDY2LjEwMDIgMTMuMDYwNEg2Ni43NjYzQzY3LjU3MjkgMTMuMDYwNCA2Ny42Nzc4IDEzLjE3MDQgNjcuNjc3OCAxNC4wMTczVjIyLjI2MTRDNjcuNjc3OCAyNC41MDcyIDY3LjMyNzUgMjUuNzIxNiA2Ni4zNDU3IDI2Ljg2MjFjNjUuMjkzNSAyOC4xMTM5IDYzLjcxNDggMjguNzc1NSA2MS45MjYzIDI4Ljc3NTVDNjAuMTAyNCAyOC43NzU1IDU4LjUyNTQgMjguMTEzOSA1Ny40NzMgMjYuODYyMUM1Ni40OTA3IDI1Ljc0MzEgNTYuMTQwMSAyNC41MDcyIDU2LjE0MDEgMjIuMjYxNFYxNC4wMTczQzU2LjE0MDEgMTMuMTcwNCA1Ni4yNDUgMTMuMDYwNCA1Ny4wNTIgMTMuMDYwNEg1Ny43MThDNTguNTI1NCAxMy4wNjA0IDU4LjYzMDIgMTMuMTcwNCA1OC42MzAyIDE0LjAxNzNWMjEuOTY2OVoiIGZpbGw9IiMwNzBGNTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI03NC4wNzYgMjAuNjc5MUM3NC4wNzYgMjQuMDY1OCA3Ni4wNzYgMjYuMzg0NyA3OC45NTE4IDI2LjM4NDdDODEuNzIyMSAyNi4zODQ3IDgzLjcyMDkgMjMuOTU0OSA4My43MjA5IDIwLjYwNTZDODMuNzIwOSAxNy41MTQyIDgxLjY1MTggMTUuMTIxNCA3OC45MTY2IDE1LjEyMTRDNzYuMDc2IDE1LjEyMTQgNzQuMDc2IDE3LjQwMzcgNzQuMDc2IDIwLjY3OTFaTTc0LjI1MjQgMTUuMjMyNEM3NS42ODk0IDEzLjUwMjQgNzcuMjMzIDEyLjcyOTEgNzkuMzM3MiAxMi43MjkxQzg2LjMzNDggMTIuNzI5MSA4Ni4yODA5IDE2LjA3ODQgODYuMjgwOSAyMC42NzkxQzg2LjI4MDkgMjUuMzUzNyA4My4yOTk3IDI4Ljc3NjEgNzkuMjY2OSAyOC43NzYxQzc3LjIzMyAyOC43NzYxIDc1LjYxOTcgMjcuOTY2MiA3NC4yNTI0IDI2LjIzNzZWMjcuMzc3NjdDNzQuMjUyNCAyOC4yMjQ2IDc0LjE0NjkgMjguMzM0NiA3My4zMzk3IDI4LjMzNDZINzIuNjc0MkM3MS44NjY5IDI4LjMzNDYgNzEuNzYxNSAyOC4yMjQ2IDcxLjc2MTUgMjcuMzc3NjdWMi40NTk3OUM3MS43NjE1IDEuNjEzNzcgNzEuODY2OSAxLjUwMzcyIDcyLjY3NDIgMS41MDM3Mkg3My4zMzk3Qzc0LjE0NjkgMS41MDM3MiA3NC4yNTI0IDEuNjEzNzcgNzQuMjUyNCAyLjQ1OTc5VjE1LjIzMjRaIiBmaWxsPSIjMDcwRjUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAzLjQ3MyAyNy4zNzc3QzEwMy40NzMgMjguMjI0NyAxMDMuMzY3IDI4LjMzNDcgMTAyLjU2MSAyOC4zMzQ3SDEwMS44OTRDMTAxLjA4NyAyOC4zMzQ3IDEwMC45ODMgMjguMjI0NyAxMDAuOTgzIDI3LjM3NzdWMTQuMDE3MUMxMDAuOTgzIDEzLjE3MTEgMTAxLjA4NyAxMy4wNjAxIDEwMS44OTQgMTMuMDYwMUgxMDIuNTYxQzEwMy4zNjcgMTMuMDYwMSAxMDMuNDczIDEzLjE3MTEgMTAzLjQ3MyAxNC4wMTcxVjI3LjM3NzdaTTEwNC4wMzQgNy4yODQwNkMxMDQuMDM0IDguMzE2MSAxMDMuMjI3IDkuMTYzMDUgMTAyLjI0NSA5LjE2MzA1QzEwMS4yNjMgOS4xNjMwNSAxMDAuNDU3IDguMzE2MSAxMDAuNDU3IDcuMjQ3MDdDMTAwLjQ1NyA2LjI1MjQ4IDEwMS4yNjMgNS40MDUwOSAxMDIuMjQ1IDUuNDA1MDlDMTAzLjIyNyA1LjQwNTA5IDEwNC4wMzQgNi4yNTI0OCAxMDQuMDM0IDcuMjg0MDZaIiBmaWxsPSIjMDcwRjUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTE1LjQ0OCAxMy41MDI1QzExNS44NjggMTMuMDYwNSAxMTUuODY4IDEzLjA2MDUgMTE2LjQ2NSAxMy4wNjA1SDExNy41NTJDMTE4LjE4MyAxMy4wNjA1IDExOC40MjkgMTMuMjQ0OSAxMTguNDI5IDEzLjY0OTVDMTE4LjQyOSAxMy43OTY1IDExOC4yODggMTQuMDE3NSAxMTguMDA4IDE0LjMxMkwxMTIuOTkyIDE5LjU3NTZMMTE5LjM0IDI3LjA4MzZDMTE5LjU4NiAyNy40MTQ3IDExOS43MjcgMjcuNjM2IDExOS43MjcgMjcuNzgzMUMxMTkuNzI3IDI4LjE1MTEgMTE5LjQ0NiAyOC4zMzUxIDExOC44MTQgMjguMzM1MUgxMTcuNzI3QzExNy4wOTYgMjguMzM1MSAxMTcuMDk2IDI4LjMzNTEgMTE2LjcxIDI3Ljg1NjZMMTExLjIzOSAyMS4zNzg1TDExMC42MDcgMjIuMDQxVjI3LjM3ODFDMTEwLjYwNyAyOC4yMjQ2IDExMC41MDIgMjguMzM1MSAxMDkuNjk2IDI4LjMzNTFIMTA5LjAzQzEwOC4yMjMgMjguMzM1MSAxMDguMTE4IDI4LjIyNDYgMTA4LjExOCAyNy4zNzgxVjIuNDYwMjJDMTA4LjExOCAxLjYxMzc2IDEwOC4yMjMgMS41MDM3MiAxMDkuMDMgMS41MDM3MkgxMDkuNjk2QzExMC41MDIgMS41MDM3MiAxMTAuNjA3IDEuNjEzNzYgMTEwLjYwNyAyLjQ2MDIyVjE4LjY5MjFMMTE1LjQ0OCAxMy41MDI1WiIgZmlsbD0iIzA3MEY1MiIvPgo8bWFzayBpZD0ibWFzazBfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIxMSIgeT0iMSIgd2lkdGg9IjEyIiBoZWlnaHQ9IjEyIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0xNy4xMTM5IDEuMDk1NzZDMTcuMDA5OSAxLjEzMzYyIDE2LjkxMjEgMS4xOTU2OCAxNi44Mjk1IDEuMjgxOTZMMTIuMDczNyA2LjI2Njk0QzExLjc4MTQgNi41NzI0MyAxMS43ODE0IDcuMDczMzUgMTIuMDczNyA3LjM3ODgxTDE2LjgyOTUgMTIuMzY0M0MxNy4xMjIzIDEyLjY3MDEgMTcuNTk5MiAxMi42NzAxIDE3Ljg5MTEgMTIuMzY0M0wyMi42NDQgNy4zNzg4MUMyMi45MzU0IDcuMDczMzUgMjIuOTM1NCA2LjU3MjQzIDIyLjY0NCA2LjI2Njk0TDE3Ljg5MTEgMS4yODE5NkMxNy44MDg5IDEuMTk1NjggMTcuNzExMiAxLjEzMzYyIDE3LjYwNzUgMS4wOTU3NkgxNy4xMTM5WiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPjxnIG1hc2s9InVybCgjbWFzazBfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjcuMTEzOSAxLjA5NTc2QzE3LjAwOTkgMS4xMzM2MiAxNi45MTIxIDEuMTk1NjggMTYuODI5NSAxLjI4MTk2TDEyLjA3MzcgNi4yNjY5NEMxMS43ODE0IDYuNTcyNDMgMTEuNzgxNCA3LjA3MzM1IDEyLjA3MzcgNy4zNzg4MUwxNi44Mjk1IDEyLjM2NDNDMTcuMTIyMyAxMi42NzAxIDE3LjU5OTIgMTIuNjcwMSAxNy44OTExIDEyLjM2NDNMMjIuNjQ0IDcuMzc4ODFDMjIuOTM1NCA3LjA3MzM1IDIyLjkzNTQgNi41NzI0MyAyMi42NDQgNi4yNjY5NkwxNy44OTExIDEuMjgxOTZDMTcuODA4OSAxLjE5NTY4IDE3LjcxMTIgMS4xMzM2MiAxNy42MDc1IDEuMDk1NzZIMTcuMTEzOVoiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPjxtYXNrIGlkPSJtYXNrMV8xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjIzIiB5PSIxMyIgd2lkdGg9IjEyIiBoZWlnaHQ9IjEzIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0yOC42ODUyIDEzLjcxNDRMMjMuOTI4NiAxOC42OTk0QzIzLjYzNzEgMTkuMDA1MyAyMy42MzcxIDE5LjUwNTMgMjMuOTI4NiAxOS44MTEzTDI4LjY4NTIgMjQuNzk2M0MyOC45NzcxIDI1LjEwMTggMjkuNDU0OSAyNS4xMDE4IDI5Ljc0NTkgMjQuNzk2M0wzNC40OTg4IDE5LjgxMTNDMzQuNzkwNyAxOS41MDUzIDM0Ljc5MDcgMTkuMDA0NCAzNC40OTg4IDE4LjY5ODZMMjkuNzQ1OSAxMy43MTQ0QzI5LjYwMDQgMTMuNTYxMiAyOS40MDgzIDEzLjQ4NDYgMjkuMjE1OCAxMy40ODQ2QzI5LjAyMzMgMTMuNDg0NiAyOC44MzE2IDEzLjU2MTIgMjguNjg1MiAxMy43MTQ0WiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPjxnIG1hc2s9InVybCgjbWFzazFfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjguNjg1MiAxMy43MTQ0TDIzLjkyODYgMTguNjk5NEMyMy42MzcxIDE5LjAwNTMgMjMuNjM3MSAxOS41MDUzIDI1LjkyODYgMTkuODExM0wyOC42ODUyIDI0Ljc5NjNDMjguOTc3MSAyNS4xMDE4IDI5LjQ1NDkgMjUuMTAxOCAyOS43NDU5IDI0Ljc5NjNMMzQuNDk4OCAxOS44MTEzQzM0LjczNzYyIDE5LjUwNTMgMzQuNzkwNyAxOS4wMDQ0IDM0LjQ5ODggMTguNjk4NkwyOS43NDU5IDEzLjcxNDRDMjkuNjAwNCAxMy41NjEyIDI5LjQwODMgMTMuNDg0NiAyOS4yMTU4IDEzLjQ4NDZDMjkuMDIzMyAxMy40ODQ2IDI4LjgzMTYgMTMuNTYxMiAyOC42ODUyIDEzLjcxNDRaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2syXzEwOTE1XzE3NCIgc3R5bGU9Im1zY2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iOCIgeT0iMzIiIHdpZHRoPSI0IiBoZWlnaHQ9IjUiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTEwLjg4MDUgMzIuMzcwM0w4Ljc2NzAzIDM0LjU4NzFjOC40NzUwOSAzNC44OTI1IDguNTMzODIgMzUuMzEwNyA4Ljg5NzQ1IDM1LjUxNTNMMTAuNzE3MyAzNi40MTg2QzExLjA5OSAzNi41ODQ2IDExLjQxMDYgMzYuMzY2MyAxMS40MTA2IDM1LjkzNFYzMi42MDFDMTEuNDEwNiAzMi4zMzYgMTEuMzIyIDMyLjE5NDcgMTEuMTg1NCAzMi4xOTQ3QzExLjA5OSAzMi4xOTQ3IDEwLjk5NDEgMzIuMjUxOSAxMC44ODA1IDMyLjM3MDNaIiBmaWxsPSJ3aGl0ZSIvPjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAuODgwNSAzMi4zNzAzTDguNzY3MDMgMzQuNTg3MUM4LjQ3NTA5IDM0Ljg5MjUgOC41MzM4MiAzNS4zMTA3IDguODk3NDUgMzUuNTE1NEwxMC43MTczIDM2LjQxODZDMTEuMDk5IDM2LjU4NDYgMTEuNDEwNiAzNi4zNjYzIDExLjQxMDYgMzUuOTM0VjMyLjYwMUMxMS40MTA2IDMyLjMzNiAxMS4zMjEzIDMyLjE5NDcgMTEuMTg1NCAzMi4xOTQ3QzExLjA5OSAzMi4xOTQ3IDEwLjk5NDEgMzIuMjUxOSAxMC44ODA1IDMyLjM3MDNaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPC9tYXNrPjxnIG1hc2s9InVybCgjbWFzazJfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAuODgwNSAzMi4zNzAzTDguNzY3MDMgMzQuNTg3MUM4LjQ3NTA5IDM0Ljg5MjUgOC41MzM4MiAzNS4zMTA3IDguODk3NDUgMzUuNTE1NEwxMC43MTczIDM2LjQxODZDMTEuMDk5IDM2LjU4NDYgMTEuNDEwNiAzNi4zNjYzIDExLjQxMDYgMzUuOTM0VjMyLjYwMUMxMS40MTA2IDMyLjMzNiAxMS4zMjEzIDMyLjE5NDcgMTEuMTg1NCAzMi4xOTQ3QzExLjA5OSAzMi4xOTQ3IDEwLjk5NDEgMzIuMjUxOSAxMC44ODA1IDMyLjM3MDNaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQuIjoibWFzazNfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIyMyIgeT0iMzIiIHdpZHRoPSI0IiBoZWlnaHQ9IjUiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTIzLjMwNTcgMzIuNjAxVjM1LjkzNEMyMy4zMDU3IDM2LjM2NjMgMjMuNjE3MyAzNi41ODQ2IDIzLjk5ODkgMzYuNDE4NkwyNS44MTg4IDM1LjUxNTRDMjYuMTgyNSAzNS4zMTA3IDI2LjI0MTYgMzQuODkyNSAyNS45NTAxIDM0LjU4NzFMMjMuODM2MiAzMi4zNzAzQzIzLjcyMjYgMzIuMjUxOSAyMy42MTczIDMyLjE5NDcgMjMuNTMxMyAzMi4xOTQ3QzIzLjM5NSAzMi4xOTQ3IDIzLjMwNTcgMzIuMzM2IDIzLjMwNTcgMzIuNjAxWiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPjxnIG1hc2s9InVybCgjbWFzazNfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjMuMzA1NyAzMi42MDFWMzUuOTM0QzIzLjMwNTcgMzYuMzY2MyAyMy42MTczIDM2LjU4NDYgMjMuOTk4OSAzNi40MTg2TDI1LjgxODggMzUuNTE1NEMyNi4xODI1IDM1LjMxMDcgMjYuMjQxNiAzNC44OTI1IDI1Ljk1MDEgMzQuNTg3MUEyMy44MzYyIDMyLjM3MDNDMjMuNzIyNiAzMi4yNTE5IDIzLjYxNzMgMzIuMTk0NyAyMy41MzEzIDMyLjE5NDdDMjMuMzk1IDMyLjE5NDcgMjMuMzA1NyAzMi4zMzYgMjMuMzA1NyAzMi42MDFaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2s0XzEwOTE1XzE3NCIgc3R5bGU9Im1hc2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iMjMiIHk9IjI1IiB3aWR0aD0iNyIgaGVpZ2h0PSI3Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0yNC4wNTYgMjUuNDkyN0MyMy42NDM3IDI1LjQ5MjcgMjMuMzA1NyAyNS44NDU3IDIzLjMwNTcgMjYuMjc4VjMwLjc3NDRDMjMuMzA1NyAzMS4yMDU3IDIzLjY0MzcgMzEuNTYwNSAyNC4wNTYgMzEuNTYwNUgyOC4zNDEyQzI4Ljc1MzUgMzEuNTYwNSAyOS4wOTE1IDMxLjIwNTcgMjkuMDkxNSAzMC43NzQ0VjI2LjI3OEMyOS4wOTE1IDI1Ljg0NTcgMjguNzUzNSAyNS40OTI3IDI4LjM0MTIgMjUuNDkyN0gyNC4wNTZaIiBmaWxsPSJ3aGl0ZSIvPjxwYXRoIGZpbGwtcnVsZT0iZXZlZ25vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTI0LjA1NiAyNS40OTI3QzIzLjY0MzcgMjUuNDkyNyAyMy4zMDU3IDI1Ljg0NTcgMjMuMzA1NyAyNi4yNzhWMzAuNzc0NEMyMy4zMDU3IDMxLjIwNTcgMjMuNjQzNyAzMS41NjA1IDI0LjA1NiAzMS41NjA1SDI4LjM0MTJDMjguNzUzNSAzMS41NjA1IDI5LjA5MTUgMzEuMjA1NyAyOS4wOTE1IDMwLjc3NDRWMjYuMjc4QzI5LjA5MTUgMjUuODQ1NyAyOC43NTM1IDI1LjQ5MjcgMjguMzQxMiAyNS40OTI3SDI0LjA1NloiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPjxtYXNrIGlkPSJtYXNrNV8xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjI5IiB5PSIxMCIgd2lkdGg9IjUiIGhlaWdodD0iNCI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMzEuOTc4MSAxMC4yNDU3TDI5Ljg2NDYgMTIuNDY0NEMyOS41NzMxIDEyLjc3MTEgMjkuNjcxNiAxMy4wMjE4IDMwLjA4NDQgMTMuMDIxOEg1My4yNjI3QzMzLjY3NDYgMTMuMDIxOCAzMy44ODI3IDEyLjY5NDQgMzMuNzI0OSAxMi4yOTM0TDMyLjg2MyAxMC4zODI1QzMyLjc1MTUgMTAuMTY0MSAzMi41NzMyIDEwLjA1MDkgMzIuMzg3IDEwLjA1MDlDMzIuMjQ3MyAxMC4wNTA5IDMyLjEwMjYgMTAuMTE0OCAzMS45NzgxIDEwLjI0NTdaIiBmaWxsPSJ3aGl0ZSIvPjxnIG1hc2s9InVybCgjbWFzazVfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMzEuOTc4MSAxMC4yNDU3TDI5Ljg2NDYgMTIuNDY0NEMyOS41NzMxIDEyLjc3MTEgMjkuNjcxNiAxMy4wMjE4IDMwLjA4NDQgMTMuMDIxOEg1My4yNjI3QzMzLjY3NDYgMTMuMDIxOCAzMy44ODI3IDEyLjY5NDQgMzMuNzI0OSAxMi4yOTM0TDMyLjg2MyAxMC4zODI1QzMyLjczMTUgMTAuMTY0MSAzMi41NzMyIDEwLjA1MDkgMzIuMzg3IDEwLjA1MDlDMzIuMjQ3MyAxMC4wNTA5IDMyLjEwMjYgMTAuMTE0OCAzMS45NzgxIDEwLjI0NTdaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPC9tYXNrPjxnIG1hc2s9InVybCgjbWFzazVfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMzEuOTc4MSAxMC4yNDU3TDI5Ljg2NDYgMTIuNDY0NEMyOS41NzMxIDEyLjc3MTEgMjkuNjcxNiAxMy4wMjE4IDMwLjA4NDQgMTMuMDIxOEg1My4yNjI3QzMzLjY3NDYgMTMuMDIxOCAzMy44ODI3IDEyLjY5NDQgMzMuNzI0OSAxMi4yOTM0TDMyLjg2MyAxMC4zODI1QzMyLjczMTUgMTAuMTY0MSAzMi41NzMyIDEwLjA1MDkgMzIuMzg3IDEwLjA1MDlDMzIuMjQ3MyAxMC4wNTA5IDMyLjEwMjYgMTAuMTE0OCAzMS45NzgxIDEwLjI0NTdaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQuIjoibWFzazZfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIyMyIgeT0iMiIgd2lkdGg9IjQiIGhlaWdodD0iNSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjMuMzA1NyAyLjU3NjE3VjUuOTA5MThDMjMuMzA1NyA2LjM0MTg4IDIzLjU0NDMgNi40NDU3NiAyMy44MzYyIDYuMTM5ODNMMjUuOTUwMSAzLjkyMjY3QzI2LjI0MTYgMy42MTc2MyAyNi4xODI0IDMuMTk5MDIgMjUuODE5MiAyLjk5NDc3TDIzLjk5ODkgMi4wOTE1M0MyMy45MTE3IDIuMDUzMjQgMjMuODI4NyAyLjAzNjA3IDIzLjc1MTkgMi4wMzYwN0MyMy40OTE1IDIuMDM2MDcgMjMuMzA1NyAyLjI0MjUyIDIzLjMwNTcgMi41NzYxN1oiIGZpbGw9IndoaXRlIi8+CjwvZ25pIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjIzIiB5PSIyIiB3aWR0aD0iNCIgaGVpZ2h0PSI1Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0yMy4zMDU3IDIuNTc2MTdWNS45MDkxOEMyMy4zMDU3IDYuMzQxODggMjMuNTQ0MyA2LjQ0NTc2IDIzLjgzNjIgNi4xMzk4M0wyNS45NTAxIDMuOTIyNjdDMjYuMjQxNiAzLjYxNzYzIDI2LjE4MjQgMy4xOTkwMiAyNS44MTkyIDIuOTk0NzdMMjMuOTk4OSAyLjA5MTUzQzIzLjcxMTcgMi4wNTMyNCAyMy44Mjg3IDIuMDM2MDcgMjMuNzUxOSAyLjAzNjA3QzIzLjQ5MTUgMi4wMzYwNyAyMy4zMDU3IDIuMjQyNTIgMjMuMzA1NyAyLjU3NjE3WiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPjxnIG1hc2s9InVybCgjbWFzazZfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjMuMzA1NyAyLjU3NjE3VjUuOTA5MThDMjMuMzA1NyA2LjM0MTg4IDIzLjU0NDMgNi40NDU3NiAyMy44MzYyIDYuMTM5ODNMMjUuOTUwMSAzLjkyMjY3QzI2LjI0MTYgMy42MTc2MyAyNi4xODI0IDMuMTk5MDIgMjUuODE5MiAyLjk5NDc3TDIzLjgwODkgMi4wOTE1M0MyMy43MTE3IDIuMDUzMjQgMjMuODI4NyAyLjAzNjA3IDIzLjczMTkgMi4wMzYwN0MyMy40OTE1IDIuMDM2MDcgMjMuMzA1NyAyLjI0MjUyIDIzLjMwNTcgMi41NzYxN1oiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPjxtYXNrIGlkPSJtYXNrN18xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjAiIHk9IjEwIiB3aWR0aD0iNiIgaGVpZ2h0PSI0Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0xLjg1MzMgMTAuMzgyM0wwLjk5MjIzNiAxMi4yOTQ4QzAuODM0MTE1IDEyLjY5NDQgMS4wNDE3MyAxMy4wMjE4IDEuNDU0MDIgMTMuMDIxOEg0LjYzMzIxQzUuMDQ1OTIgMTMuMDIxOCA1LjE0NDkgMTIuNzcxMSA0Ljg1MjU3IDEyLjQ2NDRMMi43Mzg3IDEwLjI0NTdDMi42MTQxMyAxMC4xMTQ4IDIuNDY5ODUgMTAuMDUwOSAyLjMyOTc2IDEwLjA1MDlDMi4xNDM1NCAxMC4wNTA5IDEuOTY1MjkgMTAuMTY0MSAxLjg1MzMgMTAuMzgyM1oiIGZpbGw9IndoaXRlIi8+CjwvZ25pIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjAiIHk9IjEwIiB3aWR0aD0iNiIgaGVpZ2h0PSI0Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9iI0xLjg1MzMgMTAuMzgyM0wwLjk5MjIzNiAxMi4yOTQ4QzAuODM0MTE1IDEyLjY5NDQgMS4wNDE3MyAxMy4wMjE4IDEuNDU0MDIgMTMuMDIxOEg0LjYzMzIxQzUuMDQ1OTIgMTMuMDIxOCA1LjE0NDkgMTIuNzcxMSA0Ljg1MjU3IDEyLjQ2NDRMMi43Mzg3IDEwLjI0NTdDMi42MTQxMyAxMC4xMTQ4IDIuNDY5ODUgMTAuMDUwOSAyLjMyOTc2IDEwLjA1MDlDMi4xNDM1NCAxMC4wNTA5IDEuOTY1MjkgMTAuMTY0MSAxLjg1MzMgMTAuMzgyM1oiIGZpbGw9IndoaXRlIi8+CjwvZ25pPjxnIG1hc2s9InVybCgjbWFzazdfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTE4NTMzIDEwLjM4MjNMMDAuOTkyMjM2IDEyLjI5NDhDMDAuODM0MTE1IDEyLjY5NDQgMS4wNDE3MyAxMy4wMjE4IDEuNDU0MDIgMTMuMDIxOEg0LjYzMzIxQzUuMDQ1OTIgMTMuMDIxOCA1LjE0NDkgMTIuNzcxMSA0Ljg1MjU3IDEyLjQ2NDRMMi43Mzg3IDEwLjI0NTdDMi42MTQxMyAxMC4xMTQ4IDIuNDY5ODUgMTAuMDUwOSAyLjMyOTc2IDEwLjA1MDlDMi4xNDM1NCAxMC4wNTA5IDEuOTY1MjkgMTAuMTY0MSAxLjg1MzMgMTAuMzgyM1oiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPg=="

        $logoHtml = "<img src='$base64DataUri' class='header-svg' alt='Rubrik Logo' />"

        # CSS to match the Rubrik report style
        $css = @"
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: #f0f2f5;
        color: #333;
        margin: 0;
        padding: 0;
    }
    .report-container {
        max-width: 1200px;
        margin: 20px auto;
        padding: 20px;
        background-color: #fff;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .header {
        background-color: #0d47a1;
        color: #fff;
        padding: 20px;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: flex-start;
    }
    .table-header {
    display: flex;
    align-items: center; 
    gap: 15px; 
    border-bottom: 2px solid #e0e6ed;
    padding-bottom: 10px;
    margin-bottom: 20px;
    }
    .header h1 {
        margin: 0;
        font-size: 24px;
        /* Space between the logo and the title */
        margin-left: 20px;
    }
    .header-logo {
        height: 40px; /* Adjust as needed */
    }
    .header-svg {
        height: 45px;
        width: auto;
    }
    h2 {
        color: #0d47a1;
        font-size: 20px;
        border-bottom: 2px solid #e0e0e0;
        padding-bottom: 10px;
        margin-top: 30px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 20px;
    }
    th, td {
        padding: 12px;
        text-align: center;
        border: 1px solid #ddd;
    }
    thead th {
        background-color: #2c3e50;
        color: white;
        font-weight: bold;
        text-transform: uppercase;
        font-size: 13px;
        border: 1px solid #2c3e50;
    }
    tbody tr:nth-child(odd) {
        background-color: #f9f9f9;
    }
    tbody tr:nth-child(even) {
        background-color: #fff;
    }
    tbody tr:hover {
        background-color: #e8f4fd;
    }
    tr.total {
        font-weight: bold;
        background-color: #2c3e50 !important;
        color: #fff;
    }
    .footer {
        text-align: center;
        padding: 15px;
        font-size: 12px;
        color: #888;
        border-top: 1px solid #ddd;
        margin-top: 20px;
    }
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

        # Add the first table
        $htmlBody += New-HtmlTable -TableTitle $Title -TableData $Data -TableColumns $Columns

        # If a second report is provided, add it
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
        Write-Log "Successfully exported HTML report to $fullPath" "INFO"
    }
    catch {
        Write-Log "Could not export to HTML file $fullPath. Error: $_" "ERROR"
    }
}

# =====================
# Main Logic
# =====================

$logonThreshold = (Get-Date).AddDays(-180)
$summary = @()

$domainsToAudit = if ($SpecificDomains) {
    $SpecificDomains
} else {
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | ForEach-Object { $_.Name }
}

foreach ($domain in $domainsToAudit) {
    Write-Log "Auditing domain: $domain" -ForegroundColor Cyan

    try {
        # Preload reference data
        $MSASet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' } |
                  Select-Object -ExpandProperty SamAccountName
        $GMSASet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' } |
                   Select-Object -ExpandProperty SamAccountName
        $NoExpireSet = Get-ADUser -Server $domain -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
                       Select-Object -ExpandProperty SamAccountName

        # 🔍 Get pattern-matched service accounts
        $PatternMatches = Get-UsersAsServiceAccount -NamePatterns $UserServiceAccountNamesLike -Domain $domain
        $PatternSet = $PatternMatches.SamAccountName | Sort-Object -Unique

        # 🧾 Get users
        $userAccounts = Get-ADUser -Server $domain -Filter { Enabled -eq $true } `
            -Properties SamAccountName, DistinguishedName, LastLogonTimestamp

        $msaObjects  = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' })
        $gmsaObjects = @(Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' })

        $serviceAccounts = $msaObjects + $gmsaObjects | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName     = $_.SamAccountName
                DistinguishedName  = $_.DistinguishedName
                LastLogonTimestamp = $_.LastLogonTimestamp
            }
        }

        $users = $userAccounts + $serviceAccounts

        foreach ($user in $users) {
            $sam = $user.SamAccountName
            $ou  = Get-OUFromDN $user.DistinguishedName

            $entry = $summary | Where-Object { $_.Domain -eq $domain -and $_.OU -eq $ou }
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
                $summary += $entry
            }

            $entry.TotalUsers++
            if ($user.LastLogonTimestamp) {
                if ($user.LastLogonTimestamp -ge $logonThreshold.ToFileTime()) {
                    $entry.ActiveUsers++
                } else {
                    $entry.InactiveUsers++
                }
            } else {
                $entry.NeverLoggedInUsers++
            }

            if (Test-ManagedServiceAccount      $sam $MSASet)      { $entry.ServiceAccountsManaged++ }
            elseif (Test-GroupManagedServiceAccount $sam $GMSASet)     { $entry.ServiceAccountsGroupManaged++ }
            if (Test-NonExpiringUser            $sam $NoExpireSet) { $entry.ServiceAccountsPasswordNeverExpires++ }
            if (Test-PatternMatchedUser         $sam $PatternSet)  { $entry.ServiceAccountsPatternMatched++ }
        }
    } catch {
        Write-Warning "Failed processing domain $domain : $_"
    }
}
# =====================
# Report Output
# =====================

# Get the appropriate headers based on the selected mode
$reportColumns = Get-ReportHeaders -Mode $Mode

# Create unique filename with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$fileName = "ADAudit_${Mode}_$timestamp.csv"
# $fullExportPath = Join-Path -Path $outputPath -ChildPath $fileName # This variable is no longer needed directly here

switch ($Mode) {
    "UserPerOU" {
        Write-Log "Generating OU Summary Report..." -ForegroundColor Green
        $summary | Sort-Object Domain, OU | Format-Table -AutoSize # For console output
        Export-CsvReport -FileName $fileName -Data $summary -Columns $reportColumns -OutputPath $outputPath
    }
    "Summary" {
        $summaryGrouped = $summary |
            Group-Object Domain |
            ForEach-Object {
                [PSCustomObject]@{
                    Domain                              = $_.Name
                    TotalUsers                          = ($_.Group | Measure-Object TotalUsers -Sum).Sum
                    ActiveUsers                         = ($_.Group | Measure-Object ActiveUsers -Sum).Sum
                    InactiveUsers                       = ($_.Group | Measure-Object InactiveUsers -Sum).Sum
                    NeverLoggedInUsers                  = ($_.Group | Measure-Object NeverLoggedInUsers -Sum).Sum
                    ServiceAccountsManaged              = ($_.Group | Measure-Object ServiceAccountsManaged -Sum).Sum
                    ServiceAccountsGroupManaged         = ($_.Group | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
                    ServiceAccountsPasswordNeverExpires = ($_.Group | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
                    ServiceAccountsPatternMatched       = ($_.Group | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
                }
            }
        
        Write-Log "Generating Domain Summary Report..." -ForegroundColor Green
        $summaryGrouped | Sort-Object Domain | Format-Table -AutoSize # For console output
        Export-CsvReport -FileName $fileName -Data $summaryGrouped -Columns $reportColumns -OutputPath $outputPath
    }
}

Write-Log "AD reports generation completed. Results saved to $outputPath." -ForegroundColor Green
Write-Log "Please send all the files within the directory to your Rubrik Sales representative." -ForegroundColor Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture
