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
        - Automatically export results to a timestamped CSV and HTML file

.PARAMETER SpecificDomains
    Optional. An array of fully qualified domain names to audit (e.g., "corp.domain.local").
    If omitted, the script audits all domains in the current forest.

.PARAMETER UserServiceAccountNamesLike
    Optional. Wildcard patterns (e.g., "*svc*", "*_bot") to match account names that represent
    service accounts. Used to classify matching users under ServiceAccountsPatternMatched.

.PARAMETER Mode
    Required. Selects output format:
        - 'Full': detailed counts per Organizational Unit (OU)
        - 'Summary': consolidated view per domain with a grand total row

.EXAMPLE
    .\Get-AdHumainIdentity.ps1 -SpecificDomains "corp.domain.local" -UserServiceAccountNamesLike "*svc*","*_bot" -Mode UserPerOU

    This command:
        - Targets only corp.domain.local
        - Scans for accounts whose Name matches "*svc*" or "*_bot"
        - Classifies and counts users by OU
        - Outputs results to .\ADReports\UserAudit_Full_<timestamp>.csv and .html

.EXAMPLE
    .\Get-AdHumainIdentity.ps1

    This default call:
        - Targets all domains in the forest
        - Skips name-based pattern matching
        - Defaults to Full mode
        - Outputs results to .\ADReports\UserAudit_Full_<timestamp>.csv and .html

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
    [ValidateSet("Full", "Summary")]
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
        [System.ConsoleColor]$Color = "White"
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


# === Prerequisites Check and Initialization ===
# Ensure PowerShell version and required modules are available

function Initialize-Prerequisites {
    $requiredPSVersion = [Version]"5.1"
    $moduleName = "ActiveDirectory"

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" -Level "ERROR" -Color Red
        exit
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Required module '$moduleName' not found. Please install RSAT: Active Directory Tools." -Level "ERROR" -Color Red
            exit
        }
        Import-Module $moduleName -ErrorAction Stop
        Write-Log "Successfully loaded module '$moduleName'." -Color Green
    } catch {
        Write-Log "Failed to import '$moduleName'. Ensure it's installed and accessible. $_" -Level "ERROR" -Color Red
        exit
    }

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Prerequisites validated. Environment initialized." -Color Green
}

Initialize-Prerequisites

# =====================
# Helper Functions
# =====================

function Get-OUFromDN {
    param ([string]$dn)
    ($dn -split '(?<!\\),')[1..($dn.Count - 1)] -join ','
}

function Get-ADUserData {
    [CmdletBinding()]
    param(
        [string[]] $DomainsToAudit,
        [string[]] $ServicePattern = @()
    )

    begin {
        $allUserData = @()
        # This line is no longer needed here and has been removed
    }
    process {
        foreach ($domain in $DomainsToAudit) {
            Write-Log "Auditing domain: $domain" -Color Cyan

            try {
                # Preload reference data for the domain
                $msaSet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-ManagedServiceAccount' } | Select-Object -ExpandProperty SamAccountName
                $gmsaSet = Get-ADServiceAccount -Server $domain -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' } | Select-Object -ExpandProperty SamAccountName
                $noExpireSet = Get-ADUser -Server $domain -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } | Select-Object -ExpandProperty SamAccountName

                # Get all users
                $users = Get-ADUser -Server $domain -Filter * -Properties SamAccountName, DistinguishedName, LastLogonTimestamp, Enabled, PasswordNeverExpires

                foreach ($user in $users) {
                    $lastLogonTimestamp = if ($user.LastLogonTimestamp) {
                        [DateTime]::FromFileTime($user.LastLogonTimestamp)
                    } else {
                        $null
                    }

                    $patternMatched = $false
                    if ($ServicePattern.Count -gt 0) {
                        foreach ($p in $ServicePattern) {
                            if ($user.SamAccountName -like "*$p*") {
                                $patternMatched = $true
                                break
                            }
                        }
                    }

                    $allUserData += [PSCustomObject]@{
                        Domain = $domain
                        SamAccountName = $user.SamAccountName
                        DistinguishedName = $user.DistinguishedName
                        OU = Get-OUFromDN $user.DistinguishedName
                        LastLogonDate = $lastLogonTimestamp
                        LastLogonTimestamp = $user.LastLogonTimestamp
                        Enabled = [int]$user.Enabled
                        MSA = [int]($msaSet -contains $user.SamAccountName)
                        GMSA = [int]($gmsaSet -contains $user.SamAccountName)
                        PasswordNeverExpires = [int]($noExpireSet -contains $user.SamAccountName)
                        PatternMatched = [int]$patternMatched
                    }
                }
            } catch {
                Write-Log "Failed to process domain $($domain): $_" -Level "ERROR" -Color Red
            }
        }
    }
    end {
        return $allUserData
    }
}

function Get-SummaryPerOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$UserData,
        
        [Parameter(Mandatory)]
        [datetime]$LogonThreshold
    )

    $summaryData = $UserData |
        Group-Object Domain, OU |
        ForEach-Object {
            $domain = $_.Name.Split(',')[0]
            $ou = $_.Name.Split(',')[1]
            $grpUsers = $_.Group

            [PSCustomObject]@{
                Domain                      = $domain
                OU                          = $ou
                TotalUsers                  = $grpUsers.Count
                ActiveUsers                 = ($grpUsers | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -ge $LogonThreshold }).Count
                InactiveUsers               = ($grpUsers | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -lt $LogonThreshold }).Count
                NeverLoggedInUsers          = ($grpUsers | Where-Object { $null -eq $_.LastLogonDate }).Count
                ServiceAccountsManaged      = ($grpUsers | Where-Object { $_.MSA -eq 1 }).Count
                ServiceAccountsGroupManaged = ($grpUsers | Where-Object { $_.GMSA -eq 1 }).Count
                ServiceAccountsPasswordNeverExpires = ($grpUsers | Where-Object { $_.PasswordNeverExpires -eq 1 }).Count
                ServiceAccountsPatternMatched = ($grpUsers | Where-Object { $_.PatternMatched -eq 1 }).Count
            }
        } | Sort-Object Domain, OU

    # Add a grand total row
    $summaryData += [PSCustomObject]@{
        Domain                      = 'TOTAL'
        OU                          = ''
        TotalUsers                  = ($summaryData | Measure-Object TotalUsers -Sum).Sum
        ActiveUsers                 = ($summaryData | Measure-Object ActiveUsers -Sum).Sum
        InactiveUsers               = ($summaryData | Measure-Object InactiveUsers -Sum).Sum
        NeverLoggedInUsers          = ($summaryData | Measure-Object NeverLoggedInUsers -Sum).Sum
        ServiceAccountsManaged      = ($summaryData | Measure-Object ServiceAccountsManaged -Sum).Sum
        ServiceAccountsGroupManaged = ($summaryData | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
        ServiceAccountsPasswordNeverExpires = ($summaryData | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
        ServiceAccountsPatternMatched = ($summaryData | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
    }

    return $summaryData
}

function Get-SummaryPerDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$UserData,
        
        [Parameter(Mandatory)]
        [datetime]$LogonThreshold
    )

    $summaryData = @($UserData |
        Group-Object Domain |
        ForEach-Object {
            $domain = $_.Name
            $grp = $_.Group

            [PSCustomObject]@{
                Domain                      = $domain
                TotalUsers                  = $grp.Count
                ActiveUsers                 = ($grp | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -ge $LogonThreshold }).Count
                InactiveUsers               = ($grp | Where-Object { $_.Enabled -eq 1 -and $_.LastLogonDate -lt $LogonThreshold }).Count
                NeverLoggedInUsers          = ($grp | Where-Object { $null -eq $_.LastLogonDate }).Count
                ServiceAccountsManaged      = ($grp | Where-Object { $_.MSA -eq 1 }).Count
                ServiceAccountsGroupManaged = ($grp | Where-Object { $_.GMSA -eq 1 }).Count
                ServiceAccountsPasswordNeverExpires = ($grp | Where-Object { $_.PasswordNeverExpires -eq 1 }).Count
                ServiceAccountsPatternMatched = ($grp | Where-Object { $_.PatternMatched -eq 1 }).Count
            }
        })

    $summaryData += [PSCustomObject]@{
        Domain                      = 'TOTAL'
        TotalUsers                  = ($summaryData | Measure-Object TotalUsers -Sum).Sum
        ActiveUsers                 = ($summaryData | Measure-Object ActiveUsers -Sum).Sum
        InactiveUsers               = ($summaryData | Measure-Object InactiveUsers -Sum).Sum
        NeverLoggedInUsers          = ($summaryData | Measure-Object NeverLoggedInUsers -Sum).Sum
        ServiceAccountsManaged      = ($summaryData | Measure-Object ServiceAccountsManaged -Sum).Sum
        ServiceAccountsGroupManaged = ($summaryData | Measure-Object ServiceAccountsGroupManaged -Sum).Sum
        ServiceAccountsPasswordNeverExpires = ($summaryData | Measure-Object ServiceAccountsPasswordNeverExpires -Sum).Sum
        ServiceAccountsPatternMatched = ($summaryData | Measure-Object ServiceAccountsPatternMatched -Sum).Sum
    }

    return $summaryData
}

# =====================
# Report Output Helpers
# =====================

function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Summary', 'Full')]
        [string] $Type
    )

    if ($Type -eq 'Full') {
        return [PSCustomObject]@{
            Domain                       = 'Domain'
            OU                           = 'Organizational Units'
            TotalUsers                   = 'Total Users'
            ActiveUsers                  = 'Active Users'
            InactiveUsers                = 'Inactive Users'
            NeverLoggedInUsers           = 'Never Logged In'
            ServiceAccountsManaged       = 'MSA'
            ServiceAccountsGroupManaged  = 'gMSA'
            ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
            ServiceAccountsPatternMatched = 'Pattern Matched'
        }
    } else {
        return [PSCustomObject]@{
            Domain                       = 'Domain'
            TotalUsers                   = 'Total Users'
            ActiveUsers                  = 'Active Users'
            InactiveUsers                = 'Inactive Users'
            NeverLoggedInUsers           = 'Never Logged In'
            ServiceAccountsManaged       = 'MSA'
            ServiceAccountsGroupManaged  = 'gMSA'
            ServiceAccountsPasswordNeverExpires = 'Password Never Expires'
            ServiceAccountsPatternMatched = 'Pattern Matched'
        }
    }
}

function Export-CsvReport {
    param(
        [Parameter(Mandatory)]
        [string]  $FileName,
        [Parameter(Mandatory)]
        [object[]] $Data,
        [Parameter(Mandatory)]
        [PSCustomObject] $Columns
    )
    $fullPath = Join-Path -Path $outputPath -ChildPath $FileName
    
    $calculatedProperties = @()
    foreach ($name in $Columns.PSObject.Properties.Name) {
        $header = $Columns."$name"
        $calculatedProperties += @{ Name = $header; Expression = [scriptblock]::Create("`$_.`"$name`"") }
    }
    try {
        $data | Select-Object -Property $calculatedProperties | Export-Csv -Path $fullPath -NoTypeInformation -Force -Encoding UTF8
        Write-Log "Successfully exported all objects to CSV file $fullPath" "INFO" "Green"
    } catch {
        Write-Log "Could not export to CSV file $fullPath. Error: $_" "ERROR" "RED"
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory)]
        [string]  $FileName,
        [Parameter(Mandatory)]
        [string]  $ReportTitle,
        [Parameter(Mandatory)]
        [object[]] $Tables
    )

    $fullPath = Join-Path -Path $outputPath -ChildPath $FileName
    $tablesHtml = ""
    
    # Placeholder for the SVG content.
    $base64DataUri = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjM4IiB2aWV3Qm94PSIwIDAgMTIwIDM4IiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTk1LjczMzMgMTIuNjkyMkM5NC4zMzE1IDEyLjY5MjIgOTMuNjk5NCAxMy4wOTcxIDkyLjQwMTggMTQuNzE3VjE0LjAxNzZDOTIuNDAxOCAxMy4xNzA2IDkyLjI5NjQgMTMuMDYwNiA5MS40ODk3IDEzLjA2MDZIOTAuODI0MkM5MC4wMTc2IDEzLjA2MDYgODkuOTEyMSAxMy4xNzA2IDg5LjkxMjEgMTQuMDE3NlYyNy4zNzc3Qzg5LjkxMjEgMjguMjI0NyA5MC4wMTc2IDI4LjMzNDcgOTAuODI0MiAyOC4zMzQ3SDkxLjQ4OTdDOTIuMjk2NCAyOC4zMzQ3IDkyLjQwMTggMjguMjI0NyA5Mi40MDE4IDI3LjM3NzdWMjAuMjc0MkM5Mi40MDE4IDE4LjQzMzggOTIuNTc3NiAxNy4zMzAzIDkyLjk2MyAxNi41OTQzQzkzLjQ5NTggMTUuNTc4IDk0LjY1NTggMTUuMDY4NyA5NS43Mjg1IDE1LjIyNTlDOTUuOTc4OCAxNS4yNjE5IDk2LjIgMTUuMzUwNCA5Ni40MzgyIDE1LjQzNDVDOTYuNTI2NyAxNS40NjUzIDk2LjYyODUgMTUuNDg4NiA5Ni43MTY0IDE1LjQ0ODVDOTYuODA2MSAxNS40MDcyIDk2Ljg3NjQgMTUuMzMyOCA5Ni45MzUyIDE1LjI1MjdDOTcuMDc3NiAxNS4wNjEyIDk3LjE2OTcgMTQuODMwMSA5Ny4yNzgyIDE0LjYxNjZDOTcuMzQ3MyAxNC40NzkzIDk3LjQxNjQgMTQuMzQyIDk3LjQ4NjcgMTQuMjAxMUM5Ny42Mjg1IDEzLjkwNjYgOTcuNzMzMyAxMy42ODYxIDk3LjczMzMgMTMuNTc2Qzk3Ljc2NzMgMTMuMDk3MSA5Ni44MjEyIDEyLjY5MjIgOTUuNzMzMyAxMi42OTIyWiIgZmlsbD0iIzA3MEY1MiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTUxLjQxNzIgMTIuNjkyMkM1MC4wMTUyIDEyLjY5MjIgNDkuMzgzMSAxMy4wOTcxIDQ4LjA4NTggMTQuNzE3VjE0LjAxNzZDNDguMDg1OCAxMy4xNzA2IDQ3Ljk4MDYgMTMuMDYwNiA0Ny4xNzM2IDEzLjA2MDZINDYuNTA3NUM0NS43MDA2IDEzLjA2MDYgNDUuNTk1NyAxMy4xNzA2IDQ1LjU5NTcgMTQuMDE3NlYyNy4zNzc3QzQ1LjU5NTcgMjguMjI0NyA0NS43MDA2IDI4LjMzNDcgNDYuNTA3NSAyOC4zMzQ3SDQ3LjE3MzZDNDcuOTgwNiAyOC4zMzQ3IDQ4LjA4NTggMjguMjI0NyA0OC4wODU4IDI3LjM3NzdWMjAuMjc0MkM0OC4wODU4IDE4LjQzMzggNDguMjYwNyAxNy4zMzAzIDQ4LjY0NjYgMTYuNTk0M0M0OS4xNzg4IDE1LjU3OCA1MC4zMzkzIDE1LjA2ODcgNTEuNDExOCAxNS4yMjU5QzUxLjY2MTggMTUuMjYxOSA1MS44ODM2IDE1LjM1MDQgNTIuMTIxNSAxNS40MzQ1QzUyLjIwOTUgMTUuNDY1MyA1Mi4zMTE1IDE1LjQ4ODYgNTIuMzk5NSAxNS40NDg1QzUyLjQ4ODkgMTUuNDA3MiA1Mi41NTk4IDE1LjMzMjggNTIuNjE4NSAxNS4yNTI3QzUyLjc2MSAxNS4wNjEyIDUyLjg1MzMgMTQuODMwMSA1Mi45NjEyIDE0LjYxNjZDNTMuMDMwMyAxNC40NzkzIDUzLjA5OTkgMTQuMzQyIDUzLjE3MDQgMTQuMjAxMUM1My4zMTEzIDEzLjkwNjYgNTMuNDE2MiAxMy42ODYxIDUzLjQxNjIgMTMuNTc2QzUzLjQ1MTQgMTMuMDk3MSA1Mi41MDQ0IDEyLjY5MjIgNTEuNDE3MiAxMi42OTIyWiIgZmlsbD0iIzA3MEY1MiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTU4LjYzMDIgMjEuOTY2OUM1OC42MzAyIDIzLjQwMTkgNTguNzcwNyAyNC4xNzU3IDU5LjA4NTcgMjQuODM4MkM1OS41NzY0IDI1Ljc5NTUgNjAuNjYzOCAyNi4zODQxIDYxLjkyNjMgMjYuMzg0MUM2My4xNTM1IDI2LjM4NDEgNjQuMjQwOCAyNS43OTU1IDY0LjczMjMgMjQuODM4MkM2NS4wNDc1IDI0LjE3NTcgNjUuMTg4MSAyMy40MDE5IDY1LjE4ODEgMjEuOTY2OVYxNC4wMTczQzY1LjE4ODEgMTMuMTcwNCA2NS4yOTM1IDEzLjA2MDQgNjYuMTAwMiAxMy4wNjA0SDY2Ljc2NjNDNjcuNTcyOSAxMy4wNjA0IDY3LjY3NzggMTMuMTcwNCA2Ny42Nzc4IDE0LjAxNzNWMjIuMjYxNEM2Ny42Nzc4IDI0LjUwNzIgNjcuMzI3NSAyNS43MjE2IDY2LjM0NTcgMjYuODYyMUM2NS4yOTM1IDI4LjExMzkgNjMuNzE0OCAyOC43NzU1IDYxLjkyNjMgMjguNzc1NUM2MC4xMDI0IDI4Ljc3NTUgNTguNTI1NCAyOC4xMTM5IDU3LjQ3MyAyNi44NjIxQzU2LjQ5MDcgMjUuNzIxNiA1Ni4xNDAxIDI0LjUwNzIgNTYuMTQwMSAyMi4yNjE0VjE0LjAxNzNDNTYuMTQwMSAxMy4xNzA0IDU2LjI0NSAxMy4wNjA0IDU3LjA1MiAxMy4wNjA0SDU3LjcxOEM1OC41MjU0IDEzLjA2MDQgNTguNjMwMiAxMy4xNzA0IDU4LjYzMDIgMTQuMDE3M1YyMS45NjY5WiIgZmlsbD0iIzA3MEY1MiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc0LjA3NiAyMC42NzkxQzc0LjA3NiAyNC4wNjU4IDc2LjA3NiAyNi4zODQ3IDc4Ljk1MTggMjYuMzg0N0M4MS43MjIxIDI2LjM4NDcgODMuNzIwOSAyMy45NTQ5IDgzLjcyMDkgMjAuNjA1NkM4My43MjA5IDE3LjUxNDIgODEuNjUxOCAxNS4xMjE0IDc4LjkxNjYgMTUuMTIxNEM3Ni4wNzYgMTUuMTIxNCA3NC4wNzYgMTcuNDAzNyA3NC4wNzYgMjAuNjc5MVpNNzQuMjUyNCAxNS4yMzI0Qzc1LjY4OTQgMTMuNTAyNCA3Ny4yMzMgMTIuNzI5MSA3OS4zMzcyIDEyLjcyOTFDODMuMzM0OCAxMi43MjkxIDg2LjI4MDkgMTYuMDc4NCA4Ni4yODA5IDIwLjY3OTFDODYuMjgwOSAyNS4zNTM3IDgzLjI5OTcgMjguNzc2MSA3OS4yNjY5IDI4Ljc3NjFDNzcuMjMzIDI4Ljc3NjEgNzUuNjE5NyAyNy45NjYyIDc0LjI1MjQgMjYuMjM3NlYyNy4zNzc2Qzc0LjI1MjQgMjguMjI0NiA3NC4xNDY5IDI4LjMzNDYgNzMuMzM5NyAyOC4zMzQ2SDcyLjY3NDJDNzEuODY2OSAyOC4zMzQ2IDcxLjc2MTUgMjguMjI0NiA3MS43NjE1IDI3LjM3NzZWMi40NTk3OUM3MS43NjE1IDEuNjEzNzcgNzEuODY2OSAxLjUwMzcyIDcyLjY3NDIgMS41MDM3Mkg3My4zMzk3Qzc0LjE0NjkgMS41MDM3MiA3NC4yNTI0IDEuNjEzNzcgNzQuMjUyNCAyLjQ1OTc5VjE1LjIzMjRaIiBmaWxsPSIjMDcwRjUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAzLjQ3MyAyNy4zNzc3QzEwMy40NzMgMjguMjI0NyAxMDMuMzY3IDI4LjMzNDcgMTAyLjU2MSAyOC4zMzQ3SDEwMS44OTRDMTAxLjA4NyAyOC4zMzQ3IDEwMC45ODMgMjguMjI0NyAxMDAuOTgzIDI3LjM3NzdWMTQuMDE3MUMxMDAuOTgzIDEzLjE3MTEgMTAxLjA4NyAxMy4wNjAxIDEwMS44OTQgMTMuMDYwMUgxMDIuNTYxQzEwMy4zNjcgMTMuMDYwMSAxMDMuNDczIDEzLjE3MTEgMTAzLjQ3MyAxNC4wMTcxVjI3LjM3NzdaTTEwNC4wMzQgNy4yODQwNkMxMDQuMDM0IDguMzE2MSAxMDMuMjI3IDkuMTYzMDUgMTAyLjI0NSA5LjE2MzA1QzEwMS4yNjMgOS4xNjMwNSAxMDAuNDU3IDguMzE2MSAxMDAuNDU3IDcuMjQ3MDdDMTAwLjQ1NyA2LjI1MjQ4IDEwMS4yNjMgNS40MDUwOSAxMDIuMjQ1IDUuNDA1MDlDMTAzLjIyNyA1LjQwNTA5IDEwNC4wMzQgNi4yNTI0OCAxMDQuMDM0IDcuMjg0MDZaIiBmaWxsPSIjMDcwRjUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTE1LjQ0OCAxMy41MDI1QzExNS44NjggMTMuMDYwNSAxMTUuODY4IDEzLjA2MDUgMTE2LjQ2NSAxMy4wNjA1SDExNy41NTJDMTE4LjE4MyAxMy4wNjA1IDExOC40MjkgMTMuMjQ0OSAxMTguNDI5IDEzLjY0OTVDMTE4LjQyOSAxMy43OTY1IDExOC4yODggMTQuMDE3NSAxMTguMDA4IDE0LjMxMkwxMTIuOTkyIDE5LjU3NTZMMTE5LjM0IDI3LjA4MzZDMTE5LjU4NiAyNy40MTQ3IDExOS43MjcgMjcuNjM2IDExOS43MjcgMjcuNzgzMUMxMTkuNzI3IDI4LjE1MTEgMTE5LjQ0NiAyOC4zMzUxIDExOC44MTQgMjguMzM1MUgxMTcuNzI3QzExNy4wOTYgMjguMzM1MSAxMTcuMDk2IDI4LjMzNTEgMTE2LjcxIDI3Ljg1NjZMMTExLjIzOSAyMS4zNzg1TDExMC42MDcgMjIuMDQxVjI3LjM3ODFDMTEwLjYwNyAyOC4yMjQ2IDExMC41MDIgMjguMzM1MSAxMDkuNjk2IDI4LjMzNTFIMTA5LjAzQzEwOC4yMjMgMjguMzM1MSAxMDguMTE4IDI4LjIyNDYgMTA4LjExOCAyNy4zNzgxVjIuNDYwMjJDMTA4LjExOCAxLjYxMzc2IDEwOC4yMjMgMS41MDM3MiAxMDkuMDMgMS41MDM3MkgxMDkuNjk2QzExMC41MDIgMS41MDM3MiAxMTAuNjA3IDEuNjEzNzYgMTEwLjYwNyAyLjQ2MDIyVjE4LjY5MjFMMTE1LjQ0OCAxMy41MDI1WiIgZmlsbD0iIzA3MEY1MiIvPgo8bWFzayBpZD0ibWFzazBfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIxMSIgeT0iMSIgd2lkdGg9IjEyIiBoZWlnaHQ9IjEyIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNy4xMTM5IDEuMDk1NzZDMTcuMDA5OSAxLjEzMzYyIDE2LjkxMjEgMS4xOTU2OCAxNi44Mjk1IDEuMjgxOTZMMTIuMDczNyA2LjI2Njk0QzExLjc4MTQgNi41NzI0MyAxMS43ODE0IDcuMDczMzUgMTIuMDczNyA3LjM3ODgxTDE2LjgyOTUgMTIuMzY0M0MxNy4xMjIzIDEyLjY3MDEgMTcuNTk5MiAxMi42NzAxIDE3Ljg5MTEgMTIuMzY0M0wyMi42NDQgNy4zNzg4MUMyMi45MzU0IDcuMDczMzUgMjIuOTM1NCA2LjU3MjQzIDIyLjY0NCA2LjI2Njk0TDE3Ljg5MTEgMS4yODE5NkMxNy44MDg5IDEuMTk1NjggMTcuNzExMiAxLjEzMzYyIDE3LjYwNzUgMS4wOTU3NkgxNy4xMTM5WiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPgo8ZyBtYXNrPSJ1cmwoI21hc2swXzEwOTE1XzE3NCkiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE3LjExMzkgMS4wOTU3NkMxNy4wMDk5IDEuMTMzNjIgMTYuOTEyMSAxLjE5NTY4IDE2LjgyOTUgMS4yODE5NkwxMi4wNzM3IDYuMjY2OTRDMTEuNzgxNCA2LjU3MjQzIDExLjc4MTQgNy4wNzMzNSAxMi4wNzM3IDcuMzc4ODFMMTYuODI5NSAxMi4zNjQzQzE3LjEyMjMgMTIuNjcwMSAxNy41OTkyIDEyLjY3MDEgMTcuODkxMSAxMi4zNjQzTDIyLjY0NCA3LjM3ODgxQzIyLjkzNTQgNy4wNzMzNSAyMi45MzU0IDYuNTcyNDMgMjIuNjQ0IDYuMjY2OTRMMTcuODkxMSAxLjI4MTk2QzE3LjgwODkgMS4xOTU2OCAxNy43MTEyIDEuMTMzNjIgMTcuNjA3NSAxLjA5NTc2SDE3LjExMzlaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2sxXzEwOTE1XzE3NCIgc3R5bGU9Im1hc2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iMjMiIHk9IjEzIiB3aWR0aD0iMTIiIGhlaWdodD0iMTMiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTI4LjY4NTIgMTMuNzE0NEwyMy45Mjg2IDE4LjY5OTRDMjMuNjM3MSAxOS4wMDUzIDIzLjYzNzEgMTkuNTA1MyAyMy45Mjg2IDE5LjgxMTNMMjguNjg1MiAyNC43OTYzQzI4Ljk3NzEgMjUuMTAxOCAyOS40NTQ5IDI1LjEwMTggMjkuNzQ1OSAyNC43OTYzTDM0LjQ5ODggMTkuODExM0MzNC43OTA3IDE5LjUwNTMgMzQuNzkwNyAxOS4wMDQ0IDM0LjQ5ODggMTguNjk4NkwyOS43NDU5IDEzLjcxNDRDMjkuNjAwNCAxMy41NjEyIDI5LjQwODMgMTMuNDg0NiAyOS4yMTU4IDEzLjQ4NDZDMjkuMDIzMyAxMy40ODQ2IDI4LjgzMTYgMTMuNTYxMiAyOC42ODUyIDEzLjcxNDRaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazFfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjguNjg1MiAxMy43MTQ0TDIzLjkyODYgMTguNjk5NEMyMy42MzcxIDE5LjAwNTMgMjMuNjM3MSAxOS41MDUzIDIzLjkyODYgMTkuODExM0wyOC42ODUyIDI0Ljc5NjNDMjguOTc3MSAyNS4xMDE4IDI5LjQ1NDkgMjUuMTAxOCAyOS43NDU5IDI0Ljc5NjNMMzQuNDk4OCAxOS44MTEzQzM0Ljc5MDcgMTkuNTA1MyAzNC43OTA3IDE5LjAwNDQgMzQuNDk4OCAxOC42OTg2TDI5Ljc0NTkgMTMuNzE0NEMyOS42MDA0IDEzLjU2MTIgMjkuNDA4MyAxMy40ODQ2IDI5LjIxNTggMTMuNDg0NkMyOS4wMjMzIDEzLjQ4NDYgMjguODMxNiAxMy41NjEyIDI4LjY4NTIgMTMuNzE0NFoiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPgo8bWFzayBpZD0ibWFzazJfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSI4IiB5PSIzMiIgd2lkdGg9IjQiIGhlaWdodD0iNSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAuODgwNSAzMi4zNzAzTDguNzY3MDMgMzQuNTg3MUM4LjQ3NTA5IDM0Ljg5MjUgOC41MzM4MiAzNS4zMTA3IDguODk3NDUgMzUuNTE1NEwxMC43MTczIDM2LjQxODZDMTEuMDk5IDM2LjU4NDYgMTEuNDEwNiAzNi4zNjYzIDExLjQxMDYgMzUuOTM0VjMyLjYwMUMxMS40MTA2IDMyLjMzNiAxMS4zMjEzIDMyLjE5NDcgMTEuMTg1NCAzMi4xOTQ3QzExLjA5OSAzMi4xOTQ3IDEwLjk5NDEgMzIuMjUxOSAxMC44ODA1IDMyLjM3MDNaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazJfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAuODgwNSAzMi4zNzAzTDguNzY3MDMgMzQuNTg3MUM4LjQ3NTA5IDM0Ljg5MjUgOC41MzM4MiAzNS4zMTA3IDguODk3NDUgMzUuNTE1NEwxMC43MTczIDM2LjQxODZDMTEuMDk5IDM2LjU4NDYgMTEuNDEwNiAzNi4zNjYzIDExLjQxMDYgMzUuOTM0VjMyLjYwMUMxMS40MTA2IDMyLjMzNiAxMS4zMjEzIDMyLjE5NDcgMTEuMTg1NCAzMi4xOTQ3QzExLjA5OSAzMi4xOTQ3IDEwLjk5NDEgMzIuMjUxOSAxMC44ODA1IDMyLjM3MDNaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2szXzEwOTE1XzE3NCIgc3R5bGU9Im1hc2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iMjMiIHk9IjMyIiB3aWR0aD0iNCIgaGVpZ2h0PSI1Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0yMy4zMDU3IDMyLjYwMVYzNS45MzRDMjMuMzA1NyAzNi4zNjYzIDIzLjYxNzMgMzYuNTg0NiAyMy45OTg5IDM2LjQxODZMMjUuODE4OCAzNS41MTU0QzI2LjE4MjUgMzUuMzEwNyAyNi4yNDE2IDM0Ljg5MjUgMjUuOTUwMSAzNC41ODcxTDIzLjgzNjIgMzIuMzcwM0MyMy43MjI2IDMyLjI1MTkgMjMuNjE3MyAzMi4xOTQ3IDIzLjUzMTMgMzIuMTk0N0MyMy4zOTUgMzIuMTk0NyAyMy4zMDU3IDMyLjMzNiAyMy4zMDU3IDMyLjYwMVoiIGZpbGw9IndoaXRlIi8+CjwvbWFzaz4KPGcgbWFzaz0idXJsKCNtYXNrM18xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0yMy4zMDU3IDMyLjYwMVYzNS45MzRDMjMuMzA1NyAzNi4zNjYzIDIzLjYxNzMgMzYuNTg0NiAyMy45OTg5IDM2LjQxODZMMjUuODE4OCAzNS41MTU0QzI2LjE4MjUgMzUuMzEwNyAyNi4yNDE2IDM0Ljg5MjUgMjUuOTUwMSAzNC41ODcxTDIzLjgzNjIgMzIuMzcwM0MyMy43MjI2IDMyLjI1MTkgMjMuNjE3MyAzMi4xOTQ3IDIzLjUzMTMgMzIuMTk0N0MyMy4zOTUgMzIuMTk0NyAyMy4zMDU3IDMyLjMzNiAyMy4zMDU3IDMyLjYwMVoiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPgo8bWFzayBpZD0ibWFzazRfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIyMyIgeT0iMjUiIHdpZHRoPSI3IiBoZWlnaHQ9IjciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTI0LjA1NiAyNS40OTI3QzIzLjY0MzcgMjUuNDkyNyAyMy4zMDU3IDI1Ljg0NTcgMjMuMzA1NyAyNi4yNzhWMzAuNzc0NEMyMy4zMDU3IDMxLjIwNTcgMjMuNjQzNyAzMS41NjA1IDI0LjA1NiAzMS41NjA1SDI4LjM0MTJDMjguNzUzNSAzMS41NjA1IDI5LjA5MTUgMzEuMjA1NyAyOS4wOTE1IDMwLjc3NDRWMjYuMjc4QzI5LjA5MTUgMjUuODQ1NyAyOC43NTM1IDI1LjQ5MjcgMjguMzQxMiAyNS40OTI3SDI0LjA1NloiIGZpbGw9IndoaXRlIi8+CjwvbWFzaz4KPGcgbWFzaz0idXJsKCNtYXNrNF8xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0yNC4wNTYgMjUuNDkyN0MyMy42NDM3IDI1LjQ5MjcgMjMuMzA1NyAyNS44NDU3IDIzLjMwNTcgMjYuMjc4VjMwLjc3NDRDMjMuMzA1NyAzMS4yMDU3IDIzLjY0MzcgMzEuNTYwNSAyNC4wNTYgMzEuNTYwNUgyOC4zNDEyQzI4Ljc1MzUgMzEuNTYwNSAyOS4wOTE1IDMxLjIwNTcgMjkuMDkxNSAzMC43NzQ0VjI2LjI3OEMyOS4wOTE1IDI1Ljg0NTcgMjguNzUzNSAyNS40OTI3IDI4LjM0MTIgMjUuNDkyN0gyNC4wNTZaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2s1XzEwOTE1XzE3NCIgc3R5bGU9Im1hc2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iMjkiIHk9IjEwIiB3aWR0aD0iNSIgaGVpZ2h0PSI0Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zMS45NzgxIDEwLjI0NTdMMjkuODY0NiAxMi40NjQ0QzI5LjU3MzEgMTIuNzcxMSAyOS42NzE2IDEzLjAyMTggMzAuMDg0NCAxMy4wMjE4SDMzLjI2MjdDMzMuNjc0NiAxMy4wMjE4IDMzLjg4MjcgMTIuNjk0NCAzMy43MjQ5IDEyLjI5MzRMMzIuODYzIDEwLjM4MjNDMzIuNzUxNSAxMC4xNjQxIDMyLjU3MzIgMTAuMDUwOSAzMi4zODcgMTAuMDUwOUMzMi4yNDczIDEwLjA1MDkgMzIuMTAyNiAxMC4xMTQ4IDMxLjk3ODEgMTAuMjQ1N1oiIGZpbGw9IndoaXRlIi8+CjwvbWFzaz4KPGcgbWFzaz0idXJsKCNtYXNrNV8xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zMS45NzgxIDEwLjI0NTdMMjkuODY0NiAxMi40NjQ0QzI5LjU3MzEgMTIuNzcxMSAyOS42NzE2IDEzLjAyMTggMzAuMDg0NCAxMy4wMjE4SDMzLjI2MjdDMzMuNjc0NiAxMy4wMjE4IDMzLjg4MjcgMTIuNjk0NCAzMy43MjQ5IDEyLjI5MzRMMzIuODYzIDEwLjM4MjNDMzIuNzUxNSAxMC4xNjQxIDMyLjU3MzIgMTAuMDUwOSAzMi4zODcgMTAuMDUwOUMzMi4yNDczIDEwLjA1MDkgMzIuMTAyNiAxMC4xMTQ4IDMxLjk3ODEgMTAuMjQ1N1oiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPgo8bWFzayBpZD0ibWFzazZfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIyMyIgeT0iMiIgd2lkdGg9IjQiIGhlaWdodD0iNSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMjMuMzA1NyAyLjU3NjE3VjUuOTA5MThDMjMuMzA1NyA2LjM0MTg4IDIzLjU0NDMgNi40NDU3NiAyMy44MzYyIDYuMTM5ODNMMjUuOTUwMSAzLjkyMjY3QzI2LjI0MTYgMy42MTc2MyAyNi4xODI0IDMuMTk5MDIgMjUuODE5MiAyLjk5NDc3TDIzLjk5ODkgMi4wOTE1M0MyMy45MTE3IDIuMDUzMjQgMjMuODI4NyAyLjAzNjA3IDIzLjc1MTkgMi4wMzYwN0MyMy40OTE1IDIuMDM2MDcgMjMuMzA1NyAyLjI0MjUyIDIzLjMwNTcgMi41NzYxN1oiIGZpbGw9IndoaXRlIi8+CjwvbWFzaz4KPGcgbWFzaz0idXJsKCNtYXNrNl8xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0yMy4zMDU3IDIuNTc2MTdWNS45MDkxOEMyMy4zMDU3IDYuMzQxODggMjMuNTQ0MyA2LjQ0NTc2IDIzLjgzNjIgNi4xMzk4M0wyNS45NTAxIDMuOTIyNjdDMjYuMjQxNiAzLjYxNzYzIDI2LjE4MjQgMy4xOTkwMiAyNS44MTkyIDIuOTk0NzdMMjMuOTk4OSAyLjA5MTUzQzIzLjkxMTcgMi4wNTMyNCAyMy44Mjg3IDIuMDM2MDcgMjMuNzUxOSAyLjAzNjA3QzIzLjQ5MTUgMi4wMzYwNyAyMy4zMDU3IDIuMjQyNTIgMjMuMzA1NyAyLjU3NjE3WiIgZmlsbD0iIzA3MEY1MiIvPgo8L2c+CjxtYXNrIGlkPSJtYXNrN18xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjAiIHk9IjEwIiB3aWR0aD0iNiIgaGVpZ2h0PSI0Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xLjg1MzMgMTAuMzgyM0wwLjk5MjIzNiAxMi4yOTQ4QzAuODM0MTE1IDEyLjY5NDQgMS4wNDE3MyAxMy4wMjE4IDEuNDU0MDIgMTMuMDIxOEg0LjYzMzIxQzUuMDQ1OTIgMTMuMDIxOCA1LjE0NDkgMTIuNzcxMSA0Ljg1MjU3IDEyLjQ2NDRMMi43Mzg3IDEwLjI0NTdDMi42MTQxMyAxMC4xMTQ4IDIuNDY5ODUgMTAuMDUwOSAyLjMyOTc2IDEwLjA1MDlDMi4xNDM1NCAxMC4wNTA5IDEuOTY1MjkgMTAuMTY0MSAxLjg1MzMgMTAuMzgyM1oiIGZpbGw9IndoaXRlIi8+CjwvbWFzaz4KPGcgbWFzaz0idXJsKCNtYXNrN18xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xLjg1MzMgMTAuMzgyM0wwLjk5MjIzNiAxMi4yOTQ4QzAuODM0MTE1IDEyLjY5NDQgMS4wNDE3MyAxMy4wMjE4IDEuNDU0MDIgMTMuMDIxOEg0LjYzMzIxQzUuMDQ1OTIgMTMuMDIxOCA1LjE0NDkgMTIuNzcxMSA0Ljg1MjU3IDEyLjQ2NDRMMi43Mzg3IDEwLjI0NTdDMi42MTQxMyAxMC4xMTQ4IDIuNDY5ODUgMTAuMDUwOSAyLjMyOTc2IDEwLjA1MDlDMi4xNDM1NCAxMC4wNTA5IDEuOTY1MjkgMTAuMTY0MSAxLjg1MzMgMTAuMzgyM1oiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPgo8bWFzayBpZD0ibWFzazhfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSI1IiB5PSI2IiB3aWR0aD0iNyIgaGVpZ2h0PSI4Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02LjM3NTMzIDYuOTQ5NjVDNS45NjMwNSA2Ljk0OTY1IDUuNjI1IDcuMzA0NDEgNS42MjUgNy43MzY2OVYxMi4yMzEzQzUuNjI1IDEyLjY2NCA1Ljk2MzA1IDEzLjAxODMgNi4zNzUzMyAxMy4wMTgzSDEwLjY2MDVDMTEuMDczMyAxMy4wMTgzIDExLjQxMDkgMTIuNjY0IDExLjQxMDkgMTIuMjMxM1Y3LjczNjY5QzExLjQxMDkgNy4zMDQ0MSAxMS4wNzMzIDYuOTQ5NjUgMTAuNjYwNSA2Ljk0OTY1SDYuMzc1MzNaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazhfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNi4zNzUzMyA2Ljk0OTY1QzUuOTYzMDUgNi45NDk2NSA1LjYyNSA3LjMwNDQxIDUuNjI1IDcuNzM2NjlWMTIuMjMxM0M1LjYyNSAxMi42NjQgNS45NjMwNSAxMy4wMTgzIDYuMzc1MzMgMTMuMDE4M0gxMC42NjA1QzExLjA3MzMgMTMuMDE4MyAxMS40MTA5IDEyLjY2NCAxMS40MTA5IDEyLjIzMTNWNy43MzY2OUMxMS40MTA5IDcuMzA0NDEgMTEuMDczMyA2Ljk0OTY1IDEwLjY2MDUgNi45NDk2NUg2LjM3NTMzWiIgZmlsbD0iIzA3MEY1MiIvPgo8L2c+CjxtYXNrIGlkPSJtYXNrOV8xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjgiIHk9IjIiIHdpZHRoPSI0IiBoZWlnaHQ9IjUiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTEwLjcxNzMgMi4wOTE1M0w4Ljg5NzQ1IDIuOTk0NzdDOC41MzM4MiAzLjE5OTAyIDguNDc1MDkgMy42MTc2MyA4Ljc2NzAzIDMuOTIyNjdMMTAuODgwNSA2LjEzOTgzQzExLjE3MjQgNi40NDU3NiAxMS40MTA2IDYuMzQxODggMTEuNDEwNiA1LjkwOTE4VjIuNTc2MTdDMTEuNDEwNiAyLjI0MjUyIDExLjIyNDggMi4wMzYwNyAxMC45NjQ0IDIuMDM2MDdDMTAuODg3MiAyLjAzNjA3IDEwLjgwNDUgMi4wNTM2OCAxMC43MTczIDIuMDkxNTNaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazlfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTAuNzE3MyAyLjA5MTUzTDguODk3NDUgMi45OTQ3N0M4LjUzMzgyIDMuMTk5MDIgOC40NzUwOSAzLjYxNzYzIDguNzY3MDMgMy45MjI2N0wxMC44ODA1IDYuMTM5ODNDMTEuMTcyNCA2LjQ0NTc2IDExLjQxMDYgNi4zNDE4OCAxMS40MTA2IDUuOTA5MThWMi41NzYxN0MxMS40MTA2IDIuMjQyNTIgMTEuMjI0OCAyLjAzNjA3IDEwLjk2NDQgMi4wMzYwN0MxMC44ODcyIDIuMDM2MDcgMTAuODA0NSAyLjA1MzY4IDEwLjcxNzMgMi4wOTE1M1oiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPgo8bWFzayBpZD0ibWFzazEwXzEwOTE1XzE3NCIgc3R5bGU9Im1hc2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iMjkiIHk9IjI1IiB3aWR0aD0iNSIgaGVpZ2h0PSI0Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zMC4wODQ0IDI1LjQ5MjdDMjkuNjcxNiAyNS40OTI3IDI5LjU3MzEgMjUuNzQzIDI5Ljg2NDYgMjYuMDQ4OUwzMS45NzgxIDI4LjI2ODVDMzIuMjY5NiAyOC41NzQ3IDMyLjY2OCAyOC41MTE3IDMyLjg2MyAyOC4xMzA1TDMzLjcyNDkgMjYuMjE5NEMzMy44ODI3IDI1LjgyMDEgMzMuNjc0NiAyNS40OTI3IDMzLjI2MjcgMjUuNDkyN0gzMC4wODQ0WiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPgo8ZyBtYXNrPSJ1cmwoI21hc2sxMF8xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zMC4wODQ0IDI1LjQ5MjdDMjkuNjcxNiAyNS40OTI3IDI5LjU3MzEgMjUuNzQzIDI5Ljg2NDYgMjYuMDQ4OUwzMS45NzgxIDI4LjI2ODVDMzIuMjY5NiAyOC41NzQ3IDMyLjY2OCAyOC41MTE3IDMyLjg2MyAyOC4xMzA1TDMzLjcyNDkgMjYuMjE5NEMzMy44ODI3IDI1LjgyMDEgMzMuNjc0NiAyNS40OTI3IDMzLjI2MjcgMjUuNDkyN0gzMC4wODQ0WiIgZmlsbD0iIzA3MEY1MiIvPgo8L2c+CjxtYXNrIGlkPSJtYXNrMTFfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSI1IiB5PSIyNSIgd2lkdGg9IjciIGhlaWdodD0iNyI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNi4zNzUzMyAyNS40OTI2QzUuOTYzMDUgMjUuNDkyNiA1LjYyNSAyNS44NDU2IDUuNjI1IDI2LjI3NzlWMzAuNzc0M0M1LjYyNSAzMS4yMDU2IDUuOTYzMDUgMzEuNTYwNCA2LjM3NTMzIDMxLjU2MDRIMTAuNjYwNUMxMS4wNzMzIDMxLjU2MDQgMTEuNDEwOSAzMS4yMDU2IDExLjQxMDkgMzAuNzc0M1YyNi4yNzc5QzExLjQxMDkgMjUuODQ1NiAxMS4wNzMzIDI1LjQ5MjYgMTAuNjYwNSAyNS40OTI2SDYuMzc1MzNaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazExXzEwOTE1XzE3NCkiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTYuMzc1MzMgMjUuNDkyNkM1Ljk2MzA1IDI1LjQ5MjYgNS42MjUgMjUuODQ1NiA1LjYyNSAyNi4yNzc5VjMwLjc3NDNDNS42MjUgMzEuMjA1NiA1Ljk2MzA1IDMxLjU2MDQgNi4zNzUzMyAzMS41NjA0SDEwLjY2MDVDMTEuMDczMyAzMS41NjA0IDExLjQxMDkgMzEuMjA1NiAxMS40MTA5IDMwLjc3NDNWMjYuMjc3OUMxMS40MTA5IDI1Ljg0NTYgMTEuMDczMyAyNS40OTI2IDEwLjY2MDUgMjUuNDkyNkg2LjM3NTMzWiIgZmlsbD0iIzA3MEY1MiIvPgo8L2c+CjxtYXNrIGlkPSJtYXNrMTJfMTA5MTVfMTc0IiBzdHlsZT0ibWFzay10eXBlOmFscGhhIiBtYXNrVW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4PSIwIiB5PSIyNSIgd2lkdGg9IjYiIGhlaWdodD0iNCI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMS40NTQwMiAyNS40OTI3QzEuMDQxNzMgMjUuNDkyNyAwLjgzNDExNSAyNS44MTg4IDAuOTkyMjM2IDI2LjIxOUwxLjg1MzMgMjguMTMwNUMyLjA0ODc1IDI4LjUxMTcgMi40NDcyIDI4LjU3NDcgMi43Mzg3IDI4LjI2ODVMNC44NTI1NyAyNi4wNDg5QzUuMTQ0OSAyNS43NDMgNS4wNDU5MiAyNS40OTI3IDQuNjMzMjEgMjUuNDkyN0gxLjQ1NDAyWiIgZmlsbD0id2hpdGUiLz4KPC9tYXNrPgo8ZyBtYXNrPSJ1cmwoI21hc2sxMl8xMDkxNV8xNzQpIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xLjQ1NDAyIDI1LjQ5MjdDMS4wNDE3MyAyNS40OTI3IDAuODM0MTE1IDI1LjgxODggMC45OTIyMzYgMjYuMjE5TDEuODUzMyAyOC4xMzA1QzIuMDQ4NzUgMjguNTExNyAyLjQ0NzIgMjguNTc0NyAyLjczODcgMjguMjY4NUw0Ljg1MjU3IDI2LjA0ODlDNS4xNDQ5IDI1Ljc0MyA1LjA0NTkyIDI1LjQ5MjcgNC42MzMyMSAyNS40OTI3SDEuNDU0MDJaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2sxM18xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjIzIiB5PSI2IiB3aWR0aD0iNyIgaGVpZ2h0PSI4Ij4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0yNC4wNTYgNi45NDk2NUMyMy42NDM3IDYuOTQ5NjUgMjMuMzA1NyA3LjMwNDQxIDIzLjMwNTcgNy43MzY2OVYxMi4yMzEzQzIzLjMwNTcgMTIuNjY0IDIzLjY0MzcgMTMuMDE4MyAyNC4wNTYgMTMuMDE4M0gyOC4zNDEyQzI4Ljc1MzUgMTMuMDE4MyAyOS4wOTE1IDEyLjY2NCAyOS4wOTE1IDEyLjIzMTNWNy43MzY2OUMyOS4wOTE1IDcuMzA0NDEgMjguNzUzNSA2Ljk0OTY1IDI4LjM0MTIgNi45NDk2NUgyNC4wNTZaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazEzXzEwOTE1XzE3NCkiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTI0LjA1NiA2Ljk0OTY1QzIzLjY0MzcgNi45NDk2NSAyMy4zMDU3IDcuMzA0NDEgMjMuMzA1NyA3LjczNjY5VjEyLjIzMTNDMjMuMzA1NyAxMi42NjQgMjMuNjQzNyAxMy4wMTgzIDI0LjA1NiAxMy4wMTgzSDI4LjM0MTJDMjguNzUzNSAxMy4wMTgzIDI5LjA5MTUgMTIuNjY0IDI5LjA5MTUgMTIuMjMxM1Y3LjczNjY5QzI5LjA5MTUgNy4zMDQ0MSAyOC43NTM1IDYuOTQ5NjUgMjguMzQxMiA2Ljk0OTY1SDI0LjA1NloiIGZpbGw9IiMwNzBGNTIiLz4KPC9nPgo8bWFzayBpZD0ibWFzazE0XzEwOTE1XzE3NCIgc3R5bGU9Im1hc2stdHlwZTphbHBoYSIgbWFza1VuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeD0iMTEiIHk9IjI1IiB3aWR0aD0iMTIiIGhlaWdodD0iMTMiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE2LjgyOTUgMjYuMTc3MUwxMi4wNzM3IDMxLjE2MTdDMTEuNzgxNCAzMS40Njc2IDExLjc4MTQgMzEuOTY3NiAxMi4wNzM3IDMyLjI3NEwxNi44Mjk1IDM3LjI1ODFDMTYuODk1OCAzNy4zMjcyIDE2Ljk3MTcgMzcuMzgwOSAxNy4wNTIzIDM3LjQxODdIMTcuNjY4OEMxNy43NDkzIDM3LjM4MDkgMTcuODI0OCAzNy4zMjcyIDE3Ljg5MTEgMzcuMjU4MUwyMi42NDQgMzIuMjc0QzIyLjkzNTQgMzEuOTY3NiAyMi45MzU0IDMxLjQ2NzYgMjIuNjQ0IDMxLjE2MTdMMTcuODkxMSAyNi4xNzcxQzE3Ljc0NTUgMjYuMDIzOSAxNy41NTI2IDI1Ljk0NzggMTcuMzYwNSAyNS45NDc4QzE3LjE2OCAyNS45NDc4IDE2Ljk3NTUgMjYuMDIzOSAxNi44Mjk1IDI2LjE3NzFaIiBmaWxsPSJ3aGl0ZSIvPgo8L21hc2s+CjxnIG1hc2s9InVybCgjbWFzazE0XzEwOTE1XzE3NCkiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE2LjgyOTUgMjYuMTc3MUwxMi4wNzM3IDMxLjE2MTdDMTEuNzgxNCAzMS40Njc2IDExLjc4MTQgMzEuOTY3NiAxMi4wNzM3IDMyLjI3NEwxNi44Mjk1IDM3LjI1ODFDMTYuODk1OCAzNy4zMjcyIDE2Ljk3MTcgMzcuMzgwOSAxNy4wNTIzIDM3LjQxODdIMTcuNjY4OEMxNy43NDkzIDM3LjM4MDkgMTcuODI0OCAzNy4zMjcyIDE3Ljg5MTEgMzcuMjU4MUwyMi42NDQgMzIuMjc0QzIyLjkzNTQgMzEuOTY3NiAyMi45MzU0IDMxLjQ2NzYgMjIuNjQ0IDMxLjE2MTdMMTcuODkxMSAyNi4xNzcxQzE3Ljc0NTUgMjYuMDIzOSAxNy41NTI2IDI1Ljk0NzggMTcuMzYwNSAyNS45NDc4QzE3LjE2OCAyNS45NDc4IDE2Ljk3NTUgMjYuMDIzOSAxNi44Mjk1IDI2LjE3NzFaIiBmaWxsPSIjMDcwRjUyIi8+CjwvZz4KPG1hc2sgaWQ9Im1hc2sxNV8xMDkxNV8xNzQiIHN0eWxlPSJtYXNrLXR5cGU6YWxwaGEiIG1hc2tVbml0cz0idXNlclNwYWNlT25Vc2UiIHg9IjAiIHk9IjEzIiB3aWR0aD0iMTIiIGhlaWdodD0iMTMiPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTQuOTc1MjYgMTMuNzE0NEwwLjIxODYyMiAxOC42OTk0Qy0wLjA3Mjg3NDEgMTkuMDA1MyAtMC4wNzI4NzQxIDE5LjUwNTMgMC4yMTg2MjIgMTkuODExM0w0Ljk3NTI2IDI0Ljc5NjNDNS4yNjcxNyAyNS4xMDE4IDUuNzQ0MDUgMjUuMTAxOCA2LjAzNTk2IDI0Ljc5NjNMMTAuNzg5MyAxOS44MTEzQzExLjA4MDcgMTkuNTA1MyAxMS4wODA3IDE5LjAwNDQgMTAuNzg5MyAxOC42OTg2TDYuMDM1OTYgMTMuNzE0NEM1Ljg5MDQzIDEzLjU2MTIgNS42OTc5MiAxMy40ODQ2IDUuNTA1ODIgMTMuNDg0NkM1LjMxMzMxIDEzLjQ4NDYgNS4xMjEyMSAxMy41NjEyIDQuOTc1MjYgMTMuNzE0NFoiIGZpbGw9IndoaXRlIi8+CjwvbWFzaz4KPGcgbWFzaz0idXJsKCNtYXNrMTVfMTA5MTVfMTc0KSI+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNC45NzUyNiAxMy43MTQ0TDAuMjE4NjIyIDE4LjY5OTRDLTAuMDcyODc0MSAxOS4wMDUzIC0wLjA3Mjg3NDEgMTkuNTA1MyAwLjIxODYyMiAxOS44MTEzTDQuOTc1MjYgMjQuNzk2M0M1LjI2NzE3IDI1LjEwMTggNS43NDQwNSAyNS4xMDE4IDYuMDM1OTYgMjQuNzk2M0wxMC43ODkzIDE5LjgxMTNDMTEuMDgwNyAxOS41MDUzIDExLjA4MDcgMTkuMDA0NCAxMC43ODkzIDE4LjY5ODZMNi4wMzU5NiAxMy43MTQ0QzUuODkwNDMgMTMuNTYxMiA1LjY5NzkyIDEzLjQ4NDYgNS41MDU4MiAxMy40ODQ2QzUuMzEzMzEgMTMuNDg0NiA1LjEyMTIxIDEzLjU2MTIgNC45NzUyNiAxMy43MTQ0WiIgZmlsbD0iIzA3MEY1MiIvPgo8L2c+Cjwvc3ZnPgo="
    $logoHtml = "<img src='$base64DataUri' class='header-svg' alt='Rubrik Logo' />"

    # Inner helper function to create a single HTML table
    function New-HtmlTable {
        param(
            [Parameter(Mandatory)]
            [string] $TableTitle,
            [Parameter(Mandatory)]
            [object[]] $TableData,
            [Parameter(Mandatory)]
            [PSCustomObject] $TableColumns
        )

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
        $html += '<thead><tr>'
        foreach ($header in $TableColumns.PSObject.Properties.Value) {
            $html += "<th>$header</th>"
        }
        $html += '</tr></thead>'
        $html += '<tbody>'
        foreach ($row in $TableData) {
            $isTotalRow = ($row.Domain -eq 'TOTAL')
            $rowClass = if ($isTotalRow) { ' class="total"' } else { '' }
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
    
    # Generate each table's HTML content
    foreach ($table in $Tables) {
        $tablesHtml += New-HtmlTable -TableTitle $table.Title -TableData $table.Data -TableColumns $table.Columns
    }
    
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
    .header svg {
        height: 45px;
        width: auto;
    }
    h2 {
        color: #0d47a1;
        font-size: 20px;
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
    <title>Active Directory Report</title>
    $css
</head>
<body>
    <div class="report-container">
        <div class="header">
            <div class="header-logo">$logoHtml</div>
            <h1>$ReportTitle</h1>
        </div>
        <br>
        $tablesHtml
        <div class="footer">
            Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        </div>
    </div>
</body>
</html>
"@

    try {
        $htmlBody | Out-File -FilePath $fullPath -Encoding UTF8
        Write-Log "Successfully exported HTML report to $fullPath" "INFO" "Green"
    } catch {
        Write-Log "Could not export to HTML file $fullPath. Error: $_" "ERROR" "RED"
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

Write-Log "Building AD user dataset..." -Color Cyan
$allUserData = Get-ADUserData `
    -DomainsToAudit $domainsToAudit `
    -ServicePattern $UserServiceAccountNamesLike

switch ($Mode) {
    "Full" {
        Write-Log "Generating Full Reports" -Color Cyan
        
        $perOUReport = Get-SummaryPerOU -UserData $allUserData -LogonThreshold $logonThreshold
        $domainSummaryReport = Get-SummaryPerDomain -UserData $allUserData -LogonThreshold $logonThreshold
        
        $perOUHeaders = Get-ReportHeaders -Type 'Full'
        $summaryHeaders = Get-ReportHeaders -Type 'Summary'

        Export-CsvReport -FileName "UserAudit_Full_PerOU_Summary_$timestamp.csv" -Data $perOUReport -Columns $perOUHeaders
        Export-CsvReport -FileName "UserAudit_Full_Domain_Summary_$timestamp.csv" -Data $domainSummaryReport -Columns $summaryHeaders

        $tables = @(
            @{ Title = 'AD User Audit - Per Domain Summary'; Data = $domainSummaryReport; Columns = $summaryHeaders },
            @{ Title = 'AD User Audit - Per Organizational Unit / User Details'; Data = $perOUReport; Columns = $perOUHeaders }
        )
        Export-HtmlReport -FileName "UserAudit_Full_$timestamp.html" -ReportTitle "Active Directory Audit - Full" -Tables $tables
    }

    "Summary" {
        Write-Log "Generating Summary Report" -Color Cyan
        
        $summaryReport = Get-SummaryPerDomain -UserData $allUserData -LogonThreshold $logonThreshold
        
        $columns = Get-ReportHeaders -Type 'Summary'
        $reportFileName = "UserAudit_Summary_$timestamp"
        Export-CsvReport -FileName "$reportFileName.csv" -Data $summaryReport -Columns $columns
        
        # Create a single table object for the summary report
        $tables = @(
            @{ Title = 'AD User Audit - Per Domain Summary'; Data = $summaryReport; Columns = $columns }
        )
        Export-HtmlReport -FileName "$reportFileName.html" -ReportTitle "Active Directory Audit - Summary" -Tables $tables
    }
}

Write-Log "AD reports generation completed. Please send all the files within the directory to your Rubrik Sales representative." -Color Green

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture