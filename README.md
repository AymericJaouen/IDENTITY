# 🧠 IDENTITY Scripts

This repository contains two PowerShell scripts designed to audit human identities across hybrid environments—on-premises Active Directory and Microsoft Entra ID (formerly Azure AD). These tools generate detailed reports to help IT administrators assess identity hygiene, activity, and ownership.

---

## 📄 Scripts Overview

### 1. `Get-AdHumanIdentity.ps1`

**Purpose:**  
Audits users and service accounts across one or more Active Directory domains, generating per-OU or domain-level summaries.

**Key Features:**
- Classifies accounts by activity: active, inactive, never logged in
- Detects Managed Service Accounts (MSA) and Group Managed Service Accounts (gMSA)
- Flags accounts with `PasswordNeverExpires`
- Identifies service accounts using wildcard name patterns
- Supports per-OU or domain summary reporting
- Outputs timestamped CSV reports

**Usage Examples:**
```powershell
# Audit all domains with default settings
.\Get-AdHumanIdentity.ps1 -Mode UserPerOU

# Audit specific domain with service account pattern matching
.\Get-AdHumanIdentity.ps1 -SpecificDomains "corp.domain.local" `
                          -UserServiceAccountNamesLike "*svc*", "*_bot" `
                          -Mode Summary

Parameters:

Parameter	Description
-SpecificDomains	Array of domain names to audit (optional)
-UserServiceAccountNamesLike	Wildcard patterns to identify service accounts (optional)
-Mode	Required. UserPerOU or Summary
Requirements:

PowerShell 5.1+

RSAT: Active Directory module installed

Domain-joined machine or network access to AD

2. Get-EntraHumanIdentity.ps1
Purpose: Generates detailed reports on users, applications, and service principals in Microsoft Entra ID using Microsoft Graph.

Key Features:

Connects to Microsoft Graph with required scopes

Retrieves user metadata, sign-in activity, sync status, and ownership

Flags inactive users, guest accounts, and service account patterns

Optional ownership analysis of apps and service principals

Supports Full (per-user detail) and Summary (aggregated by domain) modes

Outputs CSV and HTML reports with logging

Usage Examples:
# Full report with ownership analysis
.\Get-EntraHumanIdentity.ps1 -Mode Full `
                             -DaysInactive 180 `
                             -UserServiceAccountNamesLike "svc-", "sa-" `
                             -CheckOwnership

# Summary report only
.\Get-EntraHumanIdentity.ps1 -Mode Summary

Parameters:

Parameter	Description
-Mode	Full (default) or Summary
-DaysInactive	Threshold in days to flag inactive users (default: 180)
-UserServiceAccountNamesLike	Array of patterns to identify service accounts (optional)
-CheckOwnership	Switch to enable ownership analysis (optional)
Requirements:

PowerShell 7+

Microsoft Graph PowerShell SDK modules:

Microsoft.Graph.Users

Microsoft.Graph.Applications

Microsoft.Graph.Identity.DirectoryManagement

Admin permissions to query Entra ID

📁 Output Structure
ADReports/: Contains Active Directory audit reports

EntraReports/: Contains Entra ID reports

File names include timestamps for traceability

Reports are saved in both CSV and HTML formats

Logs are generated alongside reports for auditing

🛠️ Setup Instructions
Clone the repository:

bash
git clone https://github.com/AymericJaouen/IDENTITY.git
cd IDENTITY
Install required modules:

powershell
# For AD script
Import-Module ActiveDirectory

# For Entra script
Install-Module Microsoft.Graph -Scope CurrentUser
Run the desired script with appropriate parameters.

📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

🙋‍♂️ Author
Aymeric Jaouen For questions, feedback, or contributions, please use GitHub Issues.


---

Let me know if you'd like badges, diagrams, or a scheduling guide for automation. I can also help you generate sample reports or test data if needed.