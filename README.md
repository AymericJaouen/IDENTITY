Get-EntraHumanIdentity.ps1

PowerShell script designed to generate detailed and customizable reports on your Entra ID (formerly Azure Active Directory) environment. This tool connects to Microsoft Graph, retrieves critical user, application, and service principal data, and presents it in a clear, accessible format.

Key Features 🛠️
This script is a reporting solution with the following capabilities:

Flexible Reporting Modes: Choose between a Full report, which details every user, or a Summary report, which aggregates data by domain for a high-level overview.

Users Reporting: Automatically categorizes users as Active, Inactive, or Never Logged In based on a configurable inactivity period.

Service Account Identification: Identify service accounts by providing common naming patterns, helping you quickly filter out administrative accounts from user-facing reports.

Ownership Analysis: When enabled, the script performs a deep dive to count the number of applications and service principals owned by each user

Self-Contained HTML Reports: Generates single-file HTML reports

Logging: All actions and potential errors are logged to a dedicated file

Prerequisites
This script requires a modern version of PowerShell (v5.1 or newer) and an internet connection to install the necessary Microsoft Graph modules on first run if needed

Installation & Usage
Simply download the .ps1 file to your machine. The script will automatically check for and install the required PowerShell modules when you run it for the first time:
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.DirectoryManagement"

Example 1: Full Report with Ownership Check
This command generates a full report for all users, including the time-consuming ownership check for applications and service principals. It also identifies service accounts that have "svc-" or "sa-" in their User Principal Name (UPN).

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode Full -DaysInactive 180 -UserServiceAccountNamesLike "svc-", "sa-" -CheckOwnership
Example 2: Summary Report Only
This command runs the script in Summary mode, which is faster as it only generates the aggregated domain report.

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode Summary
Example 3: Full Report without Ownership
This command runs the script in Full mode, focusing on user activity and identifying service accounts without performing the detailed ownership analysis.

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode Full -DaysInactive 90 -UserServiceAccountNamesLike "svc-", "sa-"
Parameters
Parameter	Type	Default	Description
UserServiceAccountNamesLike	string[]	None	An array of strings used to identify service accounts by matching patterns in their UPN.
Mode	string	"Full"	Specifies the report type. Options are "Full" or "Summary".
DaysInactive	int	180	The number of days of inactivity to check for when identifying inactive users.
CheckOwnership	switch	None	When present, the script performs additional, more time-consuming calls to count the number of applications and service principals owned by each user.

Exporter vers Sheets
Output
The script creates a dedicated folder named EntraReports in the same directory it's executed from. Inside, you will find:

CSV Files: Detailed CSV files for each report, which can be easily imported into Excel or other data analysis tools.

HTML Files: A single-file HTML report ready for sharing or archival.

Log File: An audit log of the script's execution, named EntraAudit_YYYYMMDD_HHMMSS.log, for easy troubleshooting.

Customization
The HTML report's appearance can be customized by editing the CSS styles or replacing the Base64-encoded SVG logo data directly within the Export-HtmlReport function.

License
This project is licensed under the MIT License.

Author
Aymeric Jaouen