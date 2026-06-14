# PSNvdRoH

_A PowerShell module and C# library for querying the National Vulnerability Database (NVD)._

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [How to Use](#how-to-use)
   - [Basic Usage](#basic-usage)
   - [Examples](#examples)
4. [Documentation](#documentation)
5. [License](#license)

## Introduction

PSNvdRoH is a comprehensive solution for security vulnerability research and infrastructure security assessments. It provides a PowerShell module that wraps a C# library to query the National Vulnerability Database (NVD), making it easy to integrate vulnerability information into your automation workflows.

### What can you do with PSNvdRoH?

- **Query CVEs by multiple criteria**: Search by keyword, CVE ID, CPE name, severity level, and more
- **Filter by vulnerability severity**: CVSS v2, v3, and v4 severity ratings
- **Check CISA's Known Exploited Vulnerabilities (KEV)**: Identify actively exploited vulnerabilities
- **Find CERT/CC alerts and notes**: Stay informed about critical vulnerability disclosures
- **Pagination support**: Handle large result sets efficiently
- **Date range filtering**: Find vulnerabilities published or modified within specific periods

Whether you're planning infrastructure deployments, conducting security compliance assessments, or automating vulnerability management workflows, PSNvdRoH integrates seamlessly into your PowerShell automation.

## Installation

### Prerequisites

- **PowerShell**: PowerShell Core 7.0+
- **Operating Systems**: Windows, Linux, Mac
- **.NET Runtime**: .NET 8.0+ (for the C# library)
- **NVD API Key** (optional): Get one from [NVD][Get an API Key]
  - Without API key: 10 requests per 1 hour
  - With API key: 120 requests per 1 hour

### Step 1: Clone or Download the Repository

Using Git:
```powershell
git clone "https://github.com/IT-Administrators/PSNvdRoH.git"
cd PSNvdRoH
```

Or download the ZIP archive:
```powershell
Invoke-WebRequest -Uri "https://github.com/IT-Administrators/PSNvdRoH/archive/refs/heads/main.zip" -OutFile "PSNvdRoH.zip"
Expand-Archive -Path ".\PSNvdRoH.zip"
cd PSNvdRoH-main
```

### Step 2: Import the Module

**Option A: Import from current directory**
```powershell
Import-Module -Path ".\PSNvdRoH.psm1" -Force -Verbose
```

**Option B: Copy to your module directory for automatic loading**

Find your module directory:
```powershell
$env:PSModulePath
```

Copy the PSNvdRoH files (PSNvdRoH.psm1, dist/) to one of these directories, then the module will automatically import on future PowerShell sessions.

### Step 3: Verify Installation

```powershell
# Check if the module is loaded
Get-Module PSNvdRoH

# View available commands
Get-Command -Module PSNvdRoH

# Get detailed help
Get-Help Get-NvdCve -Full
```

## How to Use

### Basic Usage

The main cmdlet is `Get-NvdCve`, which provides a PowerShell-friendly interface to the NVD API.

#### Syntax

```powershell
# Example parameters
Get-NvdCve [[-ApiKey] <string>] [-KeywordSearch <string[]>] [-CveID <string>] 
           [-CpeName <string>] [-CvssV3Severity <string>] [-NoRejected] 
           [-StartIndex <int>] [-ResultsPerPage <int>] [<CommonParameters>]
```

### Examples

#### 1. Get CVEs by Keyword

Search for vulnerabilities related to a specific product:

```powershell
# Search for Apache vulnerabilities
Get-NvdCve -KeywordSearch "Apache" -ResultsPerPage 10

# Search for multiple keywords
Get-NvdCve -KeywordSearch "SQL", "injection" -ResultsPerPage 20
```

#### 2. Get a Specific CVE by ID

```powershell
# Get details for a specific CVE
Get-NvdCve -CveID "CVE-2023-12345"
```

#### 3. Filter by CVSS Severity

Find critical vulnerabilities:

```powershell
# Find all CRITICAL severity CVEs (CVSS v3)
Get-NvdCve -CvssV3Severity "CRITICAL" -StartIndex 0 -ResultsPerPage 100

# Find HIGH severity CVEs
Get-NvdCve -CvssV3Severity "HIGH" -NoRejected -ResultsPerPage 50
```

#### 4. Filter by CPE (Common Platform Enumeration)

Find vulnerabilities affecting specific products:

```powershell
# Find CVEs affecting a specific product
Get-NvdCve -CpeName "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"

# Use strict CPE matching
Get-NvdCve -CpeName "cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*" -CpeMatchString $true
```

#### 5. Check CISA's Known Exploited Vulnerabilities (KEV)

Find actively exploited vulnerabilities:

```powershell
# Get CVEs in the CISA KEV catalog
Get-NvdCve -HasKev $true -ResultsPerPage 50

# Get CVEs added to KEV catalog in a specific time period
Get-NvdCve -HasKev $true -KevStartDate (Get-Date).AddMonths(-1) -KevEndDate (Get-Date) -ResultsPerPage 100
```

#### 6. Date Range Filtering

Find recently published or modified CVEs:

```powershell
# CVEs published in the last 30 days
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date
Get-NvdCve -PubStartDate $startDate -PubEndDate $endDate -ResultsPerPage 100

# CVEs modified in the last 7 days
$lastWeek = (Get-Date).AddDays(-7)
Get-NvdCve -LastModStartDate $lastWeek -LastModEndDate (Get-Date) -ResultsPerPage 50
```

#### 7. Pagination

Handle large result sets:

```powershell
# Get the first 100 results
Get-NvdCve -KeywordSearch "Windows" -StartIndex 0 -ResultsPerPage 100

# Get the next 100 results
Get-NvdCve -KeywordSearch "Windows" -StartIndex 100 -ResultsPerPage 100
```

To iterate over all results you need to wrap the ```Get-NvdCve``` function in a loop.

#### 8. Combined Filters

Use multiple filters together:

```powershell
# Find critical Windows vulnerabilities published in the last month
$startDate = (Get-Date).AddMonths(-1)
Get-NvdCve -KeywordSearch "Windows" `
           -CvssV3Severity "CRITICAL" `
           -PubStartDate $startDate `
           -PubEndDate (Get-Date) `
           -NoRejected `
           -ResultsPerPage 50
```

#### 9. Using an API Key

Increase request limits with an API key:

```powershell
# Store your API key securely
$apiKey = "your-nvd-api-key-here"

# Use it in your queries
Get-NvdCve -ApiKey $apiKey -KeywordSearch "critical" -ResultsPerPage 200
```

### Parameter Reference

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `ApiKey` | string | NVD API key for increased rate limits | `"abc123def456"` |
| `KeywordSearch` | string[] | Free-text search in CVE descriptions | `"Apache"` |
| `KeywordExactMatch` | switch | Require exact phrase match | `-KeywordExactMatch` |
| `CveID` | string | Specific CVE identifier | `"CVE-2023-12345"` |
| `CpeName` | string | Common Platform Enumeration filter | `"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"` |
| `CpeMatchString` | switch | Use strict CPE matching | `-CpeMatchString` |
| `CvssV2Severity` | string | CVSS v2 severity (LOW, MEDIUM, HIGH) | `"HIGH"` |
| `CvssV3Severity` | string | CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL) | `"CRITICAL"` |
| `CvssV4Severity` | string | CVSS v4 severity (LOW, MEDIUM, HIGH, CRITICAL) | `"CRITICAL"` |
| `PubStartDate` | datetime | CVE publication date range start | `(Get-Date).AddDays(-30)` |
| `PubEndDate` | datetime | CVE publication date range end | `(Get-Date)` |
| `LastModStartDate` | datetime | CVE modification date range start | `(Get-Date).AddDays(-7)` |
| `LastModEndDate` | datetime | CVE modification date range end | `(Get-Date)` |
| `HasKev` | switch | Only CVEs in CISA KEV catalog | `-HasKev` |
| `HasCertAlerts` | switch | Only CVEs with CERT/CC alerts | `-HasCertAlerts` |
| `HasCertNotes` | switch | Only CVEs with CERT/CC notes | `-HasCertNotes` |
| `HasOval` | switch | Only CVEs with OVAL definitions | `-HasOval` |
| `NoRejected` | switch | Exclude rejected CVEs | `-NoRejected` |
| `ResultsPerPage` | int | Number of results per page (1-2000) | `100` |
| `StartIndex` | int | Pagination starting index (0+) | `0` |

## Documentation

For detailed technical documentation including:
- Complete class and method reference
- Architecture overview
- Development guide

See the [docs][Docs] folder.

## License

[MIT License][License]

---

[National Vulnerability Database (NVD)]: https://nvd.nist.gov/
[NVD API Documentation]: https://nvd.nist.gov/developers/vulnerabilities
[Get an API Key]: https://nvd.nist.gov/developers/request-an-api-key
[CISA Known Exploited Vulnerabilities]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[Docs]: docs/
[License]: ./LICENSE