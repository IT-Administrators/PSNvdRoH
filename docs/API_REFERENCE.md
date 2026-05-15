<!-- toc:insertAfterHeading= -->
<!-- toc:insertAfterHeadingOffset=0 -->
# Table of Contents

1. [API Reference](#api-reference)
    1. [Summary](#summary)
    1. [PowerShell Functions](#powershell-functions)
        1. [Public Cmdlets](#public-cmdlets)
            1. [`Get-NvdCve`](#get-nvdcve)
        1. [Private Functions](#private-functions)
            1. [`Invoke-NvdApi`](#invoke-nvdapi)
    1. [C# Classes](#c-classes)
        1. [Core Classes](#core-classes)
            1. [`NvdApiClient`](#nvdapiclient)
                1. [Constructor](#constructor)
                1. [GetCvesAsync](#getcvesasync)
            1. [`CveQueryParameters`](#cvequeryparameters)
                1. [Search & Filter Properties](#search-filter-properties)
                1. [CVSS Severity Properties](#cvss-severity-properties)
                1. [CVSS Metrics Properties](#cvss-metrics-properties)
                1. [Date Range Properties](#date-range-properties)
                1. [Filter Flag Properties](#filter-flag-properties)
                1. [Pagination Properties](#pagination-properties)
            1. [`QueryStringBuilder`](#querystringbuilder)
                1. [ToQueryString](#toquerystring)
    1. [Enum Types](#enum-types)
        1. [`CveTag`](#cvetag)
        1. [`CvssV2Severity`](#cvssv2severity)
        1. [`CvssV3Severity`](#cvssv3severity)
        1. [`CvssV4Severity`](#cvssv4severity)
    1. [Test Classes](#test-classes)
        1. [`QueryStringBuilderTests`](#querystringbuildertests)
    1. [File Structure Reference](#file-structure-reference)
    1. [Quick Reference](#quick-reference)
        1. [Creating an NVD Query in C#](#creating-an-nvd-query-in-c)
        1. [Using the PowerShell Cmdlet](#using-the-powershell-cmdlet)


# API Reference

Comprehensive documentation of all classes, methods, functions, and their locations.

## Summary

| Category | Count |
|----------|-------|
| **Classes** | 5 |
| **Enums** | 4 |
| **Public Methods** | 2 |
| **Public Cmdlets** | 1 |
| **Private Functions** | 1 |
| **Test Classes** | 1 |
| **Unit Tests** | 7 |

---

## PowerShell Functions

### Public Cmdlets

#### `Get-NvdCve`
**File:** [PSNvdRoH.psm1][PSModule]  
**Type:** Advanced Cmdlet  
**Purpose:** Query the National Vulnerability Database (NVD) CVE API v2.0

**Signature:**
```powershell
Get-NvdCve [[-ApiKey] <string>] 
           [-KeywordSearch <string[]>] 
           [-CveID <string>]
           [-CpeName <string>]
           [-CveTag <string>]
           [-CvssV2Severity <string>]
           [-CvssV3Severity <string>]
           [-CvssV4Severity <string>]
           [-CvssV2Metrics <string>]
           [-CvssV3Metrics <string>]
           [-CvssV4Metrics <string>]
           [-CpeMatchString <bool>]
           [-KeywordExactMatch <bool>]
           [-NoRejected <switch>]
           [-PubStartDate <datetime>]
           [-PubEndDate <datetime>]
           [-LastModStartDate <datetime>]
           [-LastModEndDate <datetime>]
           [-KevStartDate <datetime>]
           [-KevEndDate <datetime>]
           [-SourceIdentifier <string>]
           [-HasCertAlerts <switch>]
           [-HasCertNotes <switch>]
           [-HasKev <switch>]
           [-HasOval <switch>]
           [-IsVulnerable <switch>]
           [-ResultsPerPage <int>]
           [-StartIndex <int>]
           [<CommonParameters>]
```

**Parameters:**

| Name | Type | Required | Description | Example |
|------|------|----------|-------------|---------|
| `ApiKey` | string | No | NVD API key for rate limit increase | `"abc123"` |
| `KeywordSearch` | string[] | No | Free-text keyword search | `"Apache"` |
| `KeywordExactMatch` | bool | No | Require exact phrase | `$true` |
| `CveID` | string | No | Specific CVE identifier | `"CVE-2023-1234"` |
| `CpeName` | string | No | CPE filter | `"cpe:2.3:a:apache:*:*:*"` |
| `CpeMatchString` | bool | No | Strict CPE matching | `$true` |
| `CvssV2Severity` | string | No | CVSS v2 severity (LOW, MEDIUM, HIGH) | `"HIGH"` |
| `CvssV3Severity` | string | No | CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL) | `"CRITICAL"` |
| `CvssV4Severity` | string | No | CVSS v4 severity (LOW, MEDIUM, HIGH, CRITICAL) | `"CRITICAL"` |
| `CvssV2Metrics` | string | No | CVSS v2 metrics query | `"AV:N/AC:L"` |
| `CvssV3Metrics` | string | No | CVSS v3 metrics query | `"CVSS:3.1/AV:N"` |
| `CvssV4Metrics` | string | No | CVSS v4 metrics query | `"CVSS:4.0/AV:N"` |
| `PubStartDate` | datetime | No | Publication start date | `(Get-Date).AddDays(-30)` |
| `PubEndDate` | datetime | No | Publication end date | `(Get-Date)` |
| `LastModStartDate` | datetime | No | Modification start date | `(Get-Date).AddDays(-7)` |
| `LastModEndDate` | datetime | No | Modification end date | `(Get-Date)` |
| `KevStartDate` | datetime | No | KEV catalog addition start | `(Get-Date).AddMonths(-1)` |
| `KevEndDate` | datetime | No | KEV catalog addition end | `(Get-Date)` |
| `SourceIdentifier` | string | No | Vulnerability source | `"NVD"` |
| `NoRejected` | switch | No | Exclude rejected CVEs | `-NoRejected` |
| `HasCertAlerts` | switch | No | Only with CERT alerts | `-HasCertAlerts` |
| `HasCertNotes` | switch | No | Only with CERT notes | `-HasCertNotes` |
| `HasKev` | switch | No | Only in CISA KEV | `-HasKev` |
| `HasOval` | switch | No | Only with OVAL | `-HasOval` |
| `IsVulnerable` | switch | No | Only vulnerable products | `-IsVulnerable` |
| `ResultsPerPage` | int | No | Results per page (1-2000) | `100` |
| `StartIndex` | int | No | Pagination offset | `0` |

**Returns:** PSCustomObject array with CVE data

**Error Categories:**
- `InvalidArgument` — Parameter validation failed
- `ConnectionError` — API communication failed
- `NotSpecified` — Unexpected error

**Examples:**
```powershell
# Simple keyword search
Get-NvdCve -KeywordSearch "Apache"

# Critical vulnerabilities
Get-NvdCve -CvssV3Severity "CRITICAL" -NoRejected

# With pagination
Get-NvdCve -KeywordSearch "Windows" -StartIndex 0 -ResultsPerPage 100
```

---

### Private Functions

#### `Invoke-NvdApi`
**File:** [PSNvdRoH.psm1][PSModule]  
**Type:** Helper Function  
**Purpose:** Execute async C# API call and return result

**Signature:**
```powershell
Invoke-NvdApi -Client <NvdApiClient> -Params <CveQueryParameters>
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `Client` | NvdApiClient | Instantiated API client |
| `Params` | CveQueryParameters | Query parameters object |

**Returns:** string (raw JSON response)

**Internal Use Only:** Called by `Get-NvdCve` to bridge async C# to sync PowerShell

---

## C# Classes

### Core Classes

#### `NvdApiClient`
**File:** [NvdClient/NvdApiClient.cs][Nvdclient/Nvdapiclient]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** HTTP client for NVD API communication

**Public Methods:**

##### Constructor
```csharp
public NvdApiClient(string? apiKey = null)
```
- **Parameters:**
  - `apiKey` (string, optional) — NVD API key for rate limit increase
- **Description:** Initializes HTTP client and configures API key if provided
- **Example:**
  ```csharp
  var client = new NvdApiClient();  // Without API key
  var client = new NvdApiClient("your-api-key");  // With API key
  ```

##### GetCvesAsync
```csharp
public Task<string> GetCvesAsync(CveQueryParameters parameters)
```
- **Parameters:**
  - `parameters` (CveQueryParameters) — Query parameters
- **Returns:** Task<string> — Raw JSON response from NVD API
- **Description:** Executes asynchronous HTTP GET request to NVD API v2.0 endpoint
- **Throws:** HttpRequestException on network errors
- **Example:**
  ```csharp
  var client = new NvdApiClient("api-key");
  var parameters = new CveQueryParameters { KeywordSearch = new[] { "Apache" } };
  var jsonResponse = await client.GetCvesAsync(parameters);
  ```

---

#### `CveQueryParameters`
**File:** [NvdClient/CveQueryParameters.cs][Nvdclient/Cvequeryparameters]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** Strongly-typed data container for NVD API query parameters

**Public Properties:**

##### Search & Filter Properties
| Property | Type | Description |
|----------|------|-------------|
| `KeywordSearch` | string[]? | Free-text keywords (CVE descriptions) |
| `KeywordExactMatch` | bool? | Exact phrase matching |
| `CveID` | string? | Specific CVE identifier |
| `CpeName` | string? | CPE (Common Platform Enumeration) |
| `CpeMatchString` | bool? | Strict CPE matching |
| `SourceIdentifier` | string? | Vulnerability source identifier |
| `CveTag` | CveTag? | CVE tag filter (Disputed, etc.) |

##### CVSS Severity Properties
| Property | Type | Valid Values | Description |
|----------|------|--------------|-------------|
| `CvssV2Severity` | CvssV2Severity? | LOW, MEDIUM, HIGH | CVSS v2 severity |
| `CvssV3Severity` | CvssV3Severity? | LOW, MEDIUM, HIGH, CRITICAL | CVSS v3 severity |
| `CvssV4Severity` | CvssV4Severity? | LOW, MEDIUM, HIGH, CRITICAL | CVSS v4 severity |

##### CVSS Metrics Properties
| Property | Type | Description |
|----------|------|-------------|
| `CvssV2Metrics` | string? | CVSS v2 metrics string |
| `CvssV3Metrics` | string? | CVSS v3 metrics string |
| `CvssV4Metrics` | string? | CVSS v4 metrics string |

##### Date Range Properties
| Property | Type | Description |
|----------|------|-------------|
| `PubStartDate` | DateTime? | CVE publication start (requires PubEndDate) |
| `PubEndDate` | DateTime? | CVE publication end (requires PubStartDate) |
| `LastModStartDate` | DateTime? | CVE modification start (requires LastModEndDate) |
| `LastModEndDate` | DateTime? | CVE modification end (requires LastModStartDate) |
| `KevStartDate` | DateTime? | CISA KEV addition start (requires KevEndDate) |
| `KevEndDate` | DateTime? | CISA KEV addition end (requires KevStartDate) |

##### Filter Flag Properties
| Property | Type | Description |
|----------|------|-------------|
| `NoRejected` | bool? | Exclude rejected CVEs |
| `HasCertAlerts` | bool? | Only with CERT/CC alerts |
| `HasCertNotes` | bool? | Only with CERT/CC notes |
| `HasKev` | bool? | Only in CISA KEV catalog |
| `HasOval` | bool? | Only with OVAL definitions |
| `IsVulnerable` | bool? | Only vulnerable products |

##### Pagination Properties
| Property | Type | Range | Description |
|----------|------|-------|-------------|
| `ResultsPerPage` | int? | 1-2000 | Results per page |
| `StartIndex` | int? | 0+ | Pagination offset |

**Design Pattern:** Data Transfer Object (DTO) — contains only properties, no methods

**Example:**
```csharp
var parameters = new CveQueryParameters
{
    KeywordSearch = new[] { "Apache" },
    CvssV3Severity = CvssV3Severity.CRITICAL,
    NoRejected = true,
    ResultsPerPage = 50
};
```

---

#### `QueryStringBuilder`
**File:** [NvdClient/QueryStringBuilder.cs][Nvdclient/Querystringbuilder]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** Convert CveQueryParameters to NVD-compliant query strings with validation

**Public Methods:**

##### ToQueryString
```csharp
public static string ToQueryString(CveQueryParameters p)
```
- **Parameters:**
  - `p` (CveQueryParameters) — Parameter object to convert
- **Returns:** string — Query string with "?" prefix if parameters exist, empty string otherwise
- **Throws:**
  - `ArgumentException` — Invalid parameter combination
  - `InvalidOperationException` — Missing required parameter pairs
- **Description:** Validates parameter constraints and serializes to URL-encoded query string
- **Example:**
  ```csharp
  var parameters = new CveQueryParameters { KeywordSearch = new[] { "Apache" } };
  string queryString = QueryStringBuilder.ToQueryString(parameters);
  // Returns: "?keywordSearch=Apache"
  ```

**Validation Rules:**
- Mutually exclusive severity filters (only one CVSS version)
- Mutually exclusive metrics filters (only one CVSS version)
- Date range pairs must be complete (both start and end)
- KeywordExactMatch requires KeywordSearch
- IsVulnerable requires CpeName

**Date Format:** UTC with "Z" suffix: `yyyy-MM-ddTHH:mm:ssZ`

**Private Methods:**
- `GetEnumValue(object enumValue)` — Extracts enum value with [EnumMember] attribute
- `ValidateParameters(CveQueryParameters p)` — Validates parameter constraints

---

## Enum Types

### `CveTag`
**File:** [NvdClient/CveTag.cs][Nvdclient/Cvetag]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** CVE tag filter values

**Values:**
| Name | API Value |
|------|-----------|
| `Disputed` | "disputed" |
| `UnsupportedWhenAssigned` | "unsupported-when-assigned" |
| `ExclusivelyHostedService` | "exclusively-hosted-service" |

**Usage:**
```csharp
var parameters = new CveQueryParameters
{
    CveTag = CveTag.Disputed
};
```

---

### `CvssV2Severity`
**File:** [NvdClient/CvssV2Severity.cs][Nvdclient/Cvssv2severity]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** CVSS v2.0 severity ratings

**Values:** `LOW`, `MEDIUM`, `HIGH`

**Usage:**
```csharp
var parameters = new CveQueryParameters
{
    CvssV2Severity = CvssV2Severity.HIGH
};
```

---

### `CvssV3Severity`
**File:** [NvdClient/CvssV3Severity.cs][Nvdclient/Cvssv3severity]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** CVSS v3.0/v3.1 severity ratings

**Values:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

**Usage:**
```csharp
var parameters = new CveQueryParameters
{
    CvssV3Severity = CvssV3Severity.CRITICAL
};
```

---

### `CvssV4Severity`
**File:** [NvdClient/CvssV4Severity.cs][Nvdclient/Cvssv4severity]  
**Namespace:** PSNvdRoH.NvdClient  
**Purpose:** CVSS v4.0 severity ratings

**Values:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

**Usage:**
```csharp
var parameters = new CveQueryParameters
{
    CvssV4Severity = CvssV4Severity.CRITICAL
};
```

---

## Test Classes

### `QueryStringBuilderTests`
**File:** [NvdClient.Tests/QueryStringBuilderTests.cs][Nvdclient.Tests/Querystringbuildertests]  
**Namespace:** PSNvdRoH.NvdClient.Tests  
**Framework:** XUnit  
**Purpose:** Unit tests for QueryStringBuilder validation and serialization

**Public Test Methods:**

| Method | Validates |
|--------|-----------|
| `ToQueryString_IncludesAllSupportedParameters()` | All parameters serialize correctly |
| `ToQueryString_ThrowsWhenMultipleMetricParametersAreSpecified()` | Mutually exclusive CVSS metrics |
| `ToQueryString_ThrowsWhenMultipleSeverityParametersAreSpecified()` | Mutually exclusive CVSS severity |
| `ToQueryString_ThrowsWhenPubDatePairIsIncomplete()` | Publication date pair validation |
| `ToQueryString_ThrowsWhenLastModDatePairIsIncomplete()` | Modification date pair validation |
| `ToQueryString_ThrowsWhenKeywordExactMatchWithoutKeywords()` | Keyword requirement for exact match |
| `ToQueryString_ThrowsWhenIsVulnerableWithoutCpeName()` | CPE requirement for IsVulnerable |

**Run Tests:**
```bash
dotnet test NvdClient.Tests/NvdClient.Tests.csproj
```

---

## File Structure Reference

| File | Type | Purpose |
|------|------|---------|
| [PSNvdRoH.psm1][PSModule] | PowerShell Module | Main cmdlet implementation |
| [NvdClient/NvdApiClient.cs][Nvdclient/Nvdapiclient] | C# Class | HTTP API communication |
| [NvdClient/CveQueryParameters.cs][Nvdclient/Cvequeryparameters] | C# Class | Parameter data container |
| [NvdClient/QueryStringBuilder.cs][Nvdclient/Querystringbuilder] | C# Class | Query string building & validation |
| [NvdClient/CveTag.cs][Nvdclient/Cvetag] | C# Enum | CVE tag values |
| [NvdClient/CvssV2Severity.cs][Nvdclient/Cvssv2severity] | C# Enum | CVSS v2 severity |
| [NvdClient/CvssV3Severity.cs][Nvdclient/Cvssv3severity] | C# Enum | CVSS v3 severity |
| [NvdClient/CvssV4Severity.cs][Nvdclient/Cvssv4severity] | C# Enum | CVSS v4 severity |
| [NvdClient.Tests/QueryStringBuilderTests.cs][Nvdclient.Tests/Querystringbuildertests] | C# Test Class | Unit tests |

---

## Quick Reference

### Creating an NVD Query in C#

```csharp
// 1. Create parameters
var parameters = new CveQueryParameters
{
    KeywordSearch = new[] { "Apache" },
    CvssV3Severity = CvssV3Severity.CRITICAL,
    NoRejected = true,
    ResultsPerPage = 50,
    StartIndex = 0
};

// 2. Validate and build query string
string queryString = QueryStringBuilder.ToQueryString(parameters);
// Returns: "?keywordSearch=Apache&cvssV3Severity=CRITICAL&noRejected=&resultsPerPage=50&startIndex=0"

// 3. Create API client and execute
var client = new NvdApiClient("your-api-key");
string jsonResponse = await client.GetCvesAsync(parameters);

// 4. Parse JSON response
var cves = JsonSerializer.Deserialize<dynamic>(jsonResponse);
```

### Using the PowerShell Cmdlet

```powershell
# Search for critical Apache vulnerabilities
Get-NvdCve -KeywordSearch "Apache" `
           -CvssV3Severity "CRITICAL" `
           -NoRejected `
           -ResultsPerPage 50 `
           -ApiKey "your-api-key"
```

[PSModule]: ../PSNvdRoH.psm1
[Nvdclient/Nvdapiclient]: ../NvdClient/NvdApiClient.cs
[Nvdclient/Cvequeryparameters]: ../NvdClient/CveQueryParameters.cs
[Nvdclient/Querystringbuilder]: ../NvdClient/QueryStringBuilder.cs
[Nvdclient/Cvetag]: ../NvdClient/CveTag.cs
[Nvdclient/Cvssv2severity]: ../NvdClient/CvssV2Severity.cs
[Nvdclient/Cvssv3severity]: ../NvdClient/CvssV3Severity.cs
[Nvdclient/Cvssv4severity]: ../NvdClient/CvssV4Severity.cs
[Nvdclient.Tests/Querystringbuildertests]: ../NvdClient.Tests/QueryStringBuilderTests.cs