<!-- toc:insertAfterHeading=PSNvdRoH Architecture & Design-->
<!-- toc:insertAfterHeadingOffset=1 -->

# PSNvdRoH Architecture & Design

## Table of Contents

1. [Project Overview](#project-overview)
    1. [Component Statistics](#component-statistics)
1. [Architecture Diagram](#architecture-diagram)
1. [Component Details](#component-details)
    1. [PowerShell Layer](#powershell-layer)
        1. [`Get-NvdCve` Cmdlet](#get-nvdcve-cmdlet)
        1. [`Invoke-NvdApi` Helper Function](#invoke-nvdapi-helper-function)
    1. [C# Library Layer](#c-library-layer)
        1. [`NvdApiClient` Class](#nvdapiclient-class)
        1. [`CveQueryParameters` Class](#cvequeryparameters-class)
        1. [`QueryStringBuilder` Class](#querystringbuilder-class)
        1. [`CveTag` Enum](#cvetag-enum)
        1. [`CvssV2Severity` Enum](#cvssv2severity-enum)
        1. [`CvssV3Severity` Enum](#cvssv3severity-enum)
        1. [`CvssV4Severity` Enum](#cvssv4severity-enum)
    1. [Testing Layer](#testing-layer)
        1. [`QueryStringBuilderTests` Class](#querystringbuildertests-class)
1. [Design Patterns & Principles](#design-patterns-principles)
    1. [1. **Separation of Concerns**](#1-separation-of-concerns)
    1. [2. **Strong Typing**](#2-strong-typing)
    1. [3. **Two-Tier Validation**](#3-two-tier-validation)
    1. [4. **Async-to-Sync Bridge**](#4-async-to-sync-bridge)
    1. [5. **Immutable Enums with Attributes**](#5-immutable-enums-with-attributes)
1. [Data Flow](#data-flow)
    1. [Typical Query Execution](#typical-query-execution)
1. [Error Handling Strategy](#error-handling-strategy)
    1. [Category: InvalidArgument](#category-invalidargument)
    1. [Category: ConnectionError](#category-connectionerror)
    1. [Category: NotSpecified](#category-notspecified)
1. [Performance Considerations](#performance-considerations)
    1. [Rate Limiting](#rate-limiting)
    1. [Pagination](#pagination)
    1. [Memory](#memory)
1. [Future Enhancement Opportunities](#future-enhancement-opportunities)

## Project Overview

PSNvdRoH is a layered solution that combines C# and PowerShell to provide a robust interface for querying the National Vulnerability Database (NVD) API v2.0.

### Component Statistics

**Total Components:**
- **7 Classes** (including enums)
- **2 Public Functions/Cmdlets** (1 public, 1 internal helper)
- **18+ Public Methods and Properties**
- **7 Unit Tests**

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│   PowerShell Layer (PSNvdRoH.psm1)                  │
│   ┌──────────────────────────────────────────────┐  │
│   │ Get-NvdCve (Public Cmdlet)                    │  │
│   │ - Friendly PowerShell parameters              │  │
│   │ - Parameter validation & error handling       │  │
│   │ - JSON parsing and output formatting          │  │
│   └──────────────────────────────────────────────┘  │
│   ┌──────────────────────────────────────────────┐  │
│   │ Invoke-NvdApi (Private Helper)                │  │
│   │ - Async-to-sync wrapper                       │  │
│   │ - Raw API response handling                   │  │
│   └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│   C# Library Layer (NvdClient/)                      │
│   ┌──────────────────────────────────────────────┐  │
│   │ NvdApiClient                                  │  │
│   │ - HTTP communication with NVD API             │  │
│   │ - API key management                         │  │
│   │ - Returns raw JSON responses                  │  │
│   └──────────────────────────────────────────────┘  │
│   ┌──────────────────────────────────────────────┐  │
│   │ QueryStringBuilder (Static)                   │  │
│   │ - Converts parameters to query strings        │  │
│   │ - Validates parameter constraints             │  │
│   │ - Formats dates and enums                     │  │
│   └──────────────────────────────────────────────┘  │
│   ┌──────────────────────────────────────────────┐  │
│   │ CveQueryParameters (Data Class)               │  │
│   │ - Holds all supported API parameters          │  │
│   │ - Type-safe property definitions              │  │
│   └──────────────────────────────────────────────┘  │
│   ┌──────────────────────────────────────────────┐  │
│   │ Severity Enums (CvssV2, V3, V4)              │  │
│   │ - Type-safe severity values                   │  │
│   └──────────────────────────────────────────────┘  │
│   ┌──────────────────────────────────────────────┐  │
│   │ CveTag Enum                                   │  │
│   │ - CVE tag filter values                       │  │
│   └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│   NVD REST API                                      │
│   https://services.nvd.nist.gov/rest/json/cves/2.0 │
└─────────────────────────────────────────────────────┘
```

---

## Component Details

### PowerShell Layer

#### `Get-NvdCve` Cmdlet
**File:** [PSNvdRoH.psm1][PSModule]

**Purpose:** Main entry point for PowerShell users. Provides user-friendly parameter names and validation, converts PowerShell parameters to C# objects, and formats API responses.

**Key Responsibilities:**
- Accept PowerShell parameters with proper type validation
- Create and populate `CveQueryParameters` object
- Call C# `NvdApiClient` to fetch data
- Parse JSON response and return as PowerShell objects
- Handle errors with categorized error messages (InvalidArgument, ConnectionError, NotSpecified)
- Support all 20+ NVD API query parameters

**Key Parameters:**
- Filtering: `KeywordSearch`, `CveID`, `CpeName`, `CveTag`
- Severity: `CvssV2Severity`, `CvssV3Severity`, `CvssV4Severity`
- Metrics: `CvssV2Metrics`, `CvssV3Metrics`, `CvssV4Metrics`
- Dates: `PubStartDate`, `PubEndDate`, `LastModStartDate`, `LastModEndDate`, `KevStartDate`, `KevEndDate`
- Flags: `NoRejected`, `HasCertAlerts`, `HasCertNotes`, `HasKev`, `HasOval`, `IsVulnerable`
- Pagination: `StartIndex`, `ResultsPerPage`
- Authentication: `ApiKey`

---

#### `Invoke-NvdApi` Helper Function
**File:** [PSNvdRoH.psm1][PSModule]

**Purpose:** Internal helper that converts asynchronous C# calls to synchronous PowerShell execution.

**Responsibilities:**
- Accept `NvdApiClient` instance and `CveQueryParameters`
- Execute `GetCvesAsync()` and wait for completion
- Handle async task completion
- Return raw JSON string to caller

---

### C# Library Layer

#### `NvdApiClient` Class
**File:** [NvdClient/NvdApiClient.cs][Nvdclient/Nvdapiclient]

**Purpose:** High-level HTTP client for NVD CVE API v2.0 communication.

**Public Methods:**
- `NvdApiClient(string? apiKey = null)` — Constructor; initializes HttpClient and configures API key if provided
- `Task<string> GetCvesAsync(CveQueryParameters parameters)` — Executes async HTTP request to NVD API; builds query string, adds headers, and returns raw JSON response

**Key Responsibilities:**
- Manage HTTP communication with NVD API
- Attach optional API key to requests for increased rate limits
- Return unmodified JSON responses
- Handle HTTP errors and timeouts

**Dependencies:**
- `QueryStringBuilder` — for converting parameters to query strings
- `System.Net.Http.HttpClient` — for HTTP communication

---

#### `CveQueryParameters` Class
**File:** [NvdClient/CveQueryParameters.cs][Nvdclient/Cvequeryparameters]

**Purpose:** Strongly-typed data container for all NVD CVE API v2.0 query parameters.

**Public Properties:**
- **Search Filters:**
  - `string[]? KeywordSearch` — Free-text search across CVE descriptions
  - `string? CveID` — Specific CVE identifier
  - `string? CpeName` — Common Platform Enumeration filter
  - `string? SourceIdentifier` — Vulnerability source identifier

- **CVSS Severity Filters:**
  - `CvssV2Severity? CvssV2Severity` — CVSS v2 severity (LOW, MEDIUM, HIGH)
  - `CvssV3Severity? CvssV3Severity` — CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
  - `CvssV4Severity? CvssV4Severity` — CVSS v4 severity (LOW, MEDIUM, HIGH, CRITICAL)

- **CVSS Metrics:**
  - `string? CvssV2Metrics` — CVSS v2 metrics filter
  - `string? CvssV3Metrics` — CVSS v3 metrics filter
  - `string? CvssV4Metrics` — CVSS v4 metrics filter

- **Date Range Filters:**
  - `DateTime? PubStartDate` / `DateTime? PubEndDate` — CVE publication date range
  - `DateTime? LastModStartDate` / `DateTime? LastModEndDate` — CVE modification date range
  - `DateTime? KevStartDate` / `DateTime? KevEndDate` — CISA KEV catalog addition date range

- **Flags:**
  - `bool? KeywordExactMatch` — Require exact phrase matching
  - `bool? CpeMatchString` — Use strict CPE matching
  - `bool? NoRejected` — Exclude rejected CVEs
  - `bool? HasCertAlerts` — Only CVEs with CERT/CC alerts
  - `bool? HasCertNotes` — Only CVEs with CERT/CC notes
  - `bool? HasKev` — Only CVEs in CISA KEV catalog
  - `bool? HasOval` — Only CVEs with OVAL definitions
  - `bool? IsVulnerable` — Only vulnerable products

- **Tags:**
  - `CveTag? CveTag` — CVE tag filter (Disputed, UnsupportedWhenAssigned, ExclusivelyHostedService)

- **Pagination:**
  - `int? ResultsPerPage` — Number of results (1-2000)
  - `int? StartIndex` — Pagination offset (0+)

**Design Pattern:** Data Transfer Object (DTO) — no methods, only properties.

---

#### `QueryStringBuilder` Class
**File:** [NvdClient/QueryStringBuilder.cs][Nvdclient/Querystringbuilder]

**Purpose:** Converts strongly-typed `CveQueryParameters` into validated, URL-encoded NVD-compliant query strings.

**Public Methods:**
- `static string ToQueryString(CveQueryParameters p)` — Main method; validates all parameters, serializes supported parameters to query string format, returns "?" prefix if parameters exist, empty string otherwise

**Private Methods:**
- `GetEnumValue(object enumValue)` — Extracts enum value using `[EnumMember]` attribute for API compliance
- `ValidateParameters(CveQueryParameters p)` — Validates parameter constraints

**Validation Rules:**
- **Mutually Exclusive Parameters:**
  - Cannot use multiple CVSS v2/v3/v4 severity filters simultaneously
  - Cannot use multiple CVSS v2/v3/v4 metrics filters simultaneously
  - `IsVulnerable` requires `CpeName` to be specified

- **Date Range Pairs:**
  - `PubStartDate` requires `PubEndDate` and vice versa
  - `LastModStartDate` requires `LastModEndDate` and vice versa
  - `KevStartDate` requires `KevEndDate` and vice versa

- **Parameter Dependencies:**
  - `KeywordExactMatch` requires `KeywordSearch` to be specified

**Date Format:**
- All dates are formatted in UTC with "Z" suffix: `yyyy-MM-ddTHH:mm:ssZ`

---

#### `CveTag` Enum
**File:** [NvdClient/CveTag.cs][Nvdclient/Cvetag]

**Purpose:** Type-safe enum for CVE tag filter values.

**Values:**
- `Disputed` → maps to "disputed"
- `UnsupportedWhenAssigned` → maps to "unsupported-when-assigned"
- `ExclusivelyHostedService` → maps to "exclusively-hosted-service"

**Design:** Uses `[EnumMember]` attributes for API-compatible string serialization.

---

#### `CvssV2Severity` Enum
**File:** [NvdClient/CvssV2Severity.cs][Nvdclient/Cvssv2severity]

**Purpose:** Type-safe enum for CVSS v2 severity ratings.

**Values:** `LOW`, `MEDIUM`, `HIGH`

---

#### `CvssV3Severity` Enum
**File:** [NvdClient/CvssV3Severity.cs][Nvdclient/Cvssv3severity]

**Purpose:** Type-safe enum for CVSS v3 severity ratings.

**Values:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

#### `CvssV4Severity` Enum
**File:** [NvdClient/CvssV4Severity.cs][Nvdclient/Cvssv4severity]

**Purpose:** Type-safe enum for CVSS v4 severity ratings.

**Values:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

### Testing Layer

#### `QueryStringBuilderTests` Class
**File:** [NvdClient.Tests/QueryStringBuilderTests.cs][Nvdclient.Tests/Querystringbuildertests]

**Purpose:** XUnit test suite for `QueryStringBuilder` validation logic and functionality.

**Test Methods:**
1. `ToQueryString_IncludesAllSupportedParameters()` — Verifies all parameters serialize correctly
2. `ToQueryString_ThrowsWhenMultipleMetricParametersAreSpecified()` — Tests mutual exclusivity of CVSS metrics
3. `ToQueryString_ThrowsWhenMultipleSeverityParametersAreSpecified()` — Tests mutual exclusivity of CVSS severity
4. `ToQueryString_ThrowsWhenPubDatePairIsIncomplete()` — Tests publication date pair validation
5. `ToQueryString_ThrowsWhenLastModDatePairIsIncomplete()` — Tests modification date pair validation
6. `ToQueryString_ThrowsWhenKeywordExactMatchWithoutKeywords()` — Tests keyword requirement validation
7. `ToQueryString_ThrowsWhenIsVulnerableWithoutCpeName()` — Tests CPE requirement validation

**Framework:** XUnit

---

## Design Patterns & Principles

### 1. **Separation of Concerns**
- **HTTP Communication:** Handled by `NvdApiClient` only
- **Parameter Building:** Handled by `QueryStringBuilder` only
- **Data Model:** Defined in `CveQueryParameters`
- **PowerShell Interface:** Managed by `Get-NvdCve` cmdlet

### 2. **Strong Typing**
- Enums for severity and tags prevent invalid values
- Nullable types for optional parameters
- Type-safe parameter object

### 3. **Two-Tier Validation**
- **C# Validation:** `QueryStringBuilder.ValidateParameters()` enforces API constraints
- **PowerShell Validation:** `Get-NvdCve` uses `ValidateSet` attributes and parameter sets

### 4. **Async-to-Sync Bridge**
- `Invoke-NvdApi` helper converts C# async operations to PowerShell's synchronous context

### 5. **Immutable Enums with Attributes**
- `[EnumMember]` attributes ensure correct API string values
- Enum values are case-insensitive to PowerShell users

---

## Data Flow

### Typical Query Execution

1. **User calls PowerShell:**
   ```powershell
   Get-NvdCve -KeywordSearch "Apache" -CvssV3Severity "CRITICAL"
   ```

2. **PowerShell parameter binding:**
   - Parameter validation via `ValidateSet`, `ValidateRange`, etc.
   - Create `CveQueryParameters` object with user values

3. **Create API client:**
   - Instantiate `NvdApiClient` with optional API key

4. **Query string building:**
   - Call `QueryStringBuilder.ToQueryString($parameters)`
   - Validate parameter combinations
   - Serialize supported parameters to query string
   - Example output: `?keywordSearch=Apache&cvssV3Severity=CRITICAL`

5. **HTTP request:**
   - `NvdApiClient.GetCvesAsync()` called with query string
   - HTTP GET request to NVD API endpoint
   - Response headers include rate limit information

6. **Response handling:**
   - Raw JSON string received from NVD API
   - Returned to PowerShell layer

7. **Output formatting:**
   - PowerShell parses JSON via `ConvertFrom-Json`
   - Results displayed to console or piped to other cmdlets

---

## Error Handling Strategy

### Category: InvalidArgument
- Conflicting parameters (e.g., multiple severity filters)
- Missing required parameter pairs (e.g., start date without end date)
- Invalid parameter values

### Category: ConnectionError
- HTTP connection failures
- Timeout errors
- API server errors (5xx)

### Category: NotSpecified
- Unexpected errors or null references

---

## Performance Considerations

### Rate Limiting
- **Without API Key:** 10 requests per 1 hour
- **With API Key:** 120 requests per 1 hour
- Implement request batching for large operations

### Pagination
- Maximum results per page: 2000
- Use `StartIndex` and `ResultsPerPage` for efficient large result set handling

### Memory
- Raw JSON responses can be large; consider streaming for bulk operations
- PowerShell's `ConvertFrom-Json` loads entire responses into memory

---

## Future Enhancement Opportunities

1. **Async PowerShell Support:** Implement `Get-NvdCveAsync` for PowerShell 7+ native async
2. **Caching Layer:** Add response caching to reduce API calls
3. **Batch Processing:** Implement helper functions for querying multiple keywords
4. **Export Formats:** Add JSON, CSV, Excel export options
5. **CPE Enumeration:** Expand CPE API v2.0 support beyond current CVE focus
6. **CVE Severity Trending:** Helper functions to analyze vulnerability trends over time

[PSModule]: ../PSNvdRoH.psm1
[Nvdclient/Nvdapiclient]: ../NvdClient/NvdApiClient.cs
[Nvdclient/Cvequeryparameters]: ../NvdClient/CveQueryParameters.cs
[Nvdclient/Querystringbuilder]: ../NvdClient/QueryStringBuilder.cs
[Nvdclient/Cvetag]: ../NvdClient/CveTag.cs
[Nvdclient/Cvssv2severity]: ../NvdClient/CvssV2Severity.cs
[Nvdclient/Cvssv3severity]: ../NvdClient/CvssV3Severity.cs
[Nvdclient/Cvssv4severity]: ../NvdClient/CvssV4Severity.cs
[Nvdclient.Tests/Querystringbuildertests]: ../NvdClient.Tests/QueryStringBuilderTests.cs