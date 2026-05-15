<!-- toc:insertAfterHeading= -->
<!-- toc:insertAfterHeadingOffset=0 -->
# Table of Contents

1. [Documentation Index](#documentation-index)
    1. [Quick Navigation](#quick-navigation)
        1. [For Users](#for-users)
        1. [For Developers & Contributors](#for-developers-contributors)
    1. [Documentation Structure](#documentation-structure)
        1. [Project Statistics](#project-statistics)
        1. [Component Breakdown](#component-breakdown)
            1. [PowerShell Layer (`PSNvdRoH.psm1`)](#powershell-layer-psnvdrohpsm1)
            1. [C# Library (`NvdClient/`)](#c-library-nvdclient)
            1. [Testing (`NvdClient.Tests/`)](#testing-nvdclienttests)
    1. [How It Works](#how-it-works)
    1. [Common Tasks](#common-tasks)
        1. [I want to...](#i-want-to)
            1. [Use the module](#use-the-module)
            1. [Understand how it works](#understand-how-it-works)
            1. [Look up a specific class/method](#look-up-a-specific-classmethod)
            1. [Find where something is implemented](#find-where-something-is-implemented)
            1. [Run the tests](#run-the-tests)
    1. [Key Concepts](#key-concepts)
        1. [Parameters & Validation](#parameters-validation)
        1. [Parameter Constraints](#parameter-constraints)
        1. [Date Format](#date-format)
        1. [Rate Limiting](#rate-limiting)
    1. [Code Examples](#code-examples)
        1. [PowerShell](#powershell)
        1. [C#](#c)
    1. [File Structure](#file-structure)
    1. [Resources](#resources)
        1. [Official References](#official-references)
        1. [Related Standards](#related-standards)
    1. [Contributing](#contributing)
    1. [Questions?](#questions)

# Documentation Index

Welcome to PSNvdRoH documentation! This folder contains comprehensive guides and references for using and understanding the project.

## Quick Navigation

### For Users

**[README.md][Readme]** — Start here!
- Installation instructions
- How to use the `Get-NvdCve` cmdlet
- Real-world examples and common use cases

### For Developers & Contributors

**[ARCHITECTURE.md][Architecture]** — Project structure and design
- Component overview (7 classes, 2+ functions)
- Architecture diagram showing data flow
- Design patterns and principles
- Performance considerations
- Future enhancement opportunities

**[API_REFERENCE.md][Api_Reference]** — Complete API documentation
- All classes and their methods
- All enums and their values
- Function signatures and parameters
- File location reference
- Code examples

---

## Documentation Structure

### Project Statistics
- **7 Classes** (5 regular classes, 4 enums)
- **2 Public Functions** (1 cmdlet, 1 helper)
- **20+ Public Methods and Properties**
- **7 Unit Tests**

### Component Breakdown

#### PowerShell Layer (`PSNvdRoH.psm1`)
- `Get-NvdCve` — Main cmdlet for querying NVD
- `Invoke-NvdApi` — Internal async helper

#### C# Library (`NvdClient/`)
- `NvdApiClient` — HTTP communication with NVD API
- `CveQueryParameters` — Type-safe parameter container
- `QueryStringBuilder` — Query string validation & building
- `CveTag`, `CvssV2Severity`, `CvssV3Severity`, `CvssV4Severity` — Enums

#### Testing (`NvdClient.Tests/`)
- `QueryStringBuilderTests` — 7 unit tests for validation logic

---

## How It Works

```
User calls Get-NvdCve cmdlet
         ↓
PowerShell validates parameters
         ↓
Create CveQueryParameters object
         ↓
QueryStringBuilder validates & serializes
         ↓
NvdApiClient sends HTTP GET request
         ↓
NVD API returns JSON response
         ↓
PowerShell parses JSON & displays results
```

---

## Common Tasks

### I want to...

#### Use the module
→ See [README.md][Readme] for installation and usage examples

#### Understand how it works
→ See [ARCHITECTURE.md][Architecture] for architecture and design patterns

#### Look up a specific class/method
→ See [API_REFERENCE.md][Api_Reference] for complete API documentation

#### Find where something is implemented
→ Each document has file references and a summary table

#### Run the tests
```bash
cd NvdClient.Tests
dotnet test
```

---

## Key Concepts

### Parameters & Validation
PSNvdRoH uses two-tier validation:
1. **PowerShell Validation** — `ValidateSet`, `ValidateRange`, etc.
2. **C# Validation** — `QueryStringBuilder.ValidateParameters()`

### Parameter Constraints
- CVSS metrics are mutually exclusive (only one severity per query)
- Date ranges must be complete pairs (start + end)
- Some parameters have dependencies (e.g., `IsVulnerable` requires `CpeName`)

See [ARCHITECTURE.md][Architecture_ValidationRules] for complete validation rules.

### Date Format
All dates are converted to UTC with "Z" suffix: `yyyy-MM-ddTHH:mm:ssZ`

### Rate Limiting
- **Without API Key:** 10 requests/hour
- **With API Key:** 120 requests/hour

See [README.md][Readme_Prerequisites] for how to get an API key.

---

## Code Examples

### PowerShell

```powershell
# Simple search
Get-NvdCve -KeywordSearch "Apache"

# Critical vulnerabilities
Get-NvdCve -CvssV3Severity "CRITICAL" -NoRejected -ResultsPerPage 100

# With API key for better rate limits
Get-NvdCve -ApiKey "your-key" -KeywordSearch "Windows" -CvssV3Severity "HIGH"
```

### C#

```csharp
var parameters = new CveQueryParameters
{
    KeywordSearch = new[] { "Apache" },
    CvssV3Severity = CvssV3Severity.CRITICAL
};

var client = new NvdApiClient("api-key");
var json = await client.GetCvesAsync(parameters);
```

---

## File Structure

```
PSNvdRoH/
├── README.md                           # Main README (Installation & How-to-use)
├── docs/
│   ├── INDEX.md                        # This file
│   ├── ARCHITECTURE.md                 # Architecture & design patterns
│   ├── API_REFERENCE.md                # Complete API documentation
├── PSNvdRoH.psm1                       # PowerShell module (Get-NvdCve)
├── PSNvdRoH.Tests.ps1                  # PowerShell tests
├── NvdClient/                          # C# library
│   ├── NvdApiClient.cs                 # HTTP client
│   ├── CveQueryParameters.cs           # Parameter DTO
│   ├── QueryStringBuilder.cs           # Query builder
│   ├── CveTag.cs                       # CVE tag enum
│   ├── CvssV2Severity.cs               # CVSS v2 severity enum
│   ├── CvssV3Severity.cs               # CVSS v3 severity enum
│   ├── CvssV4Severity.cs               # CVSS v4 severity enum
│   ├── NvdClient.csproj                # C# project file
├── NvdClient.Tests/                    # C# unit tests
│   ├── QueryStringBuilderTests.cs      # 7 unit tests
│   └── NvdClient.Tests.csproj          # Test project file
```

---

## Resources

### Official References
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [NVD API v2.0 Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [Request an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Related Standards
- [CVSS v2.0](https://www.first.org/cvss/v2/)
- [CVSS v3.0/3.1](https://www.first.org/cvss/v3.0/)
- [CVSS v4.0](https://www.first.org/cvss/v4.0/)
- [CPE Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-23.pdf)

---

## Contributing

When contributing to PSNvdRoH, please:

1. **Run tests** before submitting changes:
   ```bash
   dotnet test NvdClient.Tests/NvdClient.Tests.csproj
   ```

2. **Update documentation** if you add or change functionality

3. **Follow design patterns** established in [ARCHITECTURE.md][Architecture]

4. **Maintain validation rules** — see [API_REFERENCE.md][Architecture_ValidationRules]

---

## Questions?

- Check [ARCHITECTURE.md][Architecture] for design questions
- Check [API_REFERENCE.md][Api_Reference] for method/parameter questions
- Check [README.md][Readme] for usage questions
- Review unit tests in [NvdClient.Tests/QueryStringBuilderTests.cs][CSharp_UnitTests] for validation examples

[Readme]: ../README.md
[Architecture]: ARCHITECTURE.md
[Api_Reference]: API_REFERENCE.md
[Readme_Prerequisites]: ../README.md#prerequisites
[Architecture_ValidationRules]: ./ARCHITECTURE.md#validation-rules
[CSharp_UnitTests]: ../NvdClient.Tests/QueryStringBuilderTests.cs