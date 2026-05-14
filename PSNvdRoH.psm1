<#
.SYNOPSIS
    PowerShell wrapper for the NVD (National Vulnerability Database) CVE API v2.0.

.DESCRIPTION
    This module provides a high-level PowerShell interface for querying CVE data
    from the NVD API using a strongly-typed C# client library.

    It automatically loads the NvdClient.dll assembly and exposes the Get-NvdCve
    cmdlet, which supports all documented API parameters including CVSS v4 metrics,
    CISA KEV catalog filters, and comprehensive CVE metadata filtering.

.NOTES
    Author: IT-Administrators
    Module: PSNvdRoH
    Version: 2.0
    RequiredAssemblies: @('dist/NvdClient.dll')
#>

# Load the C# library assembly
$assemblyPath = Join-Path -Path $PSScriptRoot -ChildPath "dist/NvdClient.dll"

if (-not (Test-Path -Path $assemblyPath)) {
    throw "NvdClient.dll not found at: $assemblyPath. Please ensure the project is built with 'make' or 'dotnet build'."
}

try {
    $alreadyLoaded = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -eq $assemblyPath }
    if (-not $alreadyLoaded) {
        $alcType = [type]::GetType('System.Runtime.Loader.AssemblyLoadContext, System.Runtime.Loader')
        if ($alcType) {
            $alcType::Default.LoadFromAssemblyPath($assemblyPath) | Out-Null
        }
        else {
            [System.Reflection.Assembly]::LoadFrom($assemblyPath) | Out-Null
        }
    }
    Write-Verbose "Loaded NvdClient assembly from: $assemblyPath"
} catch {
    throw "Failed to load NvdClient assembly from '$assemblyPath': $($_.Exception.Message)"
}

function Get-NvdCve {
    <#
    .SYNOPSIS
        Queries the National Vulnerability Database (NVD) CVE API v2.0.

    .DESCRIPTION
        The Get-NvdCve cmdlet queries the NVD CVE API v2.0 with comprehensive filtering capabilities.
        
        Only parameters explicitly provided are included in the API request. This cmdlet uses a strongly-typed
        C# client library (NvdApiClient) for secure HTTP communication and parameter validation.
        
        The API enforces several parameter combination rules which are validated before the request:
        - Only one CVSS metrics version may be used (cvssV2Metrics, cvssV3Metrics, or cvssV4Metrics)
        - Only one CVSS severity version may be used (cvssV2Severity, cvssV3Severity, or cvssV4Severity)
        - Date range pairs (PubStartDate/PubEndDate, LastModStartDate/LastModEndDate) must be specified together
        - KeywordExactMatch requires KeywordSearch to be specified
        - IsVulnerable requires CpeName to be specified

    .PARAMETER ApiKey
        Optional. Your NVD API key for higher request rate limits (120 requests per hour with key, 10 without).
        If not provided, requests are rate-limited to 10 per hour. Can be passed via pipeline by property name.

    .PARAMETER CveID
        Optional. Filter results by a specific CVE identifier (e.g., "CVE-2025-1234").
        Can be passed via pipeline by property name.

    .PARAMETER CveTag
        Optional. Filter by CVE tag. Valid values are:
        - Disputed: Vulnerability is disputed
        - UnsupportedWhenAssigned: Feature was not supported when CVE was assigned
        - ExclusivelyHostedService: Vulnerability applies only to hosted service
        Can be passed via pipeline by property name.

    .PARAMETER KeywordSearch
        Optional. Free-text keyword search across CVE descriptions. Accepts one or more values.
        When used with KeywordExactMatch, requires exact phrase matching.
        Can be passed via pipeline by property name.

    .PARAMETER KeywordExactMatch
        Optional. Requires exact keyword matching when used with KeywordSearch.
        Cannot be used without KeywordSearch. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER CpeName
        Optional. Filter by CPE (Common Platform Enumeration) name.
        Example: "cpe:2.3:a:apache:http_server:2.4.54"
        Required when using IsVulnerable parameter.
        Can be passed via pipeline by property name.

    .PARAMETER CpeMatchString
        Optional. Enable strict CPE matching rules. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER CvssV2Severity
        Optional. Filter by CVSS v2 severity rating. Valid values: LOW, MEDIUM, HIGH.
        Cannot be combined with CvssV3Severity or CvssV4Severity.
        Can be passed via pipeline by property name.

    .PARAMETER CvssV3Severity
        Optional. Filter by CVSS v3 severity rating. Valid values: LOW, MEDIUM, HIGH, CRITICAL.
        Cannot be combined with CvssV2Severity or CvssV4Severity.
        Can be passed via pipeline by property name.

    .PARAMETER CvssV4Severity
        Optional. Filter by CVSS v4 severity rating. Valid values: LOW, MEDIUM, HIGH, CRITICAL.
        Cannot be combined with CvssV2Severity or CvssV3Severity.
        Can be passed via pipeline by property name.

    .PARAMETER CvssV2Metrics
        Optional. Filter by CVSS v2 metrics string (encoded query).
        Cannot be combined with CvssV3Metrics or CvssV4Metrics.
        Can be passed via pipeline by property name.

    .PARAMETER CvssV3Metrics
        Optional. Filter by CVSS v3 metrics string (encoded query).
        Cannot be combined with CvssV2Metrics or CvssV4Metrics.
        Can be passed via pipeline by property name.

    .PARAMETER CvssV4Metrics
        Optional. Filter by CVSS v4 metrics string (encoded query).
        Cannot be combined with CvssV2Metrics or CvssV3Metrics.
        Can be passed via pipeline by property name.

    .PARAMETER PubStartDate
        Optional. Only return CVEs published on or after this date (inclusive).
        Must be used with PubEndDate. Maximum range is 120 days.
        Can be passed via pipeline by property name.

    .PARAMETER PubEndDate
        Optional. Only return CVEs published on or before this date (inclusive).
        Must be used with PubStartDate. Maximum range is 120 days.
        Can be passed via pipeline by property name.

    .PARAMETER LastModStartDate
        Optional. Only return CVEs modified on or after this date (inclusive).
        Must be used with LastModEndDate. Maximum range is 120 days.
        Can be passed via pipeline by property name.

    .PARAMETER LastModEndDate
        Optional. Only return CVEs modified on or before this date (inclusive).
        Must be used with LastModStartDate. Maximum range is 120 days.
        Can be passed via pipeline by property name.

    .PARAMETER KevStartDate
        Optional. Only return CVEs added to the CISA KEV catalog on or after this date.
        Should be used with KevEndDate for optimal results.
        Can be passed via pipeline by property name.

    .PARAMETER KevEndDate
        Optional. Only return CVEs added to the CISA KEV catalog on or before this date.
        Should be used with KevStartDate for optimal results.
        Can be passed via pipeline by property name.

    .PARAMETER SourceIdentifier
        Optional. Filter by vulnerability source identifier (e.g., "cisa", "nist").
        Can be passed via pipeline by property name.

    .PARAMETER NoRejected
        Optional. Exclude rejected CVEs from the results. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER HasCertAlerts
        Optional. Only return CVEs with CERT/CC alerts. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER HasCertNotes
        Optional. Only return CVEs with CERT/CC notes. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER HasKev
        Optional. Only return CVEs listed in CISA's Known Exploited Vulnerabilities catalog. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER HasOval
        Optional. Only return CVEs with OVAL definitions. Default is $false.
        Can be passed via pipeline by property name.

    .PARAMETER IsVulnerable
        Optional. Only return CVEs where the specified product (via CpeName) is vulnerable. Default is $false.
        Requires CpeName to be specified.
        Can be passed via pipeline by property name.

    .PARAMETER ResultsPerPage
        Optional. Number of results per page (default varies by API, maximum 2000).
        Valid range: 1-2000.
        Can be passed via pipeline by property name.

    .PARAMETER StartIndex
        Optional. Zero-based index for pagination. Use with ResultsPerPage.
        Valid range: 0 and above.
        Can be passed via pipeline by property name.

    .OUTPUTS
        System.Object[]
        PSCustomObject[] containing CVE records from the API response with vulnerability metadata.

    .EXAMPLE
        # Search for OpenSSL vulnerabilities without API key (rate-limited to 10/hr)
        PS> Get-NvdCve -KeywordSearch "openssl"
        
        This queries for CVEs mentioning "openssl" in their description without an API key.

    .EXAMPLE
        # Search with API key for critical CVSS v3 vulnerabilities (120 requests/hr limit)
        PS> Get-NvdCve -ApiKey "your-api-key" -CvssV3Severity CRITICAL -ResultsPerPage 200
        
        This retrieves up to 200 CVEs with CRITICAL CVSS v3 severity rating using the provided API key.

    .EXAMPLE
        # Find vulnerabilities in Apache HTTP Server with exact match
        PS> Get-NvdCve -CpeName "cpe:2.3:a:apache:http_server" -KeywordSearch "remote code execution" -KeywordExactMatch $true
        
        This searches for "remote code execution" vulnerabilities specific to Apache HTTP Server.

    .EXAMPLE
        # Get CVEs from a specific month with comprehensive filtering
        PS> $startDate = Get-Date -Year 2025 -Month 1 -Day 1
        PS> $endDate = Get-Date -Year 2025 -Month 1 -Day 31
        PS> Get-NvdCve -ApiKey $apiKey -PubStartDate $startDate -PubEndDate $endDate -ResultsPerPage 500
        
        This retrieves CVEs published during January 2025 with pagination.

    .EXAMPLE
        # Get known exploited vulnerabilities with high severity
        PS> Get-NvdCve -HasKev $true -CvssV3Severity HIGH -NoRejected $true -ApiKey $key
        
        This finds high-severity CVEs in CISA's known exploited vulnerabilities list, excluding rejected entries.

    .EXAMPLE
        # Search for recent modifications to critical vulnerabilities
        PS> $sevenDaysAgo = (Get-Date).AddDays(-7)
        PS> $today = Get-Date
        PS> Get-NvdCve -LastModStartDate $sevenDaysAgo -LastModEndDate $today -CvssV3Severity CRITICAL -ApiKey $key
        
        This retrieves recently updated critical vulnerabilities from the past week.

    .NOTES
        Author: IT-Administrators
        Version: 2.0
        API Documentation: https://nvd.nist.gov/developers/vulnerabilities
        
        Rate Limits:
        - Without API key: 10 requests per hour
        - With API key: 120 requests per hour
        
        Parameter Combination Rules:
        - Date pairs (Pub/LastMod) must be complete when used
        - CVSS severity and metrics cannot be mixed across versions
        - IsVulnerable requires CpeName
        - KeywordExactMatch requires KeywordSearch
        
        Error Handling:
        - Parameter validation errors are caught and reported with InvalidArgument category
        - Network/HTTP errors are reported with ConnectionError category
        - Unexpected errors are reported with NotSpecified category

    .LINK
        https://nvd.nist.gov/developers

        https://nvd.nist.gov/api/documents/vulnerability-metrics-temporal

        https://pages.nist.gov/NVD/guidance/vulnerability-metrics/v3

        https://github.com/IT-Administrators/PSNvdRoH
    #>

    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(

        # API KEY
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ApiKey,

        # TEXT SEARCH
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$KeywordSearch,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$KeywordExactMatch,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$CveID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Disputed','UnsupportedWhenAssigned','ExclusivelyHostedService')]
        [string]$CveTag,

        # CPE FILTERING
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$CpeName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$CpeMatchString,

        # CVSS SEVERITY (Mutually Exclusive via Parameter Sets)
        [Parameter(ParameterSetName='CvssV2', ValueFromPipelineByPropertyName)]
        [ValidateSet('LOW','MEDIUM','HIGH')]
        [string]$CvssV2Severity,

        [Parameter(ParameterSetName='CvssV3', ValueFromPipelineByPropertyName)]
        [ValidateSet('LOW','MEDIUM','HIGH','CRITICAL')]
        [string]$CvssV3Severity,

        [Parameter(ParameterSetName='CvssV4', ValueFromPipelineByPropertyName)]
        [ValidateSet('LOW','MEDIUM','HIGH','CRITICAL')]
        [string]$CvssV4Severity,

        # CVSS METRICS (Mutually Exclusive via Parameter Sets)
        [Parameter(ParameterSetName='CvssV2', ValueFromPipelineByPropertyName)]
        [string]$CvssV2Metrics,

        [Parameter(ParameterSetName='CvssV3', ValueFromPipelineByPropertyName)]
        [string]$CvssV3Metrics,

        [Parameter(ParameterSetName='CvssV4', ValueFromPipelineByPropertyName)]
        [string]$CvssV4Metrics,

        # PUBLICATION DATE RANGE (Required Together)
        [Parameter(ValueFromPipelineByPropertyName)]
        [datetime]$PubStartDate,

        [Parameter(ValueFromPipelineByPropertyName)]
        [datetime]$PubEndDate,

        # LAST MODIFIED DATE RANGE (Required Together)
        [Parameter(ValueFromPipelineByPropertyName)]
        [datetime]$LastModStartDate,

        [Parameter(ValueFromPipelineByPropertyName)]
        [datetime]$LastModEndDate,

        # KEV DATE RANGE
        [Parameter(ParameterSetName='Kev', ValueFromPipelineByPropertyName)]
        [datetime]$KevStartDate,

        [Parameter(ParameterSetName='Kev', ValueFromPipelineByPropertyName)]
        [datetime]$KevEndDate,

        # SOURCE IDENTIFIER
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SourceIdentifier,

        # BOOLEAN FLAGS
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$NoRejected,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$HasCertAlerts,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$HasCertNotes,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$HasKev,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$HasOval,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$IsVulnerable,

        # PAGINATION
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,2000)]
        [int]$ResultsPerPage,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,[int]::MaxValue)]
        [int]$StartIndex
    )

    begin {
        # Instantiate the C# HTTP client with optional API key
        Write-Verbose "Initializing NVD API client..."
        $client = [NvdClient.NvdApiClient]::new($ApiKey)
        
        if ($ApiKey) {
            Write-Verbose "NVD API client initialized with API key (rate limit: 120 requests/hour)"
        }
        else {
            Write-Verbose "NVD API client initialized without API key (rate limit: 10 requests/hour)"
        }
    }

    process {
        # Additional PowerShell-side validation for required parameter pairs
        if ($PSBoundParameters.ContainsKey('PubStartDate') -xor $PSBoundParameters.ContainsKey('PubEndDate')) {
            throw "PubStartDate and PubEndDate must be specified together."
        }

        if ($PSBoundParameters.ContainsKey('LastModStartDate') -xor $PSBoundParameters.ContainsKey('LastModEndDate')) {
            throw "LastModStartDate and LastModEndDate must be specified together."
        }

        if ($PSBoundParameters.ContainsKey('KevStartDate') -xor $PSBoundParameters.ContainsKey('KevEndDate')) {
            throw "KevStartDate and KevEndDate must be specified together."
        }

        if ($KeywordExactMatch -and (-not $KeywordSearch)) {
            throw "KeywordExactMatch requires KeywordSearch to be specified."
        }

        if ($IsVulnerable -and (-not $CpeName)) {
            throw "IsVulnerable requires CpeName to be specified."
        }

        # Create a new C# parameter object to hold the query parameters
        # Only properties explicitly set will be passed to the API
        $params = [NvdClient.CveQueryParameters]::new()

        # Populate the parameter object with values from bound parameters
        # Ensures only specified parameters are sent to the API
        foreach ($key in $PSBoundParameters.Keys) {
            # Skip the API key as it's handled separately by the client
            if ($key -eq 'ApiKey') {
                continue
            }

            $hasProperty = $params | Get-Member -Name $key -MemberType Property -ErrorAction SilentlyContinue
            if (-not $hasProperty) {
                Write-Verbose "Skipping unsupported parameter: $key"
                continue
            }

            Write-Verbose "Setting parameter: $key = $($PSBoundParameters[$key])"
            $params.$key = $PSBoundParameters[$key]
            $null = $params.$key
        }

        try {
            # Execute the async API request and wait for the result
            Write-Verbose "Executing NVD API query..."
            # $json = $client.GetCvesAsync($params).GetAwaiter().GetResult()
            $json = Invoke-NvdApi -Client $client -Params $params

            if (-not $json) {
                Write-Verbose "No JSON response received from NVD API."
                return
            }

            # Parse JSON response and convert to PowerShell objects for easy consumption
            Write-Verbose "Query executed successfully, parsing response..."
            $json | ConvertFrom-Json
        }
        catch [InvalidOperationException] {
            # Parameter validation errors from C# client
            if ($_.Exception.InnerException) {
                $errorMessage = "Invalid parameter combination: $($_.Exception.InnerException.Message)"
            }
            else {
                $errorMessage = "Invalid parameter combination: $($_.Exception.Message)"
            }
            Write-Error -Message $errorMessage -Category InvalidArgument -ErrorAction Stop
        }
        catch [System.Net.Http.HttpRequestException] {
            # Network/HTTP errors
            $errorMessage = "Failed to connect to NVD API: $($_.Exception.Message)"
            Write-Error -Message $errorMessage -Category ConnectionError -ErrorAction Stop
        }
        catch {
            # Unexpected errors
            $errorMessage = "An error occurred while querying the NVD API: $($_.Exception.Message)"
            Write-Error -Message $errorMessage -Category NotSpecified -ErrorAction Stop
        }
    }

    end {
        Write-Verbose "NVD CVE query operation completed"
    }
}

function Invoke-NvdApi {
    param(
        $Client,
        $Params
    )
    return $Client.GetCvesAsync($Params).GetAwaiter().GetResult()
}

# Export the public function from the module
Export-ModuleMember -Function Get-NvdCve
