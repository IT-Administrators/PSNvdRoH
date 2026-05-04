namespace NvdClient;

/// <summary>
/// Strongly‑typed representation of all supported NVD CVE API v2.0 query parameters.
/// 
/// This class contains only data — no logic. It is consumed by:
///   - <see cref="QueryStringBuilder"/> for serialization
///   - <see cref="NvdApiClient"/> for HTTP requests
/// 
/// Only non‑null properties are included in the final query string.
/// </summary>
public class CveQueryParameters
{
    // TEXT SEARCH PARAMETERS

    /// <summary>
    /// Free‑text keyword search across CVE descriptions.
    /// Maps to "keywordSearch".
    /// </summary>
    public string? KeywordSearch { get; set; }

    /// <summary>
    /// Filter by CPE (Common Platform Enumeration) name.
    /// Maps to "cpeName".
    /// </summary>
    public string? CpeName { get; set; }


    // CVSS FILTERS (ENUMS + METRICS)

    /// <summary>
    /// Filter by CVSS v2 severity.
    /// Maps to "cvssV2Severity".
    /// </summary>
    public CvssV2Severity? CvssV2Severity { get; set; }

    /// <summary>
    /// Filter by CVSS v3 severity.
    /// Maps to "cvssV3Severity".
    /// </summary>
    public CvssV3Severity? CvssV3Severity { get; set; }

    /// <summary>
    /// Filter by CVSS v2 base score (0.0 - 10.0).
    /// Maps to "cvssV2Metrics".
    /// </summary>
    public double? CvssV2Metrics { get; set; }

    /// <summary>
    /// Filter by CVSS v3 base score (0.0 - 10.0).
    /// Maps to "cvssV3Metrics".
    /// </summary>
    public double? CvssV3Metrics { get; set; }


    // CPE MATCHING

    /// <summary>
    /// Enables strict CPE matching.
    /// Maps to "cpeMatchString".
    /// </summary>
    public bool? CpeMatchString { get; set; }


    // DATE FILTERS

    /// <summary>
    /// Only return CVEs published on or after this date.
    /// Maps to "pubStartDate".
    /// </summary>
    public DateTime? PubStartDate { get; set; }

    /// <summary>
    /// Only return CVEs published on or before this date.
    /// Maps to "pubEndDate".
    /// </summary>
    public DateTime? PubEndDate { get; set; }

    /// <summary>
    /// Only return CVEs modified on or after this date.
    /// Maps to "lastModStartDate".
    /// </summary>
    public DateTime? LastModStartDate { get; set; }

    /// <summary>
    /// Only return CVEs modified on or before this date.
    /// Maps to "lastModEndDate".
    /// </summary>
    public DateTime? LastModEndDate { get; set; }

    // PAGINATION

    /// <summary>
    /// Number of results per page (max 2000).
    /// Maps to "resultsPerPage".
    /// </summary>
    public int? ResultsPerPage { get; set; }

    /// <summary>
    /// Zero‑based index for pagination.
    /// Maps to "startIndex".
    /// </summary>
    public int? StartIndex { get; set; }

    // BOOLEAN FILTERS

    public bool? HasCertAlerts { get; set; }
    public bool? HasCertNotes { get; set; }
    public bool? HasKev { get; set; }
    public bool? HasOval { get; set; }
    public bool? IsVulnerable { get; set; }
}
