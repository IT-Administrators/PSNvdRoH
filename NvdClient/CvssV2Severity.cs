namespace NvdClient;

/// <summary>
/// Represents the allowed values for the NVD API parameter "cvssV2Severity".
/// 
/// The NVD API only accepts the following string values:
///   - "LOW"
///   - "MEDIUM"
///   - "HIGH"
/// 
/// Using a top‑level enum ensures:
///   - PowerShell can resolve the type
///   - Tab‑completion works automatically
///   - Invalid values cannot be passed
/// </summary>
public enum CvssV2Severity
{
    /// <summary>
    /// CVSS v2 severity: LOW
    /// Indicates limited impact or low exploitability.
    /// </summary>
    LOW,

    /// <summary>
    /// CVSS v2 severity: MEDIUM
    /// Indicates moderate impact or exploitability.
    /// </summary>
    MEDIUM,

    /// <summary>
    /// CVSS v2 severity: HIGH
    /// Indicates significant impact or high exploitability.
    /// </summary>
    HIGH
}
