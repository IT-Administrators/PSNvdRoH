namespace NvdClient;

/// <summary>
/// Represents the allowed values for the NVD API parameter "cvssV4Severity".
/// 
/// The NVD API accepts:
///   - "LOW"
///   - "MEDIUM"
///   - "HIGH"
///   - "CRITICAL"
/// 
/// This enum ensures strong typing and PowerShell compatibility.
/// </summary>
public enum CvssV4Severity
{
    /// <summary>
    /// CVSS v4 severity: LOW
    /// </summary>
    LOW,

    /// <summary>
    /// CVSS v4 severity: MEDIUM
    /// </summary>
    MEDIUM,

    /// <summary>
    /// CVSS v4 severity: HIGH
    /// </summary>
    HIGH,

    /// <summary>
    /// CVSS v4 severity: CRITICAL
    /// </summary>
    CRITICAL
}
