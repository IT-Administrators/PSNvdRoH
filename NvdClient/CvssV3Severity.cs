namespace NvdClient;

/// <summary>
/// Represents the allowed values for the NVD API parameter "cvssV3Severity".
/// 
/// The NVD API only accepts:
///   - "LOW"
///   - "MEDIUM"
///   - "HIGH"
///   - "CRITICAL"
/// 
/// This enum ensures strong typing and PowerShell compatibility.
/// </summary>
public enum CvssV3Severity
{
    /// <summary>
    /// CVSS v3 severity: LOW
    /// </summary>
    LOW,

    /// <summary>
    /// CVSS v3 severity: MEDIUM
    /// </summary>
    MEDIUM,

    /// <summary>
    /// CVSS v3 severity: HIGH
    /// </summary>
    HIGH,

    /// <summary>
    /// CVSS v3 severity: CRITICAL
    /// </summary>
    CRITICAL
}
