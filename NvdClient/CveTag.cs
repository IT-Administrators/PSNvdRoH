namespace NvdClient;

using System.Runtime.Serialization;

/// <summary>
/// Represents the allowed values for the NVD API parameter "cveTag".
/// 
/// This enum provides strong typing while preserving the exact API string values.
/// </summary>
public enum CveTag
{
    /// <summary>
    /// CVE tag: disputed
    /// </summary>
    [EnumMember(Value = "disputed")]
    Disputed,

    /// <summary>
    /// CVE tag: unsupported-when-assigned
    /// </summary>
    [EnumMember(Value = "unsupported-when-assigned")]
    UnsupportedWhenAssigned,

    /// <summary>
    /// CVE tag: exclusively-hosted-service
    /// </summary>
    [EnumMember(Value = "exclusively-hosted-service")]
    ExclusivelyHostedService
}
