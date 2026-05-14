using System.Reflection;
using System.Runtime.Serialization;
using System.Web;

namespace NvdClient;

/// <summary>
/// Converts a <see cref="CveQueryParameters"/> instance into a fully validated,
/// URL‑encoded, NVD‑compliant query string.
/// 
/// Responsibilities:
///   • Include only non‑null parameters
///   • Validate mutually exclusive / required parameter combinations
///   • Encode all values safely for HTTP transport
///   • Convert enums using EnumMemberAttribute when present
///   • Format dates in strict UTC with "Z" suffix
///   • Produce a query string beginning with "?" or an empty string
/// </summary>
public static class QueryStringBuilder
{
    /// <summary>
    /// Converts a parameter object into a query string.
    /// </summary>
    public static string ToQueryString(CveQueryParameters p)
    {
        // Validate logical constraints before building the query string.
        ValidateParameters(p);

        // NameValueCollection that will hold encoded key/value pairs.
        var q = HttpUtility.ParseQueryString(string.Empty);

        // Local helper to add parameters only when they have meaningful values.
        void Add(string name, object? value)
        {
            if (value == null)
                return;

            switch (value)
            {
                // DATE HANDLING
                // NVD requires strict UTC timestamps with a "Z" suffix.
                case DateTime dt:
                    q[name] = dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                    return;

                // BOOLEAN HANDLING 
                // NVD expects lowercase "true"/"false".
                case bool b:
                    q[name] = b ? "true" : "false";
                    return;

                // ARRAY HANDLING
                // keywordSearch supports multiple values.
                case string[] arr:
                    foreach (var item in arr)
                    {
                        if (!string.IsNullOrWhiteSpace(item))
                            q.Add(name, HttpUtility.UrlEncode(item));
                    }
                    return;

                // ENUM HANDLING
                // Use EnumMemberAttribute when present (e.g., cveTag).
                default:
                    if (value.GetType().IsEnum)
                    {
                        q[name] = HttpUtility.UrlEncode(GetEnumValue(value));
                        return;
                    }

                    // DEFAULT HANDLING 
                    // Encode all other values (strings, ints, etc.)
                    q[name] = HttpUtility.UrlEncode(value.ToString());
                    return;
            }
        }

        // TEXT SEARCH PARAMETERS
        Add("keywordSearch", p.KeywordSearch);
        Add("keywordExactMatch", p.KeywordExactMatch);
        Add("cveID", p.CveID);
        Add("cveTag", p.CveTag);
        Add("cpeName", p.CpeName);

        // CVSS SEVERITY ENUMS
        // These now correctly use enum reflection instead of .ToString().
        Add("cvssV2Severity", p.CvssV2Severity);
        Add("cvssV3Severity", p.CvssV3Severity);
        Add("cvssV4Severity", p.CvssV4Severity);

        // CVSS METRICS STRINGS
        Add("cvssV2Metrics", p.CvssV2Metrics);
        Add("cvssV3Metrics", p.CvssV3Metrics);
        Add("cvssV4Metrics", p.CvssV4Metrics);

        // CPE MATCHING
        Add("cpeMatchString", p.CpeMatchString);

        // DATE FILTERS
        Add("pubStartDate", p.PubStartDate);
        Add("pubEndDate", p.PubEndDate);
        Add("lastModStartDate", p.LastModStartDate);
        Add("lastModEndDate", p.LastModEndDate);
        Add("kevStartDate", p.KevStartDate);
        Add("kevEndDate", p.KevEndDate);

        // PAGINATION
        Add("resultsPerPage", p.ResultsPerPage);
        Add("startIndex", p.StartIndex);

        // BOOLEAN FLAGS
        Add("hasCertAlerts", p.HasCertAlerts);
        Add("hasCertNotes", p.HasCertNotes);
        Add("hasKev", p.HasKev);
        Add("hasOval", p.HasOval);
        Add("isVulnerable", p.IsVulnerable);
        Add("noRejected", p.NoRejected);

        // SOURCE IDENTIFIER
        Add("sourceIdentifier", p.SourceIdentifier);

        // Convert the NameValueCollection into a query string.
        var result = q.ToString();

        // If no parameters were added, return an empty string.
        return string.IsNullOrEmpty(result) ? string.Empty : "?" + result;
    }

    /// <summary>
    /// Extracts the correct string representation of an enum value.
    /// If the enum member has an EnumMemberAttribute, its Value is used.
    /// Otherwise, the enum's name is used.
    /// </summary>
    private static string GetEnumValue(object enumValue)
    {
        var member = enumValue.GetType().GetMember(enumValue.ToString() ?? string.Empty).FirstOrDefault();
        if (member == null)
            return enumValue.ToString() ?? string.Empty;

        var attribute = member.GetCustomAttribute<EnumMemberAttribute>();
        return attribute?.Value ?? enumValue.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Validates logical constraints between parameters.
    /// Throws InvalidOperationException when invalid combinations are detected.
    /// </summary>
    private static void ValidateParameters(CveQueryParameters p)
    {
        // CVSS METRICS: Only one version allowed
        var metricCount =
            (p.CvssV2Metrics != null ? 1 : 0) +
            (p.CvssV3Metrics != null ? 1 : 0) +
            (p.CvssV4Metrics != null ? 1 : 0);

        if (metricCount > 1)
            throw new InvalidOperationException("Only one CVSS metrics parameter may be specified.");

        // CVSS SEVERITY: Only one version allowed
        var severityCount =
            (p.CvssV2Severity != null ? 1 : 0) +
            (p.CvssV3Severity != null ? 1 : 0) +
            (p.CvssV4Severity != null ? 1 : 0);

        if (severityCount > 1){
            throw new InvalidOperationException("Only one CVSS severity parameter may be specified.");
        }

        // DATE PAIRS MUST BE COMPLETE
        if ((p.PubStartDate != null) ^ (p.PubEndDate != null)){
            throw new InvalidOperationException("Both pubStartDate and pubEndDate must be specified together.");
        }

        if ((p.LastModStartDate != null) ^ (p.LastModEndDate != null)){
            throw new InvalidOperationException("Both lastModStartDate and lastModEndDate must be specified together.");
        }

        if ((p.KevStartDate != null) ^ (p.KevEndDate != null))
        {
            throw new InvalidOperationException("Both kevStartDate and kevEndDate must be specified together.");
        }

        // KEYWORD EXACT MATCH REQUIRES KEYWORDS
        if (p.KeywordExactMatch == true && (p.KeywordSearch == null || p.KeywordSearch.Length == 0)){
            throw new InvalidOperationException("keywordExactMatch requires keywordSearch.");
        }

        // IS VULNERABLE REQUIRES CPE NAME
        if (p.IsVulnerable == true && string.IsNullOrEmpty(p.CpeName)){
            throw new InvalidOperationException("isVulnerable requires cpeName.");
        }
    }
}
