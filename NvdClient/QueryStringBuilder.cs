using System.Reflection;
using System.Runtime.Serialization;
using System.Web;

namespace NvdClient;

/// <summary>
/// Converts a <see cref="CveQueryParameters"/> instance into a properly encoded
/// query string for the NVD CVE API v2.0.
/// </summary>
public static class QueryStringBuilder
{
    public static string ToQueryString(CveQueryParameters p)
    {
        ValidateParameters(p);

        var q = HttpUtility.ParseQueryString(string.Empty);

        void Add(string name, object? value)
        {
            if (value == null)
                return;

            switch (value)
            {
                case DateTime dt:
                    q[name] = dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                    return;

                case bool b:
                    q[name] = b ? "true" : "false";
                    return;

                case string[] arr:
                    foreach (var item in arr)
                    {
                        if (!string.IsNullOrWhiteSpace(item))
                            q.Add(name, HttpUtility.UrlEncode(item));
                    }
                    return;

                default:
                    if (value.GetType().IsEnum)
                    {
                        q[name] = HttpUtility.UrlEncode(GetEnumValue(value));
                        return;
                    }

                    q[name] = HttpUtility.UrlEncode(value.ToString());
                    return;
            }
        }

        // TEXT SEARCH
        Add("keywordSearch", p.KeywordSearch);
        Add("keywordExactMatch", p.KeywordExactMatch);
        Add("cveID", p.CveID);
        Add("cveTag", p.CveTag);
        Add("cpeName", p.CpeName);

        // CVSS SEVERITY ENUMS (fixed)
        Add("cvssV2Severity", p.CvssV2Severity);
        Add("cvssV3Severity", p.CvssV3Severity);
        Add("cvssV4Severity", p.CvssV4Severity);

        // CVSS METRICS
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

        var result = q.ToString();
        return string.IsNullOrEmpty(result) ? string.Empty : "?" + result;
    }

    private static string GetEnumValue(object enumValue)
    {
        var member = enumValue.GetType().GetMember(enumValue.ToString() ?? string.Empty).FirstOrDefault();
        if (member == null)
            return enumValue.ToString() ?? string.Empty;

        var attribute = member.GetCustomAttribute<EnumMemberAttribute>();
        return attribute?.Value ?? enumValue.ToString() ?? string.Empty;
    }

    private static void ValidateParameters(CveQueryParameters p)
    {
        var metricCount =
            (p.CvssV2Metrics != null ? 1 : 0) +
            (p.CvssV3Metrics != null ? 1 : 0) +
            (p.CvssV4Metrics != null ? 1 : 0);

        if (metricCount > 1)
            throw new InvalidOperationException("Only one CVSS metrics parameter may be specified.");

        var severityCount =
            (p.CvssV2Severity != null ? 1 : 0) +
            (p.CvssV3Severity != null ? 1 : 0) +
            (p.CvssV4Severity != null ? 1 : 0);

        if (severityCount > 1)
            throw new InvalidOperationException("Only one CVSS severity parameter may be specified.");

        if ((p.PubStartDate != null) ^ (p.PubEndDate != null))
            throw new InvalidOperationException("Both pubStartDate and pubEndDate must be specified together.");

        if ((p.LastModStartDate != null) ^ (p.LastModEndDate != null))
            throw new InvalidOperationException("Both lastModStartDate and lastModEndDate must be specified together.");

        if (p.KeywordExactMatch == true && (p.KeywordSearch == null || p.KeywordSearch.Length == 0))
            throw new InvalidOperationException("keywordExactMatch requires keywordSearch.");

        if (p.IsVulnerable == true && string.IsNullOrEmpty(p.CpeName))
            throw new InvalidOperationException("isVulnerable requires cpeName.");
    }
}
