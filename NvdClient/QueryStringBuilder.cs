using System.Reflection;
using System.Runtime.Serialization;
using System.Web;

namespace NvdClient;

/// <summary>
/// Converts a <see cref="CveQueryParameters"/> instance into a properly encoded
/// query string for the NVD CVE API v2.0.
/// 
/// Responsibilities:
///   - Include only non‑null parameters
///   - Format DateTime values as ISO‑8601
///   - Convert enums to their string names
/// </summary>
public static class QueryStringBuilder
{
    public static string ToQueryString(CveQueryParameters p)
    {
        var q = HttpUtility.ParseQueryString(string.Empty);

        // Helper method to add parameters only when they have values.
        void Add(string name, object? value)
        {
            if (value == null)
                return;

            if (value is DateTime dt)
            {
                q[name] = dt.ToString("o"); // ISO‑8601
                return;
            }

            if (value is string[] values)
            {
                foreach (var item in values)
                {
                    if (!string.IsNullOrEmpty(item))
                    {
                        q.Add(name, item);
                    }
                }
                return;
            }

            if (value.GetType().IsEnum)
            {
                q[name] = GetEnumValue(value);
                return;
            }

            q[name] = value.ToString();
        }

        static string? GetEnumValue(object enumValue)
        {
            var member = enumValue.GetType().GetMember(enumValue.ToString() ?? string.Empty).FirstOrDefault();
            if (member == null)
                return enumValue.ToString();

            var attribute = member.GetCustomAttribute<EnumMemberAttribute>();
            return attribute?.Value ?? enumValue.ToString();
        }

        // Text search
        Add("keywordSearch", p.KeywordSearch);
        Add("keywordExactMatch", p.KeywordExactMatch);
        Add("cveID", p.CveID);
        Add("cveTag", p.CveTag);
        Add("cpeName", p.CpeName);

        // CVSS enums
        Add("cvssV2Severity", p.CvssV2Severity?.ToString());
        Add("cvssV3Severity", p.CvssV3Severity?.ToString());
        Add("cvssV4Severity", p.CvssV4Severity?.ToString());

        // CVSS metrics
        Add("cvssV2Metrics", p.CvssV2Metrics);
        Add("cvssV3Metrics", p.CvssV3Metrics);
        Add("cvssV4Metrics", p.CvssV4Metrics);

        // CPE matching
        Add("cpeMatchString", p.CpeMatchString);

        // Dates
        Add("pubStartDate", p.PubStartDate);
        Add("pubEndDate", p.PubEndDate);
        Add("lastModStartDate", p.LastModStartDate);
        Add("lastModEndDate", p.LastModEndDate);
        Add("kevStartDate", p.KevStartDate);
        Add("kevEndDate", p.KevEndDate);

        // Pagination
        Add("resultsPerPage", p.ResultsPerPage);
        Add("startIndex", p.StartIndex);

        // Boolean flags
        Add("hasCertAlerts", p.HasCertAlerts);
        Add("hasCertNotes", p.HasCertNotes);
        Add("hasKev", p.HasKev);
        Add("hasOval", p.HasOval);
        Add("isVulnerable", p.IsVulnerable);
        Add("noRejected", p.NoRejected);
        Add("sourceIdentifier", p.SourceIdentifier);

        return "?" + q.ToString();
    }
}
