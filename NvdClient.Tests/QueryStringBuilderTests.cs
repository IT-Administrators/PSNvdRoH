using System;
using System.Linq;
using System.Web;
using NvdClient;
using Xunit;

namespace NvdClient.Tests
{
    public class QueryStringBuilderTests
    {
        [Fact]
        public void ToQueryString_IncludesAllSupportedParameters()
        {
            var parameters = new CveQueryParameters
            {
                KeywordSearch = new[] { "openssl", "kernel" },
                KeywordExactMatch = true,
                CveID = "CVE-2025-1234",
                CveTag = CveTag.UnsupportedWhenAssigned,
                CpeName = "cpe:2.3:a:apache:http_server:2.4.54",
                CvssV2Severity = CvssV2Severity.HIGH,
                CvssV2Metrics = "5.0",
                CpeMatchString = true,
                PubStartDate = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                PubEndDate = new DateTime(2025, 1, 31, 23, 59, 59, DateTimeKind.Utc),
                LastModStartDate = new DateTime(2025, 2, 1, 0, 0, 0, DateTimeKind.Utc),
                LastModEndDate = new DateTime(2025, 2, 28, 23, 59, 59, DateTimeKind.Utc),
                KevStartDate = new DateTime(2025, 3, 1, 0, 0, 0, DateTimeKind.Utc),
                KevEndDate = new DateTime(2025, 3, 15, 0, 0, 0, DateTimeKind.Utc),
                SourceIdentifier = "cisa",
                ResultsPerPage = 100,
                StartIndex = 0,
                HasCertAlerts = true,
                HasCertNotes = true,
                HasKev = true,
                HasOval = true,
                IsVulnerable = true,
                NoRejected = true
            };

            var query = QueryStringBuilder.ToQueryString(parameters);
            var values = HttpUtility.ParseQueryString(query.Substring(1));

            Assert.Equal("openssl", values.GetValues("keywordSearch")![0]);
            Assert.Equal("kernel", values.GetValues("keywordSearch")![1]);
            Assert.Equal("True", values["keywordExactMatch"]);
            Assert.Equal("CVE-2025-1234", values["cveID"]);
            Assert.Equal("unsupported-when-assigned", values["cveTag"]);
            Assert.Equal("cpe:2.3:a:apache:http_server:2.4.54", values["cpeName"]);
            Assert.Equal("HIGH", values["cvssV2Severity"]);
            Assert.Equal("5.0", values["cvssV2Metrics"]);
            Assert.Equal("True", values["cpeMatchString"]);
            Assert.Equal(parameters.PubStartDate!.Value.ToString("o"), values["pubStartDate"]);
            Assert.Equal(parameters.PubEndDate!.Value.ToString("o"), values["pubEndDate"]);
            Assert.Equal(parameters.LastModStartDate!.Value.ToString("o"), values["lastModStartDate"]);
            Assert.Equal(parameters.LastModEndDate!.Value.ToString("o"), values["lastModEndDate"]);
            Assert.Equal(parameters.KevStartDate!.Value.ToString("o"), values["kevStartDate"]);
            Assert.Equal(parameters.KevEndDate!.Value.ToString("o"), values["kevEndDate"]);
            Assert.Equal("cisa", values["sourceIdentifier"]);
            Assert.Equal("100", values["resultsPerPage"]);
            Assert.Equal("0", values["startIndex"]);
            Assert.Equal("True", values["hasCertAlerts"]);
            Assert.Equal("True", values["hasCertNotes"]);
            Assert.Equal("True", values["hasKev"]);
            Assert.Equal("True", values["hasOval"]);
            Assert.Equal("True", values["isVulnerable"]);
            Assert.Equal("True", values["noRejected"]);
        }

        [Fact]
        public void ToQueryString_ThrowsWhenMultipleMetricParametersAreSpecified()
        {
            var parameters = new CveQueryParameters
            {
                CvssV2Metrics = "5.0",
                CvssV3Metrics = "6.0"
            };

            var ex = Assert.Throws<InvalidOperationException>(() => QueryStringBuilder.ToQueryString(parameters));
            Assert.Contains("Only one CVSS metrics parameter", ex.Message);
        }

        [Fact]
        public void ToQueryString_ThrowsWhenMultipleSeverityParametersAreSpecified()
        {
            var parameters = new CveQueryParameters
            {
                CvssV2Severity = CvssV2Severity.LOW,
                CvssV3Severity = CvssV3Severity.MEDIUM
            };

            var ex = Assert.Throws<InvalidOperationException>(() => QueryStringBuilder.ToQueryString(parameters));
            Assert.Contains("Only one CVSS severity parameter", ex.Message);
        }

        [Fact]
        public void ToQueryString_ThrowsWhenPubDatePairIsIncomplete()
        {
            var parameters = new CveQueryParameters
            {
                PubStartDate = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            };

            var ex = Assert.Throws<InvalidOperationException>(() => QueryStringBuilder.ToQueryString(parameters));
            Assert.Contains("pubStartDate and pubEndDate", ex.Message);
        }

        [Fact]
        public void ToQueryString_ThrowsWhenLastModDatePairIsIncomplete()
        {
            var parameters = new CveQueryParameters
            {
                LastModEndDate = new DateTime(2025, 2, 1, 0, 0, 0, DateTimeKind.Utc)
            };

            var ex = Assert.Throws<InvalidOperationException>(() => QueryStringBuilder.ToQueryString(parameters));
            Assert.Contains("lastModStartDate and lastModEndDate", ex.Message);
        }

        [Fact]
        public void ToQueryString_ThrowsWhenKeywordExactMatchWithoutKeywords()
        {
            var parameters = new CveQueryParameters
            {
                KeywordExactMatch = true
            };

            var ex = Assert.Throws<InvalidOperationException>(() => QueryStringBuilder.ToQueryString(parameters));
            Assert.Contains("keywordExactMatch requires keywordSearch", ex.Message);
        }

        [Fact]
        public void ToQueryString_ThrowsWhenIsVulnerableWithoutCpeName()
        {
            var parameters = new CveQueryParameters
            {
                IsVulnerable = true
            };

            var ex = Assert.Throws<InvalidOperationException>(() => QueryStringBuilder.ToQueryString(parameters));
            Assert.Contains("isVulnerable requires cpeName", ex.Message);
        }
    }
}
