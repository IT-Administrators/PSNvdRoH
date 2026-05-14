namespace NvdClient;

/// <summary>
/// High‑level client for interacting with the NVD CVE API v2.0.
/// 
/// Responsibilities:
///   - Manage HttpClient
///   - Attach API key (optional)
///   - Build request URLs
///   - Return raw JSON
/// 
/// JSON parsing is intentionally left to the caller.
/// </summary>
public class NvdApiClient
{
    private readonly HttpClient _http;

    public NvdApiClient(string? apiKey = null)
    {
        _http = new HttpClient();
        if (!string.IsNullOrEmpty(apiKey))
        {
            _http.DefaultRequestHeaders.Add("apiKey", apiKey);
        }
    }

    public async Task<string> GetCvesAsync(CveQueryParameters parameters)
    {
        var query = QueryStringBuilder.ToQueryString(parameters);
        var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0{query}";

        var response = await _http.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"NVD API returned {(int)response.StatusCode} ({response.ReasonPhrase}): {content}");
        }

        return content;
    }
}
