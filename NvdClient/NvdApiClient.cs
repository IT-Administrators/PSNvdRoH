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
        return await _http.GetStringAsync(url);
    }
}
