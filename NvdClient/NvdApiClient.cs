namespace NvdClient;

/// <summary>
/// Class to query the NVD api
/// </summary>
public class NvdApiClient
{
    private readonly HttpClient _http;

    /// <summary>
    /// Build the authentication header for the request
    /// </summary>
    /// <param name="apiKey"></param>
    public NvdApiClient(string apiKey)
    {
        _http = new HttpClient();
        _http.DefaultRequestHeaders.Add("apiKey", apiKey);
    }
    /// <summary>
    /// Get all cves
    /// </summary>
    /// <param name="query"></param>
    /// <returns></returns>
    public async Task<string> GetCvesAsync(string query)
    {
        var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0{query}";
        return await _http.GetStringAsync(url);
    }
}
