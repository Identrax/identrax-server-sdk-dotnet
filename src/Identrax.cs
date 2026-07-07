using System.Text;
using System.Text.Json;

namespace Identrax;

/// <summary>
/// The org-surface client (blueprint §10.1): key + secret in, automatic
/// token refresh, methods mirroring the API. HttpClient + System.Text.Json.
/// </summary>
public sealed class ApiException(int status, string message)
    : Exception($"identrax: HTTP {status}: {message}")
{
    public int Status { get; } = status;
}

public sealed class IdentraxClient(string baseUrl, string keyId, string secret)
{
    private readonly HttpClient _http = new();
    private readonly string _baseUrl = baseUrl.TrimEnd('/');
    private string? _token;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    private async Task<string> AccessTokenAsync()
    {
        if (_token is not null && DateTimeOffset.UtcNow < _expiresAt.AddSeconds(-60))
            return _token;
        var payload = JsonSerializer.Serialize(new { key_id = keyId, secret });
        var response = await _http.PostAsync(
            $"{_baseUrl}/v2/org/oauth/token",
            new StringContent(payload, Encoding.UTF8, "application/json"));
        var body = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new ApiException((int)response.StatusCode, body);
        using var doc = JsonDocument.Parse(body);
        _token = doc.RootElement.GetProperty("access_token").GetString();
        _expiresAt = DateTimeOffset.UtcNow.AddSeconds(
            doc.RootElement.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 3600);
        return _token!;
    }

    public async Task<JsonElement> RequestAsync(HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, $"{_baseUrl}{path}");
        request.Headers.Add("authorization", $"Bearer {await AccessTokenAsync()}");
        if (body is not null)
            request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        var response = await _http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new ApiException((int)response.StatusCode, text);
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    public Task<JsonElement> CreateVerificationAsync(string subjectNin, string[] scopes, string purpose) =>
        RequestAsync(HttpMethod.Post, "/v2/org/verifications",
            new { subject_nin = subjectNin, scopes, purpose });

    public Task<JsonElement> GetProofAsync(string token) =>
        RequestAsync(HttpMethod.Get, $"/v2/org/proofs/{token}");

    public Task<JsonElement> RunScreeningAsync(string subjectRef, string[] kinds) =>
        RequestAsync(HttpMethod.Post, "/v2/org/screening", new { subject_ref = subjectRef, kinds });

    public Task<JsonElement> VerifyBusinessAsync(string rcNumber) =>
        RequestAsync(HttpMethod.Post, "/v2/org/business-verifications", new { rc_number = rcNumber });

    public Task<JsonElement> CompliancePostureAsync() =>
        RequestAsync(HttpMethod.Get, "/v2/org/compliance/posture");
}
