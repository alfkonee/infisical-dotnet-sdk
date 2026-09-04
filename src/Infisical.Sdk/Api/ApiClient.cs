
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;
using Polly;
using Polly.Extensions.Http;

namespace Infisical.Sdk.Api
{
  public class InfisicalException : Exception
  {
    public InfisicalException(string message) : base(message) { }
    public InfisicalException(string message, Exception innerException) : base(message, innerException) { }
  }

  public class ApiClient : IDisposable
  {
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private string? _accessToken;
    private string _baseUrl;

    private static readonly IAsyncPolicy<HttpResponseMessage> RetryPolicy =
    HttpPolicyExtensions
        .HandleTransientHttpError() // HttpRequestException and 5XX/408 responses
        .OrResult(msg => msg.StatusCode == (System.Net.HttpStatusCode)429)
        .WaitAndRetryAsync(3, retryAttempt =>
            TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
            onRetry: (outcome, _) => outcome.Result?.Dispose());

    public ApiClient(string baseUrl, string? accessToken = null)
      : this(baseUrl, new HttpClient(), accessToken, true)
    {
    }

    /// <summary>Uses a caller-owned HTTP client, which is not disposed by this API client.</summary>
    public ApiClient(HttpClient httpClient, string baseUrl, string? accessToken = null)
      : this(baseUrl, httpClient, accessToken, false)
    {
    }

    private ApiClient(string baseUrl, HttpClient httpClient, string? accessToken, bool ownsHttpClient)
    {
      _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
      _ownsHttpClient = ownsHttpClient;
      _baseUrl = baseUrl;
      _accessToken = accessToken;
      FormatBaseUrl();
    }

    public void SetAccessToken(string accessToken)
    {
      _accessToken = accessToken;
    }

    private void FormatBaseUrl()
    {
      // Remove trailing slash if present
      if (_baseUrl.EndsWith("/"))
      {
        _baseUrl = _baseUrl.Substring(0, _baseUrl.Length - 1);
      }

      // Check if URL starts with protocol
      if (!System.Text.RegularExpressions.Regex.IsMatch(_baseUrl, @"^[a-zA-Z]+://.*"))
      {
        _baseUrl = "https://" + _baseUrl;
      }

      // Remove /api if present at the end
      if (_baseUrl.EndsWith("/api"))
      {
        _baseUrl = _baseUrl.Substring(0, _baseUrl.Length - 4);
      }
    }

    public string GetBaseUrl()
    {
      return _baseUrl;
    }

    public HttpClient GetClient()
    {
      return _httpClient;
    }

    private async Task<string> FormatErrorMessageAsync(HttpResponseMessage response)
    {
      var message = $"Unexpected response: {response.StatusCode} {response.ReasonPhrase}";

      try
      {
        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!string.IsNullOrEmpty(content))
        {
          message += $" - {content}";
        }
      }
      catch
      {
        // If we can't read the error content, just use the status message
      }

      return message;
    }

    internal Task<ApiResponse<TResponse>> PostForResponseAsync<TRequest, TResponse>(
      string url, TRequest requestBody, bool omitNullValues = false, CancellationToken cancellationToken = default)
    {
      return SendForResponseAsync<TRequest, TResponse>(
        HttpMethod.Post, url, requestBody, omitNullValues, false, false, cancellationToken);
    }

    internal async Task<TResponse> SendSensitiveAsync<TRequest, TResponse>(
      HttpMethod method, string url, TRequest requestBody, CancellationToken cancellationToken,
      Func<TResponse, bool> validateResponse, bool retry = true)
    {
      var response = await SendForResponseAsync<TRequest, TResponse>(
        method, url, requestBody, true, true, retry, cancellationToken, validateResponse).ConfigureAwait(false);
      return response.Value!;
    }

    private async Task<ApiResponse<TResponse>> SendForResponseAsync<TRequest, TResponse>(
      HttpMethod method, string url, TRequest requestBody, bool omitNullValues, bool sensitive,
      bool retry, CancellationToken cancellationToken, Func<TResponse, bool>? validateResponse = null)
    {
      System.Net.HttpStatusCode? statusCode = null;
      try
      {
        cancellationToken.ThrowIfCancellationRequested();
        // ResponseHeadersRead ends HttpClient's own timeout at headers; keep one deadline
        // across retries, backoff, and the complete response body.
        var timeout = _httpClient.Timeout;
        using var timeoutSource = timeout == Timeout.InfiniteTimeSpan ? null
          : cancellationToken.CanBeCanceled
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, CancellationToken.None)
            : new CancellationTokenSource();
        timeoutSource?.CancelAfter(timeout);
        var operationToken = timeoutSource?.Token ?? cancellationToken;
        // One cryptographic operation must not change machine identities between retry attempts.
        var accessToken = _accessToken;
        var jsonContent = method == HttpMethod.Get ? null : JsonSerializer.Serialize(requestBody,
          omitNullValues ? new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull } : null);

        async Task<HttpResponseMessage> SendAsync(CancellationToken token)
        {
          using var request = new HttpRequestMessage(method, new Uri(new Uri(_baseUrl), url));
          if (jsonContent != null)
          {
            request.Content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
          }
          request.Headers.Add("Accept", "application/json");
          if (!string.IsNullOrEmpty(accessToken))
          {
            request.Headers.Add("Authorization", $"Bearer {accessToken}");
          }
          return await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        }

        using var response = retry
          ? await RetryPolicy.ExecuteAsync(SendAsync, operationToken).ConfigureAwait(false)
          : await SendAsync(operationToken).ConfigureAwait(false);
        statusCode = response.StatusCode;
        if (sensitive && !response.IsSuccessStatusCode)
        {
          throw new InfisicalSensitiveOperationException(method.Method, statusCode, "http_error");
        }

        var responseContent = await ReadContentAsync(response.Content, operationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
          return ApiResponse<TResponse>.Failure(response.StatusCode, response.ReasonPhrase, responseContent);
        }
        if (string.IsNullOrEmpty(responseContent))
        {
          if (sensitive)
          {
            throw new InfisicalSensitiveOperationException(method.Method, statusCode, "invalid_response");
          }
          throw new HttpRequestException("Response body is null or empty");
        }
        var result = JsonSerializer.Deserialize<TResponse>(responseContent, new JsonSerializerOptions
        {
          PropertyNameCaseInsensitive = true
        });
        operationToken.ThrowIfCancellationRequested();
        if (result == null || (validateResponse != null && !validateResponse(result)))
        {
          if (sensitive)
          {
            throw new InfisicalSensitiveOperationException(method.Method, statusCode, "invalid_response");
          }
          throw new InfisicalException("Failed to deserialize response content");
        }
        return ApiResponse<TResponse>.Success(response.StatusCode,
          sensitive ? null : response.ReasonPhrase, sensitive ? string.Empty : responseContent, result);
      }
      catch (OperationCanceledException ex) when (sensitive)
      {
        // Preserve cancellation without retaining a handler's potentially sensitive message or inner exception.
        throw new OperationCanceledException("Infisical request canceled.",
          cancellationToken.IsCancellationRequested ? cancellationToken : ex.CancellationToken);
      }
      catch (Exception ex) when (sensitive && !(ex is InfisicalSensitiveOperationException))
      {
        // Do not retain an inner exception: JSON and transport errors may contain sensitive input.
        throw new InfisicalSensitiveOperationException(method.Method, statusCode,
          ex is JsonException ? "invalid_response" : "transport_error");
      }
    }

    private static async Task<string> ReadContentAsync(HttpContent content, CancellationToken cancellationToken)
    {
#if NET5_0_OR_GREATER
      return await content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
#else
      // Older targets do not offer cancellable HttpContent reads. Disposing content aborts the read.
      using (cancellationToken.Register(content.Dispose))
      {
        try
        {
          var result = await content.ReadAsStringAsync().ConfigureAwait(false);
          cancellationToken.ThrowIfCancellationRequested();
          return result;
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
          throw new OperationCanceledException(cancellationToken);
        }
      }
#endif
    }

    public Task<TResponse> PostAsync<TRequest, TResponse>(
      string url, TRequest requestBody, bool omitNullValues = false)
    {
      return PostAsync<TRequest, TResponse>(url, requestBody, omitNullValues, CancellationToken.None);
    }

    public async Task<TResponse> PostAsync<TRequest, TResponse>(
      string url, TRequest requestBody, bool omitNullValues, CancellationToken cancellationToken)
    {
      try
      {
        var response = await PostForResponseAsync<TRequest, TResponse>(url, requestBody, omitNullValues, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
          throw new HttpRequestException(response.FormatErrorMessage());
        }

        return response.Value!;
      }
      catch (Exception ex) when (!(ex is InfisicalException) && !(ex is OperationCanceledException))
      {
        throw new InfisicalException($"Error during POST request: {ex.Message}", ex);
      }
    }

    public async Task<TResponse> GetAsync<TResponse>(string url, Dictionary<string, string>? queryParams = null)
    {
      try
      {
        var uriBuilder = new UriBuilder(new Uri(new Uri(_baseUrl), url));

        if (queryParams != null && queryParams.Count > 0)
        {
          var query = HttpUtility.ParseQueryString(string.Empty);
          foreach (var param in queryParams)
          {
            query[param.Key] = param.Value;
          }
          uriBuilder.Query = query.ToString();
        }


        var response = await RetryPolicy.ExecuteAsync(async () =>
        {
          using var request = new HttpRequestMessage(HttpMethod.Get, uriBuilder.Uri);
          request.Headers.Add("Accept", "application/json");

          if (!string.IsNullOrEmpty(_accessToken))
          {
            request.Headers.Add("Authorization", $"Bearer {_accessToken}");
          }
          return await _httpClient.SendAsync(request).ConfigureAwait(false);
        }).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
          var errorMessage = await FormatErrorMessageAsync(response).ConfigureAwait(false);
          throw new HttpRequestException(errorMessage);
        }

        var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (string.IsNullOrEmpty(responseContent))
        {
          throw new HttpRequestException("Response body is null or empty");
        }

        var result = JsonSerializer.Deserialize<TResponse>(responseContent, new JsonSerializerOptions
        {
          PropertyNameCaseInsensitive = true
        });

        if (result == null)
        {
          throw new InfisicalException("Failed to deserialize response content");
        }

        return result;
      }
      catch (Exception ex) when (!(ex is InfisicalException))
      {
        throw new InfisicalException($"Error during GET request: {ex.Message}", ex);
      }
    }

    public async Task<TResponse> PatchAsync<TRequest, TResponse>(string url, TRequest requestBody, bool omitNullValues = false)
    {
      try
      {
        var jsonContent = omitNullValues ? JsonSerializer.Serialize(requestBody, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }) : JsonSerializer.Serialize(requestBody);
        var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

        var request = new HttpRequestMessage(new HttpMethod("PATCH"), new Uri(new Uri(_baseUrl), url))
        {
          Content = content
        };

        request.Headers.Add("Accept", "application/json");

        if (!string.IsNullOrEmpty(_accessToken))
        {
          request.Headers.Add("Authorization", $"Bearer {_accessToken}");
        }

        var response = await _httpClient.SendAsync(request).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
          var errorMessage = await FormatErrorMessageAsync(response).ConfigureAwait(false);
          throw new HttpRequestException(errorMessage);
        }

        var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (string.IsNullOrEmpty(responseContent))
        {
          throw new HttpRequestException("Response body is null or empty");
        }

        var result = JsonSerializer.Deserialize<TResponse>(responseContent, new JsonSerializerOptions
        {
          PropertyNameCaseInsensitive = true
        });

        if (result == null)
        {
          throw new InfisicalException("Failed to deserialize response content");
        }

        return result;
      }
      catch (Exception ex) when (!(ex is InfisicalException))
      {
        throw new InfisicalException($"Error during PATCH request: {ex.Message}", ex);
      }
    }

    public async Task<TResponse> DeleteAsync<TRequest, TResponse>(string url, TRequest requestBody, bool omitNullValues = false)
    {
      try
      {
        var jsonContent = omitNullValues ? JsonSerializer.Serialize(requestBody, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }) : JsonSerializer.Serialize(requestBody);
        var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

        var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(new Uri(_baseUrl), url))
        {
          Content = content
        };

        request.Headers.Add("Accept", "application/json");

        if (!string.IsNullOrEmpty(_accessToken))
        {
          request.Headers.Add("Authorization", $"Bearer {_accessToken}");
        }

        var response = await _httpClient.SendAsync(request).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
          var errorMessage = await FormatErrorMessageAsync(response).ConfigureAwait(false);
          throw new HttpRequestException(errorMessage);
        }

        var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (string.IsNullOrEmpty(responseContent))
        {
          throw new HttpRequestException("Response body is null or empty");
        }

        var result = JsonSerializer.Deserialize<TResponse>(responseContent, new JsonSerializerOptions
        {
          PropertyNameCaseInsensitive = true
        });

        if (result == null)
        {
          throw new InfisicalException("Failed to deserialize response content");
        }

        return result;
      }
      catch (Exception ex) when (!(ex is InfisicalException))
      {
        throw new InfisicalException($"Error during DELETE request: {ex.Message}", ex);
      }
    }

    public void Dispose()
    {
      if (_ownsHttpClient)
      {
        _httpClient.Dispose();
      }
    }
  }

  public class QueryBuilder
  {
    private readonly Dictionary<string, string> _params = new Dictionary<string, string>();

    public QueryBuilder Add(string key, object value)
    {
      if (value != null)
      {
#pragma warning disable CS8601 // Possible null reference assignment.
        _params[key] = value.ToString();
#pragma warning restore CS8601 // Possible null reference assignment.
      }
      return this;
    }

    public Dictionary<string, string> Build()
    {
      return new Dictionary<string, string>(_params);
    }
  }

  internal class ApiResponse<T>
  {
    private ApiResponse(System.Net.HttpStatusCode statusCode, string? reasonPhrase, string content, T? value, bool isSuccessStatusCode)
    {
      StatusCode = statusCode;
      ReasonPhrase = reasonPhrase;
      Content = content;
      Value = value;
      IsSuccessStatusCode = isSuccessStatusCode;
    }

    public System.Net.HttpStatusCode StatusCode { get; }
    public string? ReasonPhrase { get; }
    public string Content { get; }
    public T? Value { get; }
    public bool IsSuccessStatusCode { get; }

    public static ApiResponse<T> Success(System.Net.HttpStatusCode statusCode, string? reasonPhrase, string content, T value)
    {
      return new ApiResponse<T>(statusCode, reasonPhrase, content, value, true);
    }

    public static ApiResponse<T> Failure(System.Net.HttpStatusCode statusCode, string? reasonPhrase, string content)
    {
      return new ApiResponse<T>(statusCode, reasonPhrase, content, default, false);
    }

    public string FormatErrorMessage()
    {
      var message = $"Unexpected response: {StatusCode} {ReasonPhrase}";
      if (!string.IsNullOrEmpty(Content))
      {
        message += $" - {Content}";
      }

      return message;
    }
  }
}
