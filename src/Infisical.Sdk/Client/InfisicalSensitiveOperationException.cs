using System.Net;

namespace Infisical.Sdk;

/// <summary>A KMS or universal-auth failure that never includes request or response payloads.</summary>
public sealed class InfisicalSensitiveOperationException : InfisicalException
{
  internal InfisicalSensitiveOperationException(string method, HttpStatusCode? statusCode, string code)
    : base($"Infisical {method} failed (status: {(statusCode.HasValue ? ((int)statusCode.Value).ToString() : "unavailable")}, code: {code}).")
  {
    Method = method;
    StatusCode = statusCode;
    Code = code;
  }

  public string Method { get; }
  public HttpStatusCode? StatusCode { get; }

  /// <summary>SDK error classification: http_error, invalid_response, or transport_error.</summary>
  public string Code { get; }
}
