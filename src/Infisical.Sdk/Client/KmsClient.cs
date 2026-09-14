using Infisical.Sdk.Api;
using Infisical.Sdk.Model;

namespace Infisical.Sdk.Client;

/// <summary>Remote cryptographic operations with non-exported Infisical KMS keys.</summary>
public sealed class KmsClient
{
  private const int MaxDataBytes = 1024 * 1024;
  private const int MaxCiphertextBytes = MaxDataBytes + 1024;
  private const int MaxMacBytes = 1024;
  private readonly ApiClient _apiClient;

  public KmsClient(ApiClient apiClient)
  {
    _apiClient = apiClient ?? throw new ArgumentNullException(nameof(apiClient));
  }

  public Task<KmsEncryptResponse> EncryptAsync(
    string keyId, KmsEncryptRequest request, CancellationToken cancellationToken = default)
  {
    ValidateKeyId(keyId);
    if (request == null) throw new ArgumentNullException(nameof(request));
    ValidateBase64(request.Plaintext, nameof(request.Plaintext), MaxDataBytes, allowEmpty: true);
    return _apiClient.SendSensitiveAsync<KmsEncryptRequest, KmsEncryptResponse>(
      HttpMethod.Post, $"/api/v1/kms/keys/{keyId}/encrypt", request, cancellationToken,
      static response => IsBase64(response.Ciphertext, MaxCiphertextBytes, allowEmpty: false));
  }

  public Task<KmsDecryptResponse> DecryptAsync(
    string keyId, KmsDecryptRequest request, CancellationToken cancellationToken = default)
  {
    ValidateKeyId(keyId);
    if (request == null) throw new ArgumentNullException(nameof(request));
    ValidateBase64(request.Ciphertext, nameof(request.Ciphertext), MaxCiphertextBytes, allowEmpty: false);
    return _apiClient.SendSensitiveAsync<KmsDecryptRequest, KmsDecryptResponse>(
      HttpMethod.Post, $"/api/v1/kms/keys/{keyId}/decrypt", request, cancellationToken,
      static response => IsBase64(response.Plaintext, MaxDataBytes, allowEmpty: true));
  }

  public Task<KmsGenerateMacResponse> GenerateMacAsync(
    string keyId, KmsGenerateMacRequest request, CancellationToken cancellationToken = default)
  {
    ValidateKeyId(keyId);
    if (request == null) throw new ArgumentNullException(nameof(request));
    ValidateBase64(request.Data, nameof(request.Data), MaxDataBytes, allowEmpty: true);
    return _apiClient.SendSensitiveAsync<KmsGenerateMacRequest, KmsGenerateMacResponse>(
      HttpMethod.Post, $"/api/v1/kms/keys/{keyId}/generate-mac", request, cancellationToken,
      response => IsBase64(response.Mac, MaxMacBytes, allowEmpty: false)
        && string.Equals(response.KeyId, keyId, StringComparison.OrdinalIgnoreCase)
        && IsMacAlgorithm(response.MacAlgorithm));
  }

  public Task<KmsVerifyMacResponse> VerifyMacAsync(
    string keyId, KmsVerifyMacRequest request, CancellationToken cancellationToken = default)
  {
    ValidateKeyId(keyId);
    if (request == null) throw new ArgumentNullException(nameof(request));
    ValidateBase64(request.Data, nameof(request.Data), MaxDataBytes, allowEmpty: true);
    ValidateBase64(request.Mac, nameof(request.Mac), MaxMacBytes, allowEmpty: true);
    return _apiClient.SendSensitiveAsync<KmsVerifyMacRequest, KmsVerifyMacResponse>(
      HttpMethod.Post, $"/api/v1/kms/keys/{keyId}/verify-mac", request, cancellationToken,
      response => string.Equals(response.KeyId, keyId, StringComparison.OrdinalIgnoreCase)
        && IsMacAlgorithm(response.MacAlgorithm));
  }

  public Task<KmsGetKeyResponse> GetKeyAsync(string keyId, CancellationToken cancellationToken = default)
  {
    ValidateKeyId(keyId);
    return _apiClient.SendSensitiveAsync<object?, KmsGetKeyResponse>(
      HttpMethod.Get, $"/api/v1/kms/keys/{keyId}", null, cancellationToken,
      response => response.Key != null
        && string.Equals(response.Key.Id, keyId, StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(response.Key.Name)
        && !string.IsNullOrWhiteSpace(response.Key.OrgId)
        && !string.IsNullOrWhiteSpace(response.Key.KeyUsage)
        && !string.IsNullOrWhiteSpace(response.Key.Algorithm)
        && response.Key.Version > 0);
  }

  private static void ValidateKeyId(string keyId)
  {
    if (!Guid.TryParseExact(keyId, "D", out var id) || id == Guid.Empty)
    {
      throw new ArgumentException("A non-empty KMS key UUID is required.", nameof(keyId));
    }
  }

  private static bool IsMacAlgorithm(string algorithm)
  {
    return algorithm is "HMAC_SHA_1" or "HMAC_SHA_224" or "HMAC_SHA_256" or "HMAC_SHA_384" or "HMAC_SHA_512";
  }

  private static void ValidateBase64(string value, string parameterName, int maxBytes, bool allowEmpty)
  {
    if (!IsBase64(value, maxBytes, allowEmpty))
    {
      throw new ArgumentException($"A valid base64 value of at most {maxBytes} decoded bytes is required.", parameterName);
    }
  }

  // Validate wire encoding without allocating or decoding sensitive bytes merely to discard them.
  private static bool IsBase64(string? value, int maxBytes, bool allowEmpty)
  {
    if (value == null || (value.Length == 0 && !allowEmpty) || value.Length % 4 != 0) return false;
    if (value.Length == 0) return true;
    var padding = value[value.Length - 1] == '=' ? (value[value.Length - 2] == '=' ? 2 : 1) : 0;
    if ((long)value.Length / 4 * 3 - padding > maxBytes) return false;
    for (var i = 0; i < value.Length - padding; i++)
    {
      var character = value[i];
      if (!(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/')) return false;
    }
    return true;
  }
}
