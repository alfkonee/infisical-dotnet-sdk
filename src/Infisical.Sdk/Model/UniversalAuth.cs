using System.Text.Json.Serialization;

namespace Infisical.Sdk.Model;

// Keep strict universal-auth wire validation separate from the existing public credential/LDAP contract.
internal sealed class UniversalAuthLoginResponse
{
  [JsonPropertyName("accessToken"), JsonRequired]
  public string AccessToken { get; init; } = null!;

  [JsonPropertyName("expiresIn"), JsonRequired]
  public decimal ExpiresIn { get; init; }

  [JsonPropertyName("accessTokenMaxTTL"), JsonRequired]
  public decimal AccessTokenMaxTTL { get; init; }

  [JsonPropertyName("tokenType"), JsonRequired]
  public string TokenType { get; init; } = null!;
}
