using System.Text.Json.Serialization;

namespace Infisical.Sdk.Model;

public sealed class KmsEncryptRequest
{
  /// <summary>Base64-encoded bytes. The SDK sends this value without encoding it again.</summary>
  [JsonPropertyName("plaintext")]
  public string Plaintext { get; init; } = null!;
}

public sealed class KmsEncryptResponse
{
  /// <summary>Opaque base64 ciphertext. Preserve it unchanged, including its embedded key version.</summary>
  [JsonPropertyName("ciphertext"), JsonRequired]
  public string Ciphertext { get; init; } = null!;
}

public sealed class KmsDecryptRequest
{
  /// <summary>The unchanged base64 ciphertext returned by Infisical encryption.</summary>
  [JsonPropertyName("ciphertext")]
  public string Ciphertext { get; init; } = null!;
}

public sealed class KmsDecryptResponse
{
  /// <summary>Base64-encoded plaintext bytes. Decode once in the caller.</summary>
  [JsonPropertyName("plaintext"), JsonRequired]
  public string Plaintext { get; init; } = null!;
}

public sealed class KmsGenerateMacRequest
{
  /// <summary>Base64-encoded message bytes. The algorithm is configured on the KMS key.</summary>
  [JsonPropertyName("data")]
  public string Data { get; init; } = null!;
}

public sealed class KmsGenerateMacResponse
{
  [JsonPropertyName("mac"), JsonRequired]
  public string Mac { get; init; } = null!;

  [JsonPropertyName("keyId"), JsonRequired]
  public string KeyId { get; init; } = null!;

  [JsonPropertyName("macAlgorithm"), JsonRequired]
  public string MacAlgorithm { get; init; } = null!;
}

public sealed class KmsVerifyMacRequest
{
  [JsonPropertyName("data")]
  public string Data { get; init; } = null!;

  [JsonPropertyName("mac")]
  public string Mac { get; init; } = null!;
}

public sealed class KmsVerifyMacResponse
{
  /// <summary>False is a successful verification response indicating that the MAC does not match.</summary>
  [JsonPropertyName("macValid"), JsonRequired]
  public bool MacValid { get; init; }

  [JsonPropertyName("keyId"), JsonRequired]
  public string KeyId { get; init; } = null!;

  [JsonPropertyName("macAlgorithm"), JsonRequired]
  public string MacAlgorithm { get; init; } = null!;
}

public sealed class KmsGetKeyResponse
{
  [JsonPropertyName("key"), JsonRequired]
  public KmsKeyMetadata Key { get; init; } = null!;
}

/// <summary>Public key metadata only; this model never contains raw key material.</summary>
public sealed class KmsKeyMetadata
{
  [JsonPropertyName("id"), JsonRequired]
  public string Id { get; init; } = null!;

  [JsonPropertyName("name"), JsonRequired]
  public string Name { get; init; } = null!;

  [JsonPropertyName("description")]
  public string? Description { get; init; }

  [JsonPropertyName("orgId"), JsonRequired]
  public string OrgId { get; init; } = null!;

  [JsonPropertyName("projectId")]
  public string? ProjectId { get; init; }

  [JsonPropertyName("createdAt"), JsonRequired]
  public DateTimeOffset CreatedAt { get; init; }

  [JsonPropertyName("updatedAt"), JsonRequired]
  public DateTimeOffset UpdatedAt { get; init; }

  [JsonPropertyName("isDisabled"), JsonRequired]
  public bool? IsDisabled { get; init; }

  [JsonPropertyName("isExportable"), JsonRequired]
  public bool IsExportable { get; init; }

  [JsonPropertyName("hasDeleteProtection"), JsonRequired]
  public bool HasDeleteProtection { get; init; }

  /// <summary>encrypt-decrypt, sign-verify, or generate-verify-mac.</summary>
  [JsonPropertyName("keyUsage"), JsonRequired]
  public string KeyUsage { get; init; } = null!;

  [JsonPropertyName("algorithm"), JsonRequired]
  public string Algorithm { get; init; } = null!;

  /// <summary>Current key-material version, not necessarily the version of previously returned ciphertext.</summary>
  [JsonPropertyName("version"), JsonRequired]
  public int Version { get; init; }
}
