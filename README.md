<h1 align="center">
  <img width="300" src="/img/logoname-white.svg#gh-dark-mode-only" alt="infisical">
</h1>
<p align="center">
  <p align="center"><b>Infisical .NET SDK</b></p>
<h4 align="center">
|
  <a href="https://infisical.com/docs/sdks/languages/dotnet">Documentation</a> |
  <a href="https://www.infisical.com">Website</a> |
  <a href="https://infisical.com/slack">Slack</a> |
</h4>

<h4 align="center">
  <a href="https://github.com/Infisical/infisical-dotnet-sdk/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Infisical SDK's are released under the MIT license." />
  </a>
  <a href="https://infisical.com/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
  <a href="https://twitter.com/infisical">
    <img src="https://img.shields.io/twitter/follow/infisical?label=Follow" alt="Infisical Twitter" />
  </a>
</h4>

## Introduction

**[Infisical](https://infisical.com)** is the open source secret management platform that teams use to centralize their secrets like API keys, database credentials, and configurations.

If you’re working with .NET, the official Infisical .NET SDK package is the easiest way to fetch and work with secrets for your application. You can read the documentation [here](https://infisical.com/docs/sdks/languages/dotnet).

## Documentation
You can find the documentation for the .NET SDK on our [SDK documentation page](https://infisical.com/docs/sdks/languages/dotnet).

### Key management service (KMS)

Use `client.Kms()` with an authenticated `InfisicalClient`. The client supports:

| Method | Operation |
| --- | --- |
| `EncryptAsync` | Encrypt Base64-encoded bytes with an encrypt/decrypt key. |
| `DecryptAsync` | Decrypt opaque Base64 ciphertext using its original key ID. |
| `GetKeyAsync` | Read public key metadata, without exporting key material. |
| `GenerateMacAsync` | Generate a MAC using the algorithm configured on the key. |
| `VerifyMacAsync` | Verify a MAC; an ordinary mismatch returns `MacValid == false`. |

All methods accept a `CancellationToken`. Key IDs must be UUIDs in standard hyphenated form. Binary request fields are already Base64-encoded strings: the SDK validates them and does not encode them again.

```csharp
using System;
using System.Text;
using Infisical.Sdk.Model;

// client is authenticated; keyId identifies an encrypt/decrypt KMS key.
var encrypted = await client.Kms().EncryptAsync(
    keyId,
    new KmsEncryptRequest
    {
        Plaintext = Convert.ToBase64String(Encoding.UTF8.GetBytes("example payload"))
    },
    cancellationToken);

// Store encrypted.Ciphertext unchanged together with keyId.
var decrypted = await client.Kms().DecryptAsync(
    keyId,
    new KmsDecryptRequest { Ciphertext = encrypted.Ciphertext },
    cancellationToken);

byte[] plaintext = Convert.FromBase64String(decrypted.Plaintext);
// Consume securely; do not log plaintext or retain sensitive buffers unnecessarily.
```

For envelope encryption, generate the data-encryption key locally and encrypt that key through `EncryptAsync`. Infisical does not expose a public generate-data-key operation. The SDK does not parse the ciphertext envelope or provide undocumented AAD/version-selection parameters. `GetKeyAsync` reports current metadata; it does not atomically identify which native key version a concurrent encrypt request used. MAC keys require a new key ID for rotation.

KMS and Universal Auth failures use `InfisicalSensitiveOperationException` with safe `Method`, `StatusCode`, and `Code` fields, without echoing sensitive payloads or server response bodies. Cancellation remains `OperationCanceledException`. Configure logging and any caller-supplied HTTP handlers accordingly: Base64 does not make payloads safe to log. Infisical's server-side MAC audit events may include generated/verified MAC values; review provider audit privacy separately from SDK logging.

`InfisicalClient(settings, httpClient)` accepts a caller-owned `HttpClient`; disposing the SDK client does not dispose that supplied client. The original constructor creates and owns its HTTP client.

See the [Infisical KMS documentation](https://infisical.com/docs/documentation/platform/kms/overview) for key creation, machine-identity permissions, and server availability.

## Security

Please do not file GitHub issues or post on our public forum for security vulnerabilities, as they are public!

Infisical takes security issues very seriously. If you have any concerns about Infisical or believe you have uncovered a vulnerability, please get in touch via the e-mail address security@infisical.com. In the message, try to provide a description of the issue and ideally a way of reproducing it. The security team will get back to you as soon as possible.

Note that this security address should be used only for undisclosed vulnerabilities. Please report any security problems to us before disclosing it publicly.