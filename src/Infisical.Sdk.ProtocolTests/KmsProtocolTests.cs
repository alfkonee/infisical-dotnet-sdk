using System.Net;
using System.Text;
using System.Text.Json;
using Infisical.Sdk.Api;
using Infisical.Sdk.Model;
using Xunit;

namespace Infisical.Sdk.ProtocolTests;

public sealed class KmsProtocolTests
{
  private const string KeyId = "534bb50c-2f53-4e5d-9f15-5f2c09d35740";
  private const string Token = "test-identity-access-token";
  private static readonly InfisicalSdkSettings Settings = new InfisicalSdkSettingsBuilder()
    .WithHostUri("https://kms.example.test/api/").Build();

  [Fact]
  public async Task Universal_auth_encrypt_and_decrypt_preserve_exact_base64_and_bearer()
  {
    var plaintext = Convert.ToBase64String(new byte[] { 0, 255, 128, 1, 13, 10, 240 });
    var ciphertext = Convert.ToBase64String(new byte[] { 255, 0, 254, 0, 1, 2, 3, 118, 48, 50 });
    using var handler = new ProtocolHandler((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath switch
    {
      "/api/v1/auth/universal-auth/login" => Json(new { accessToken = Token, expiresIn = 3600, accessTokenMaxTTL = 7200, tokenType = "Bearer" }),
      var path when path.EndsWith("/encrypt") => Json(new { ciphertext }),
      _ => Json(new { plaintext })
    }));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);

    var credential = await client.Auth().UniversalAuth().LoginAsync("identity-id", "identity-secret");
    var encrypted = await client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = plaintext });
    var decrypted = await client.Kms().DecryptAsync(KeyId, new KmsDecryptRequest { Ciphertext = encrypted.Ciphertext });

    Assert.Equal(Token, credential.AccessToken);
    Assert.Equal(ciphertext, encrypted.Ciphertext);
    Assert.Equal(plaintext, decrypted.Plaintext);
    Assert.Equal(new byte[] { 0, 255, 128, 1, 13, 10, 240 }, Convert.FromBase64String(decrypted.Plaintext));
    Assert.Equal(3, handler.Requests.Count);
    AssertRequest(handler.Requests[0], "/api/v1/auth/universal-auth/login", new { clientId = "identity-id", clientSecret = "identity-secret" }, null);
    AssertRequest(handler.Requests[1], $"/api/v1/kms/keys/{KeyId}/encrypt", new { plaintext });
    AssertRequest(handler.Requests[2], $"/api/v1/kms/keys/{KeyId}/decrypt", new { ciphertext });
  }

  [Fact]
  public async Task Mac_generation_and_false_verification_use_the_key_algorithm_and_exact_wire_contract()
  {
    const string data = "AP/+AQ==";
    const string mac = "dGVzdC1tYWM=";
    using var handler = new ProtocolHandler((request, _) => Task.FromResult(
      request.RequestUri!.AbsolutePath.EndsWith("/generate-mac")
        ? Json(new { mac, keyId = KeyId, macAlgorithm = "HMAC_SHA_256" })
        : Json(new { macValid = false, keyId = KeyId, macAlgorithm = "HMAC_SHA_256" })));
    using var http = new HttpClient(handler);
    using var api = new ApiClient(http, Settings.HostUri, Token);
    var kms = new Client.KmsClient(api);

    var generated = await kms.GenerateMacAsync(KeyId, new KmsGenerateMacRequest { Data = data });
    var verified = await kms.VerifyMacAsync(KeyId, new KmsVerifyMacRequest { Data = data, Mac = generated.Mac });

    Assert.Equal(mac, generated.Mac);
    Assert.Equal("HMAC_SHA_256", generated.MacAlgorithm);
    Assert.False(verified.MacValid);
    Assert.Equal(KeyId, verified.KeyId);
    AssertRequest(handler.Requests[0], $"/api/v1/kms/keys/{KeyId}/generate-mac", new { data });
    AssertRequest(handler.Requests[1], $"/api/v1/kms/keys/{KeyId}/verify-mac", new { data, mac });
  }

  [Fact]
  public async Task Empty_base64_mac_is_sent_for_server_verification_and_returns_false()
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(
      Json(new { macValid = false, keyId = KeyId, macAlgorithm = "HMAC_SHA_256" })));
    using var http = new HttpClient(handler);
    using var api = new ApiClient(http, Settings.HostUri, Token);
    var result = await new Client.KmsClient(api).VerifyMacAsync(KeyId,
      new KmsVerifyMacRequest { Data = "", Mac = "" });
    Assert.False(result.MacValid);
    AssertRequest(Assert.Single(handler.Requests), $"/api/v1/kms/keys/{KeyId}/verify-mac", new { data = "", mac = "" });
  }

  [Fact]
  public async Task Key_metadata_is_read_only_and_reports_current_version_without_exporting_key_material()
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Json(new
    {
      key = new
      {
        id = KeyId, name = "subscriber-encryption", description = (string?)null,
        orgId = "41dc8d31-33b7-46c0-a93c-5e1f3bdb3e9e", projectId = (string?)null,
        createdAt = "2026-09-01T00:00:00Z", updatedAt = "2026-09-02T00:00:00Z",
        isDisabled = (bool?)null, isExportable = false, hasDeleteProtection = true,
        keyUsage = "encrypt-decrypt", algorithm = "aes-256-gcm", version = 2
      }
    })));
    using var http = new HttpClient(handler);
    using var api = new ApiClient(http, Settings.HostUri, Token);

    var result = await new Client.KmsClient(api).GetKeyAsync(KeyId);

    Assert.Equal(2, result.Key.Version);
    Assert.Equal("aes-256-gcm", result.Key.Algorithm);
    Assert.Equal("encrypt-decrypt", result.Key.KeyUsage);
    Assert.False(result.Key.IsExportable);
    Assert.Null(result.Key.IsDisabled);
    var request = Assert.Single(handler.Requests);
    Assert.Equal("GET", request.Method);
    Assert.Equal($"https://kms.example.test/api/v1/kms/keys/{KeyId}", request.Url);
    Assert.Null(request.Body);
    Assert.Equal($"Bearer {Token}", request.Authorization);
  }

  [Theory]
  [InlineData("")]
  [InlineData("not-a-uuid")]
  [InlineData("../../other/key")]
  [InlineData("00000000-0000-0000-0000-000000000000")]
  [InlineData("534bb50c2f534e5d9f155f2c09d35740")]
  public async Task Invalid_key_ids_are_rejected_before_http(string keyId)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Json(new { ciphertext = "AA==" })));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    await Assert.ThrowsAsync<ArgumentException>(() => client.Kms().EncryptAsync(keyId, new KmsEncryptRequest { Plaintext = "AA==" }));
    Assert.Empty(handler.Requests);
  }

  [Theory]
  [InlineData(null)]
  [InlineData("raw plaintext")]
  [InlineData("abc")]
  [InlineData("A===")]
  [InlineData("AA==\n")]
  [InlineData("__8=")]
  public async Task Malformed_base64_is_rejected_without_echoing_input(string? plaintext)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Json(new { ciphertext = "AA==" })));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var error = await Assert.ThrowsAsync<ArgumentException>(() => client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = plaintext! }));
    Assert.Empty(handler.Requests);
    if (plaintext != null) Assert.DoesNotContain(plaintext, error.Message);
  }

  [Fact]
  public async Task Data_size_limit_is_decoded_bytes_and_empty_plaintext_round_trips()
  {
    using var handler = new ProtocolHandler((request, _) => Task.FromResult(
      request.RequestUri!.AbsolutePath.EndsWith("/encrypt") ? Json(new { ciphertext = "AA==" }) : Json(new { plaintext = "" })));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    await client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "" });
    Assert.Empty((await client.Kms().DecryptAsync(KeyId, new KmsDecryptRequest { Ciphertext = "AA==" })).Plaintext);
    await client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = Convert.ToBase64String(new byte[1024 * 1024]) });
    await Assert.ThrowsAsync<ArgumentException>(() => client.Kms().EncryptAsync(KeyId,
      new KmsEncryptRequest { Plaintext = Convert.ToBase64String(new byte[1024 * 1024 + 1]) }));
    Assert.Equal(3, handler.Requests.Count);
  }

  [Theory]
  [InlineData("")]
  [InlineData("null")]
  [InlineData("{}")]
  [InlineData("{\"ciphertext\":null}")]
  [InlineData("{\"ciphertext\":\"\"}")]
  [InlineData("{\"ciphertext\":\"private-malformed-payload\"}")]
  [InlineData("{\"ciphertext\":42}")]
  [InlineData("private-malformed-payload-not-json")]
  public async Task Invalid_success_payloads_are_rejected_and_redacted(string body)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Raw(body)));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var error = await Assert.ThrowsAsync<InfisicalSensitiveOperationException>(() => client.Kms().EncryptAsync(KeyId,
      new KmsEncryptRequest { Plaintext = "cHJpdmF0ZS1pbnB1dA==" }));
    Assert.Equal("invalid_response", error.Code);
    Assert.Equal(HttpStatusCode.OK, error.StatusCode);
    Assert.Null(error.InnerException);
    Assert.DoesNotContain("private-malformed-payload", error.ToString());
    Assert.DoesNotContain("cHJpdmF0ZS1pbnB1dA==", error.ToString());
  }

  [Theory]
  [InlineData("{\"keyId\":\"534bb50c-2f53-4e5d-9f15-5f2c09d35740\",\"macAlgorithm\":\"HMAC_SHA_256\"}")]
  [InlineData("{\"macValid\":null,\"keyId\":\"534bb50c-2f53-4e5d-9f15-5f2c09d35740\",\"macAlgorithm\":\"HMAC_SHA_256\"}")]
  [InlineData("{\"macValid\":false,\"keyId\":\"41dc8d31-33b7-46c0-a93c-5e1f3bdb3e9e\",\"macAlgorithm\":\"HMAC_SHA_256\"}")]
  [InlineData("{\"macValid\":true,\"keyId\":\"534bb50c-2f53-4e5d-9f15-5f2c09d35740\",\"macAlgorithm\":\"hmac-sha256\"}")]
  public async Task Malformed_verification_is_not_treated_as_valid_or_invalid_mac(string body)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Raw(body)));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var error = await Assert.ThrowsAsync<InfisicalSensitiveOperationException>(() => client.Kms().VerifyMacAsync(KeyId,
      new KmsVerifyMacRequest { Data = "AA==", Mac = "AQ==" }));
    Assert.Equal("invalid_response", error.Code);
  }

  [Theory]
  [InlineData(400)]
  [InlineData(401)]
  [InlineData(403)]
  [InlineData(404)]
  [InlineData(422)]
  public async Task Sensitive_http_errors_expose_only_method_status_and_local_code(int status)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status)
    {
      ReasonPhrase = "secret-reason-phrase", Content = new StringContent("plaintext ciphertext data-key mac-message server-body-secret")
    }));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var error = await Assert.ThrowsAsync<InfisicalSensitiveOperationException>(() => client.Kms().DecryptAsync(KeyId,
      new KmsDecryptRequest { Ciphertext = "c2VjcmV0" }));
    Assert.Equal("POST", error.Method);
    Assert.Equal((HttpStatusCode)status, error.StatusCode);
    Assert.Equal("http_error", error.Code);
    Assert.Null(error.InnerException);
    Assert.DoesNotContain("secret", error.ToString());
    Assert.DoesNotContain("plaintext", error.ToString());
    Assert.Single(handler.Requests);
  }

  [Fact]
  public async Task Universal_auth_failure_and_malformed_success_never_expose_credentials_or_server_body()
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Raw("{\"accessToken\":null}", HttpStatusCode.OK)));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var error = await Assert.ThrowsAsync<InfisicalSensitiveOperationException>(() => client.Auth().UniversalAuth().LoginAsync("id", "secret-credential"));
    Assert.Equal("invalid_response", error.Code);
    Assert.DoesNotContain("secret-credential", error.ToString());
    Assert.Null(error.InnerException);
  }

  [Theory]
  [InlineData("accessToken")]
  [InlineData("expiresIn")]
  [InlineData("accessTokenMaxTTL")]
  [InlineData("tokenType")]
  [InlineData("invalid-token-type")]
  [InlineData("null-token-type")]
  public async Task Malformed_auth_success_does_not_replace_the_existing_bearer(string malformedField)
  {
    var payload = new Dictionary<string, object?>
    {
      ["accessToken"] = "invalid-response-token", ["expiresIn"] = 3600,
      ["accessTokenMaxTTL"] = 7200, ["tokenType"] = "Bearer"
    };
    if (malformedField == "invalid-token-type") payload["tokenType"] = "Basic";
    else if (malformedField == "null-token-type") payload["tokenType"] = null;
    else payload.Remove(malformedField);
    using var handler = new ProtocolHandler((request, _) => Task.FromResult(
      request.RequestUri!.AbsolutePath.EndsWith("/login") ? Json(payload) : Json(new { ciphertext = "AA==" })));
    using var http = new HttpClient(handler);
    using var api = new ApiClient(http, Settings.HostUri, Token);
    var auth = new Client.UniversalAuth(api, api.SetAccessToken);
    var error = await Assert.ThrowsAsync<InfisicalSensitiveOperationException>(() => auth.LoginAsync("id", "secret"));
    Assert.Equal("invalid_response", error.Code);
    Assert.Null(error.InnerException);
    Assert.DoesNotContain("invalid-response-token", error.ToString());
    await new Client.KmsClient(api).EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" });
    Assert.Equal($"Bearer {Token}", handler.Requests[1].Authorization);
  }

  [Theory]
  [InlineData("Bearer")]
  [InlineData("bEaReR")]
  public async Task Auth_preserves_present_zero_ttls_and_accepts_case_insensitive_bearer(string tokenType)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(
      Json(new { accessToken = Token, expiresIn = 0, accessTokenMaxTTL = 0, tokenType })));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var result = await client.Auth().UniversalAuth().LoginAsync("id", "secret");
    Assert.Equal(0, result.ExpiresIn);
    Assert.Equal(0, result.AccessTokenMaxTTL);
    Assert.Equal(tokenType, result.TokenType);
  }

  [Theory]
  [InlineData(false)]
  [InlineData(true)]
  public async Task Cancellation_before_send_remains_cancellation_and_performs_no_request(bool login)
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Json(new { ciphertext = "AA==" })));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    using var cancellation = new CancellationTokenSource();
    cancellation.Cancel();
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => login
      ? client.Auth().UniversalAuth().LoginAsync("id", "secret", cancellation.Token)
      : client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" }, cancellation.Token));
    Assert.Empty(handler.Requests);
  }

  [Theory]
  [InlineData(false)]
  [InlineData(true)]
  public async Task Cancellation_during_http_reaches_handler_without_exception_wrapping(bool login)
  {
    var entered = NewSignal();
    using var handler = new ProtocolHandler(async (_, token) =>
    {
      entered.TrySetResult(true);
      await Task.Delay(Timeout.Infinite, token);
      throw new InvalidOperationException("Cancellation did not propagate.");
    });
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    using var cancellation = new CancellationTokenSource();
    Task operation = login
      ? client.Auth().UniversalAuth().LoginAsync("id", "secret", cancellation.Token)
      : client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" }, cancellation.Token);
    await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
    cancellation.Cancel();
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
    Assert.Single(handler.Requests);
  }

  [Theory]
  [InlineData(false)]
  [InlineData(true)]
  public async Task Cancellation_during_content_read_reaches_body_reader(bool login)
  {
    using var content = new BlockingContent();
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content }));
    using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    using var client = new InfisicalClient(Settings, http);
    using var cancellation = new CancellationTokenSource();
    Task operation = login
      ? client.Auth().UniversalAuth().LoginAsync("id", "secret", cancellation.Token)
      : client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" }, cancellation.Token);
    await content.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
    cancellation.Cancel();
    var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
    Assert.Equal(cancellation.Token, error.CancellationToken);
    Assert.Null(error.InnerException);
    Assert.DoesNotContain("sensitive-partial-body", error.ToString());
  }

  [Theory]
  [InlineData(false)]
  [InlineData(true)]
  public async Task Http_timeout_bounds_response_body_without_a_caller_token(bool login)
  {
    using var content = new BlockingContent();
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content }));
    using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(50) };
    using var client = new InfisicalClient(Settings, http);
    Task operation = login
      ? client.Auth().UniversalAuth().LoginAsync("id", "secret")
      : client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" });
    await content.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
    var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
    Assert.True(content.Disposed.Task.IsCompletedSuccessfully);
    Assert.True(error.CancellationToken.IsCancellationRequested);
    Assert.Null(error.InnerException);
    Assert.DoesNotContain("sensitive-partial-body", error.ToString());
    Assert.Single(handler.Requests);
  }

  [Fact]
  public async Task Http_timeout_also_bounds_retry_backoff_without_a_caller_token()
  {
    using var content = new DisposingContent();
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(
      new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = content }));
    using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(50) };
    using var client = new InfisicalClient(Settings, http);
    var operation = client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" });
    await content.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
    var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
    Assert.True(error.CancellationToken.IsCancellationRequested);
    Assert.Null(error.InnerException);
    Assert.Single(handler.Requests);
  }

  [Theory]
  [InlineData(408)]
  [InlineData(429)]
  [InlineData(503)]
  public async Task Retry_backoff_is_cancellable_and_failed_response_is_disposed(int status)
  {
    using var failedContent = new DisposingContent();
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) { Content = failedContent }));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    using var cancellation = new CancellationTokenSource();
    var operation = client.Kms().EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AA==" }, cancellation.Token);
    await failedContent.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
    cancellation.Cancel();
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
    Assert.Single(handler.Requests);
  }

  [Fact]
  public async Task Retry_regenerates_request_content_and_keeps_the_original_identity()
  {
    var attempts = 0;
    using var failedContent = new DisposingContent();
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(++attempts == 1
      ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = failedContent } : Json(new { ciphertext = "AP8=" })));
    using var http = new HttpClient(handler);
    using var api = new ApiClient(http, Settings.HostUri, Token);
    var kms = new Client.KmsClient(api);
    var operation = kms.EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AP8=" });
    await failedContent.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
    api.SetAccessToken("replacement-identity-token");
    var result = await operation;
    Assert.Equal("AP8=", result.Ciphertext);
    Assert.Equal(2, handler.Requests.Count);
    Assert.NotSame(handler.Requests[0].Message, handler.Requests[1].Message);
    Assert.NotSame(handler.Requests[0].Content, handler.Requests[1].Content);
    foreach (var request in handler.Requests)
      AssertRequest(request, $"/api/v1/kms/keys/{KeyId}/encrypt", new { plaintext = "AP8=" });
    await kms.EncryptAsync(KeyId, new KmsEncryptRequest { Plaintext = "AP8=" });
    Assert.Equal("Bearer replacement-identity-token", handler.Requests[2].Authorization);
  }

  [Fact]
  public async Task Transport_failure_does_not_retain_sensitive_inner_exception()
  {
    using var handler = new ProtocolHandler((_, _) => throw new InvalidOperationException("transport echoed secret-message"));
    using var http = new HttpClient(handler);
    using var client = new InfisicalClient(Settings, http);
    var error = await Assert.ThrowsAsync<InfisicalSensitiveOperationException>(() => client.Kms().GetKeyAsync(KeyId));
    Assert.Equal("transport_error", error.Code);
    Assert.Null(error.StatusCode);
    Assert.Null(error.InnerException);
    Assert.DoesNotContain("secret-message", error.ToString());
  }

  [Fact]
  public async Task Existing_clients_post_contract_and_caller_owned_http_client_remain_usable()
  {
    using var handler = new ProtocolHandler((_, _) => Task.FromResult(Json(new { value = "existing-result" })));
    using var http = new HttpClient(handler);
    using (var client = new InfisicalClient(Settings, http))
    {
      Assert.NotNull(client.Auth());
      Assert.NotNull(client.Secrets());
      Assert.NotNull(client.Folders());
      Assert.NotNull(client.Pki());
      Assert.Same(client.Kms(), client.Kms());
    }
    using (var api = new ApiClient(http, Settings.HostUri, Token))
    {
      var result = await api.PostAsync<object, Dictionary<string, string>>("/legacy", new { value = "original", optional = (string?)null });
      Assert.Equal("existing-result", result["value"]);
      AssertRequest(Assert.Single(handler.Requests), "/legacy", new { value = "original", optional = (string?)null });
    }
    using var response = await http.GetAsync("https://kms.example.test/still-owned-by-caller");
    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    using var originalNullTokenConstructor = new ApiClient("https://kms.example.test", null);
    var ownedHttp = originalNullTokenConstructor.GetClient();
    originalNullTokenConstructor.Dispose();
    await Assert.ThrowsAsync<ObjectDisposedException>(() => ownedHttp.GetAsync("https://kms.example.test/disposed"));
  }

  [Fact]
  public void Existing_public_clr_signatures_remain_available_alongside_explicit_cancellation_overloads()
  {
    Assert.NotNull(typeof(InfisicalClient).GetConstructor(new[] { typeof(InfisicalSdkSettings) }));
    Assert.NotNull(typeof(ApiClient).GetConstructor(new[] { typeof(string), typeof(string) }));
    var originalLogin = typeof(Client.UniversalAuth).GetMethod("LoginAsync", new[] { typeof(string), typeof(string) });
    Assert.NotNull(originalLogin);
    Assert.Equal(typeof(Task<MachineIdentityCredential>), originalLogin.ReturnType);
    var cancellableLogin = typeof(Client.UniversalAuth).GetMethod("LoginAsync",
      new[] { typeof(string), typeof(string), typeof(CancellationToken) });
    Assert.NotNull(cancellableLogin);
    Assert.False(cancellableLogin.GetParameters()[2].IsOptional);
    var originalPost = Assert.Single(typeof(ApiClient).GetMethods(),
      method => method.Name == "PostAsync" && method.IsGenericMethodDefinition && method.GetParameters().Length == 3);
    Assert.Equal(2, originalPost.GetGenericArguments().Length);
    Assert.Equal(typeof(string), originalPost.GetParameters()[0].ParameterType);
    Assert.Equal(originalPost.GetGenericArguments()[0], originalPost.GetParameters()[1].ParameterType);
    Assert.Equal(typeof(bool), originalPost.GetParameters()[2].ParameterType);
    Assert.Equal(false, originalPost.GetParameters()[2].DefaultValue);
    var cancellablePost = Assert.Single(typeof(ApiClient).GetMethods(),
      method => method.Name == "PostAsync" && method.IsGenericMethodDefinition && method.GetParameters().Length == 4);
    Assert.Equal(typeof(CancellationToken), cancellablePost.GetParameters()[3].ParameterType);
    Assert.False(cancellablePost.GetParameters()[3].IsOptional);
  }

  private static void AssertRequest<T>(CapturedRequest request, string path, T expectedBody, string? bearer = Token)
  {
    Assert.Equal("POST", request.Method);
    Assert.Equal($"https://kms.example.test{path}", request.Url);
    Assert.Equal("application/json; charset=utf-8", request.ContentType);
    Assert.Equal("application/json", request.Accept);
    Assert.Equal(bearer == null ? null : $"Bearer {bearer}", request.Authorization);
    Assert.Equal(JsonSerializer.Serialize(expectedBody), request.Body);
  }

  private static HttpResponseMessage Json<T>(T value) => Raw(JsonSerializer.Serialize(value));
  private static HttpResponseMessage Raw(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status)
  {
    Content = new StringContent(body, Encoding.UTF8, "application/json")
  };
  private static TaskCompletionSource<bool> NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

  private sealed record CapturedRequest(HttpRequestMessage Message, HttpContent? Content, string Method, string Url,
    string? Body, string? ContentType, string Accept, string? Authorization);

  private sealed class ProtocolHandler : HttpMessageHandler
  {
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;
    public List<CapturedRequest> Requests { get; } = new();
    public ProtocolHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) => _respond = respond;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
      Requests.Add(new CapturedRequest(request, request.Content, request.Method.Method, request.RequestUri!.AbsoluteUri,
        request.Content == null ? null : await request.Content.ReadAsStringAsync(cancellationToken),
        request.Content?.Headers.ContentType?.ToString(), request.Headers.Accept.ToString(), request.Headers.Authorization?.ToString()));
      return await _respond(request, cancellationToken);
    }
  }

  private sealed class DisposingContent : StringContent
  {
    public TaskCompletionSource<bool> Disposed { get; } = NewSignal();
    public DisposingContent() : base("sensitive-error-body") { }
    protected override void Dispose(bool disposing)
    {
      base.Dispose(disposing);
      if (disposing) Disposed.TrySetResult(true);
    }
  }

  private sealed class BlockingContent : HttpContent
  {
    public TaskCompletionSource<bool> Started { get; } = NewSignal();
    public TaskCompletionSource<bool> Disposed { get; } = NewSignal();
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
      => SerializeToStreamAsync(stream, context, CancellationToken.None);
    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
      await stream.WriteAsync(Encoding.UTF8.GetBytes("sensitive-partial-body"), cancellationToken);
      Started.TrySetResult(true);
      await Task.Delay(Timeout.Infinite, cancellationToken);
    }
    protected override bool TryComputeLength(out long length) { length = 0; return false; }
    protected override void Dispose(bool disposing)
    {
      base.Dispose(disposing);
      if (disposing) Disposed.TrySetResult(true);
    }
  }
}
