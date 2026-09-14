using Infisical.Sdk.Api;
using Infisical.Sdk.Model;

namespace Infisical.Sdk.Client;


public class UniversalAuth
{

  public UniversalAuth(ApiClient apiClient, Action<string> setAccessTokenFunc)
  {
    _apiClient = apiClient;
    _setAccessTokenFunc = setAccessTokenFunc;
  }

  public Task<MachineIdentityCredential> LoginAsync(string clientId, string clientSecret)
  {
    return LoginAsync(clientId, clientSecret, CancellationToken.None);
  }

  public async Task<MachineIdentityCredential> LoginAsync(
    string clientId, string clientSecret, CancellationToken cancellationToken)
  {
    var loginRequest = new UniversalAuthLoginRequest(clientId, clientSecret);
    var response = await _apiClient.SendSensitiveAsync<UniversalAuthLoginRequest, UniversalAuthLoginResponse>(
      HttpMethod.Post, "/api/v1/auth/universal-auth/login", loginRequest, cancellationToken,
      static credential => !string.IsNullOrWhiteSpace(credential.AccessToken)
        && string.Equals(credential.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase), retry: false).ConfigureAwait(false);
    cancellationToken.ThrowIfCancellationRequested();
    _setAccessTokenFunc(response.AccessToken);
    return new MachineIdentityCredential(response.AccessToken, response.ExpiresIn, response.AccessTokenMaxTTL, response.TokenType);
  }

  private readonly ApiClient _apiClient;
  private readonly Action<string> _setAccessTokenFunc;
}

public class LdapAuth
{

  public LdapAuth(ApiClient apiClient, Action<string> setAccessTokenFunc)
  {
    _apiClient = apiClient;
    _setAccessTokenFunc = setAccessTokenFunc;
  }

  public async Task<MachineIdentityCredential> LoginAsync(string identityId, string username, string password)
  {
    try
    {
      var loginRequest = new LdapAuthLoginRequest(identityId, username, password);

      var response = await _apiClient.PostAsync<LdapAuthLoginRequest, MachineIdentityCredential>("/api/v1/auth/ldap-auth/login", loginRequest).ConfigureAwait(false);
      _setAccessTokenFunc(response.AccessToken);
      return response;
    }
    catch (Exception e)
    {
      throw new InfisicalException("Failed to login", e);
    }
  }

  private readonly ApiClient _apiClient;
  private readonly Action<string> _setAccessTokenFunc;
}



public class AuthClient
{
  private readonly ApiClient _apiClient;
  UniversalAuth _universalAuth;
  LdapAuth _ldapAuth;
  private readonly Action<string> _setAccessTokenFunc;

  public AuthClient(ApiClient apiClient, Action<string> setAccessTokenFunc)
  {
    _apiClient = apiClient;
    _setAccessTokenFunc = setAccessTokenFunc;
    _universalAuth = new UniversalAuth(_apiClient, _setAccessTokenFunc);
    _ldapAuth = new LdapAuth(_apiClient, _setAccessTokenFunc);
  }

  public UniversalAuth UniversalAuth()
  {
    return _universalAuth;
  }

  public LdapAuth LdapAuth()
  {
    return _ldapAuth;
  }
}
