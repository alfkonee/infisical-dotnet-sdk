using System.Threading.Tasks;
using Infisical.Sdk.Api;
using Infisical.Sdk.Client;
using Infisical.Sdk.Model;

namespace Infisical.Sdk
{
  public class InfisicalClient : IDisposable
  {
    internal ApiClient _apiClient;
    private AuthClient _authClient;
    private SecretsClient _secretsClient;
    private PkiClient _pkiClient;
    private FoldersClient _foldersClient;
    private readonly KmsClient _kmsClient;
    public InfisicalClient(InfisicalSdkSettings settings)
      : this(new ApiClient(settings.HostUri))
    {
    }

    /// <summary>Uses a caller-owned HTTP client, which is not disposed by this SDK client.</summary>
    public InfisicalClient(InfisicalSdkSettings settings, HttpClient httpClient)
      : this(new ApiClient(httpClient, settings.HostUri))
    {
    }

    private InfisicalClient(ApiClient apiClient)
    {
      _apiClient = apiClient;
      _secretsClient = new SecretsClient(_apiClient);
      _authClient = new AuthClient(_apiClient, (accessToken) => _apiClient.SetAccessToken(accessToken));
      _pkiClient = new PkiClient(_apiClient);
      _foldersClient = new FoldersClient(_apiClient);
      _kmsClient = new KmsClient(_apiClient);
    }

    public AuthClient Auth()
    {
      return _authClient;
    }

    public SecretsClient Secrets()
    {
      return _secretsClient;
    }

    public PkiClient Pki()
    {
      return _pkiClient;
    }

    public FoldersClient Folders()
    {
      return _foldersClient;
    }

    public KmsClient Kms()
    {
      return _kmsClient;
    }

    public void Dispose()
    {
      _apiClient.Dispose();
    }
  }
}