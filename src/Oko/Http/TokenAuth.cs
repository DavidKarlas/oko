using System.Security.Cryptography;
using System.Text;

namespace Oko.Http;

/// <summary>
/// Validates the capture access token.
/// </summary>
/// <remarks>
/// The token is accepted as the first path segment because that is what makes the primary use case a
/// single <c>curl</c> away. That does mean it lands in proxy logs and shell history, so
/// <c>Authorization: Bearer</c> is accepted too for anyone who cares.
/// </remarks>
internal sealed class TokenAuthenticator : IDisposable
{
    private readonly byte[][] _staticTokens;
    private readonly string? _tokensFile;
    private readonly ILogger<TokenAuthenticator> _logger;
    private readonly FileSystemWatcher? _watcher;
    private readonly Lock _gate = new();

    private byte[][] _fileTokens = [];

    public TokenAuthenticator(OkoOptions options, ILogger<TokenAuthenticator> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _logger = logger;
        AllowAnonymous = options.AllowAnonymous;
        _staticTokens = [.. options.Tokens.Select(Encoding.UTF8.GetBytes)];
        _tokensFile = options.TokensFile;

        if (_tokensFile is not null)
        {
            ReloadFileTokens();
            _watcher = WatchTokensFile(_tokensFile);
        }

        if (!IsConfigured && !AllowAnonymous)
        {
            _logger.LogError(
                "No access tokens configured. Capture endpoints will return 503. Set OKO_TOKENS (or " +
                "OKO_TOKENS_FILE), or set OKO_ALLOW_ANONYMOUS=true if this really should be open.");
        }
    }

    public bool AllowAnonymous { get; }

    public bool IsConfigured
    {
        get
        {
            lock (_gate)
            {
                return _staticTokens.Length > 0 || _fileTokens.Length > 0;
            }
        }
    }

    /// <summary>
    /// Compares in constant time against every configured token. The results are accumulated rather
    /// than short-circuited so the time taken does not reveal which token matched.
    /// </summary>
    public bool IsValid(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate))
        {
            return false;
        }

        byte[] candidateBytes = Encoding.UTF8.GetBytes(candidate);

        byte[][] staticTokens;
        byte[][] fileTokens;
        lock (_gate)
        {
            staticTokens = _staticTokens;
            fileTokens = _fileTokens;
        }

        bool matched = false;
        foreach (byte[] token in staticTokens)
        {
            matched |= CryptographicOperations.FixedTimeEquals(candidateBytes, token);
        }

        foreach (byte[] token in fileTokens)
        {
            matched |= CryptographicOperations.FixedTimeEquals(candidateBytes, token);
        }

        return matched;
    }

    public void Dispose() => _watcher?.Dispose();

    private FileSystemWatcher? WatchTokensFile(string path)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (directory is null || !Directory.Exists(directory))
        {
            return null;
        }

        var watcher = new FileSystemWatcher(directory, Path.GetFileName(path))
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
            EnableRaisingEvents = true,
        };

        watcher.Changed += (_, _) => ReloadFileTokens();
        watcher.Created += (_, _) => ReloadFileTokens();
        watcher.Deleted += (_, _) => ReloadFileTokens();
        watcher.Renamed += (_, _) => ReloadFileTokens();
        return watcher;
    }

    private void ReloadFileTokens()
    {
        if (_tokensFile is null)
        {
            return;
        }

        try
        {
            byte[][] tokens = File.Exists(_tokensFile)
                ?
                [
                    .. File.ReadAllLines(_tokensFile)
                        .Select(line => line.Trim())
                        .Where(line => line.Length > 0 && !line.StartsWith('#'))
                        .Select(Encoding.UTF8.GetBytes),
                ]
                : [];

            lock (_gate)
            {
                _fileTokens = tokens;
            }

            _logger.LogInformation("Loaded {Count} token(s) from {Path}.", tokens.Length, _tokensFile);
        }
        catch (IOException exception)
        {
            // Editors often write in two steps; the watcher will fire again when the write completes.
            _logger.LogDebug(exception, "Could not read {Path} yet.", _tokensFile);
        }
    }
}

/// <summary>
/// Rejects requests without a valid token.
/// </summary>
/// <remarks>
/// A bad token yields 404 rather than 401 so that a wrong token and a wrong path are
/// indistinguishable, and a missing configuration yields 503 rather than silently serving captures to
/// anyone who asks.
/// </remarks>
internal sealed class TokenAuthFilter(TokenAuthenticator authenticator) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        if (!authenticator.AllowAnonymous)
        {
            if (!authenticator.IsConfigured)
            {
                return Results.Problem(
                    detail: "Oko has no access tokens configured; set OKO_TOKENS.",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            if (!IsAuthorized(context.HttpContext))
            {
                return Results.NotFound();
            }
        }

        return await next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Accepts the token from the path, an <c>Authorization: Bearer</c> header, or a <c>token</c> query
    /// parameter.
    /// </summary>
    /// <remarks>
    /// Every route carries a <c>{token}</c> segment, so the path candidate is always present. The other
    /// two must therefore be checked as alternatives rather than fallbacks — treating the path as
    /// authoritative when it exists made the header and query forms unreachable, so a caller supplying a
    /// header had to put a placeholder in the path and still got a 404.
    /// </remarks>
    private bool IsAuthorized(HttpContext context)
    {
        if (context.Request.RouteValues.TryGetValue("token", out object? routeValue) &&
            routeValue is string pathToken &&
            authenticator.IsValid(pathToken))
        {
            return true;
        }

        string? authorization = context.Request.Headers.Authorization;
        const string bearerPrefix = "Bearer ";
        if (authorization is not null &&
            authorization.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase) &&
            authenticator.IsValid(authorization[bearerPrefix.Length..].Trim()))
        {
            return true;
        }

        return authenticator.IsValid(context.Request.Query["token"].FirstOrDefault());
    }
}
