using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Oko;

/// <summary>
/// Effective configuration, read from <c>OKO_*</c> environment variables.
/// </summary>
/// <remarks>
/// Values are read explicitly rather than through <c>IConfiguration.Bind</c>: the binder would
/// silently ignore a misspelled or unparseable variable, and a collector that quietly runs with a
/// default retention or a default port is worse than one that refuses to start.
/// </remarks>
internal sealed class OkoOptions
{
    /// <summary>Largest possible UDP payload, so one receive buffer always holds a whole datagram.</summary>
    public const int MaxDatagramSize = 65535;

    /// <summary>
    /// Floor for <see cref="BlockBytes"/>. A block must be able to hold the largest possible EPB, or a
    /// single oversized frame could never be appended to an empty block.
    /// </summary>
    public const int MinimumBlockBytes = 128 * 1024;

    public int UdpPort { get; private init; } = 37008;

    /// <summary>
    /// TCP port that accepts inbound classic-pcap streams, for hosts that tap with <c>tcpdump</c> rather
    /// than speaking TZSP. Zero disables it.
    /// </summary>
    public int PcapTcpPort { get; private init; } = 37009;

    public IPAddress UdpBind { get; private init; } = IPAddress.Any;

    public string DataDirectory { get; private init; } = "/data";

    /// <summary>Accumulated bytes that trigger a segment flush.</summary>
    public long FlushBytes { get; private init; } = 8 * 1024 * 1024;

    /// <summary>Upper bound on how long data may sit in memory, so an idle link still reaches disk.</summary>
    public TimeSpan FlushInterval { get; private init; } = TimeSpan.FromMinutes(1);

    public int BlockBytes { get; private init; } = 1024 * 1024;

    /// <summary>Frames longer than this are truncated. Zero means keep everything.</summary>
    public int SnapshotLength { get; private init; }

    public long RetentionBytes { get; private init; } = 50L * 1024 * 1024 * 1024;

    public TimeSpan RetentionDuration { get; private init; } = TimeSpan.FromDays(7);

    public int SocketReceiveBuffer { get; private init; } = 8 * 1024 * 1024;

    public TimeSpan LiveFlushInterval { get; private init; } = TimeSpan.FromMilliseconds(200);

    public int LiveMaxSubscribers { get; private init; } = 8;

    public IReadOnlyList<string> Tokens { get; private init; } = [];

    public string? TokensFile { get; private init; }

    public bool AllowAnonymous { get; private init; }

    public string SegmentsDirectory => Path.Combine(DataDirectory, "segments");

    public string InterfacesPath => Path.Combine(DataDirectory, "interfaces.json");

    /// <summary>
    /// Whether to bind one dual-stack socket rather than a single-family one. Only when no specific
    /// address was requested.
    /// </summary>
    public bool UseDualStack => UdpBind.Equals(IPAddress.Any);

    /// <summary>
    /// Address family for ingest sockets.
    /// </summary>
    /// <remarks>
    /// Derived here rather than in each listener: they previously computed it separately and drifted, so
    /// the TCP listener created an IPv6 socket and then tried to bind an IPv4 address to it.
    /// </remarks>
    public AddressFamily BindAddressFamily =>
        UseDualStack || UdpBind.AddressFamily == AddressFamily.InterNetworkV6
            ? AddressFamily.InterNetworkV6
            : AddressFamily.InterNetwork;

    /// <summary>The address to actually bind, which is <c>::</c> when running dual-stack.</summary>
    public IPAddress BindAddress => UseDualStack ? IPAddress.IPv6Any : UdpBind;

    public static OkoOptions FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new OkoOptions
        {
            UdpPort = ReadPort(configuration, "UDP_PORT", 37008),
            // Zero is meaningful here, so this one allows it rather than going through ReadPort.
            PcapTcpPort = ReadInt32(configuration, "PCAP_TCP_PORT", 37009, minimum: 0) is var pcapPort
                && pcapPort <= 65535
                    ? pcapPort
                    : throw new OkoConfigurationException(
                        $"OKO_PCAP_TCP_PORT must be between 0 and 65535, got {pcapPort}."),
            UdpBind = ReadAddress(configuration, "UDP_BIND", IPAddress.Any),
            DataDirectory = configuration["DATA_DIR"] ?? "/data",
            FlushBytes = ReadInt64(configuration, "FLUSH_BYTES", 8 * 1024 * 1024, minimum: 64 * 1024),
            FlushInterval = ReadTimeSpan(configuration, "FLUSH_INTERVAL", TimeSpan.FromMinutes(1)),
            BlockBytes = ReadInt32(configuration, "BLOCK_BYTES", 1024 * 1024, minimum: MinimumBlockBytes),
            SnapshotLength = ReadInt32(configuration, "SNAPLEN", 0, minimum: 0),
            RetentionBytes = ReadInt64(configuration, "RETENTION_BYTES", 50L * 1024 * 1024 * 1024, minimum: 1024 * 1024),
            RetentionDuration = ReadTimeSpan(configuration, "RETENTION_DURATION", TimeSpan.FromDays(7)),
            SocketReceiveBuffer = ReadInt32(configuration, "SOCKET_RECEIVE_BUFFER", 8 * 1024 * 1024, minimum: 64 * 1024),
            LiveFlushInterval = TimeSpan.FromMilliseconds(
                ReadInt32(configuration, "LIVE_FLUSH_MS", 200, minimum: 1)),
            LiveMaxSubscribers = ReadInt32(configuration, "LIVE_MAX_SUBSCRIBERS", 8, minimum: 1),
            Tokens = ReadTokens(configuration["TOKENS"]),
            TokensFile = NullIfBlank(configuration["TOKENS_FILE"]),
            AllowAnonymous = ReadBoolean(configuration, "ALLOW_ANONYMOUS", false),
        };

        if (options.SnapshotLength is > 0 and < 64)
        {
            throw new OkoConfigurationException("OKO_SNAPLEN must be 0 or at least 64 bytes.");
        }

        return options;
    }

    private static IReadOnlyList<string> ReadTokens(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static int ReadPort(IConfiguration configuration, string key, int fallback)
    {
        int port = ReadInt32(configuration, key, fallback, minimum: 1);
        if (port > 65535)
        {
            throw new OkoConfigurationException($"OKO_{key} must be between 1 and 65535, got {port}.");
        }

        return port;
    }

    private static IPAddress ReadAddress(IConfiguration configuration, string key, IPAddress fallback)
    {
        string? raw = NullIfBlank(configuration[key]);
        if (raw is null)
        {
            return fallback;
        }

        return IPAddress.TryParse(raw, out IPAddress? address)
            ? address
            : throw new OkoConfigurationException($"OKO_{key} is not a valid IP address: '{raw}'.");
    }

    private static int ReadInt32(IConfiguration configuration, string key, int fallback, int minimum)
    {
        string? raw = NullIfBlank(configuration[key]);
        if (raw is null)
        {
            return fallback;
        }

        if (!int.TryParse(raw, CultureInfo.InvariantCulture, out int value))
        {
            throw new OkoConfigurationException($"OKO_{key} is not an integer: '{raw}'.");
        }

        return value >= minimum
            ? value
            : throw new OkoConfigurationException($"OKO_{key} must be at least {minimum}, got {value}.");
    }

    private static long ReadInt64(IConfiguration configuration, string key, long fallback, long minimum)
    {
        string? raw = NullIfBlank(configuration[key]);
        if (raw is null)
        {
            return fallback;
        }

        if (!long.TryParse(raw, CultureInfo.InvariantCulture, out long value))
        {
            throw new OkoConfigurationException($"OKO_{key} is not an integer: '{raw}'.");
        }

        return value >= minimum
            ? value
            : throw new OkoConfigurationException($"OKO_{key} must be at least {minimum}, got {value}.");
    }

    private static TimeSpan ReadTimeSpan(IConfiguration configuration, string key, TimeSpan fallback)
    {
        string? raw = NullIfBlank(configuration[key]);
        if (raw is null)
        {
            return fallback;
        }

        if (!TimeSpan.TryParse(raw, CultureInfo.InvariantCulture, out TimeSpan value) || value <= TimeSpan.Zero)
        {
            throw new OkoConfigurationException(
                $"OKO_{key} must be a positive duration such as 00:01:00 or 7.00:00:00, got '{raw}'.");
        }

        return value;
    }

    private static bool ReadBoolean(IConfiguration configuration, string key, bool fallback)
    {
        string? raw = NullIfBlank(configuration[key]);
        if (raw is null)
        {
            return fallback;
        }

        return bool.TryParse(raw, out bool value)
            ? value
            : throw new OkoConfigurationException($"OKO_{key} must be true or false, got '{raw}'.");
    }
}

/// <summary>Thrown at startup for a configuration value Oko will not guess at.</summary>
internal sealed class OkoConfigurationException(string message) : Exception(message);
