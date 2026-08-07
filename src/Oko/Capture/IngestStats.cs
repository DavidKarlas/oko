using System.Collections.Concurrent;
using Oko.Tzsp;

namespace Oko.Capture;

/// <summary>Per-sensor totals, keyed by pcapng interface ID.</summary>
internal sealed record SensorStats(string Address, ushort LinkType, long Packets, long Bytes, DateTime LastSeenUtc);

internal sealed record IngestSnapshot(
    long PacketsReceived,
    long BytesReceived,
    long FramesStored,
    long BytesStored,
    double PacketsPerSecond,
    double BitsPerSecond,
    long Keepalives,
    long EmptyPayloads,
    long UnsupportedEncapsulation,
    long ParseErrors,
    long ReceiveErrors,
    long TruncatedFrames,
    long PcapStreamErrors,
    long CaptureLoopSuspects,
    long ClockSkewedSenders,
    IReadOnlyList<SensorStats> Sensors);

/// <summary>
/// Ingest counters. All increments come from the single receive loop; reads come from the status
/// endpoint, so the fields are updated with interlocked operations to keep readers from seeing
/// half-updated values.
/// </summary>
internal sealed class IngestStats
{
    private readonly ConcurrentDictionary<uint, Counters> _sensors = new();

    private long _packetsReceived;
    private long _bytesReceived;
    private long _framesStored;
    private long _bytesStored;
    private long _keepalives;
    private long _emptyPayloads;
    private long _unsupportedEncapsulation;
    private long _parseErrors;
    private long _receiveErrors;
    private long _truncatedFrames;
    private long _pcapStreamErrors;
    private long _captureLoopSuspects;
    private long _clockSkewedSenders;

    private long _rateBaselinePackets;
    private long _rateBaselineBytes;
    private double _packetsPerSecond;
    private double _bitsPerSecond;

    public void RecordDatagram(int bytes)
    {
        Interlocked.Increment(ref _packetsReceived);
        Interlocked.Add(ref _bytesReceived, bytes);
    }

    public void RecordStoredFrame(uint interfaceId, string address, ushort linkType, int bytes, DateTime nowUtc)
    {
        Interlocked.Increment(ref _framesStored);
        Interlocked.Add(ref _bytesStored, bytes);

        Counters counters = _sensors.GetOrAdd(interfaceId, _ => new Counters(address, linkType));
        Interlocked.Increment(ref counters.Packets);
        Interlocked.Add(ref counters.Bytes, bytes);
        Interlocked.Exchange(ref counters.LastSeenTicks, nowUtc.Ticks);
    }

    public void RecordTruncatedFrame() => Interlocked.Increment(ref _truncatedFrames);

    public void RecordKeepalive() => Interlocked.Increment(ref _keepalives);

    public void RecordEmptyPayload() => Interlocked.Increment(ref _emptyPayloads);

    public void RecordUnsupportedEncapsulation() => Interlocked.Increment(ref _unsupportedEncapsulation);

    public void RecordParseError(TzspParseResult result)
    {
        _ = result;
        Interlocked.Increment(ref _parseErrors);
    }

    public void RecordReceiveError() => Interlocked.Increment(ref _receiveErrors);

    /// <summary>A pcap stream Oko refused, almost always a misconfigured sender.</summary>
    public void RecordPcapStreamError() => Interlocked.Increment(ref _pcapStreamErrors);

    /// <summary>
    /// A captured frame addressed to one of Oko's own ingest ports — the signature of a tap whose filter
    /// fails to exclude its own stream, which amplifies without bound.
    /// </summary>
    public void RecordCaptureLoopSuspect() => Interlocked.Increment(ref _captureLoopSuspects);

    /// <summary>A sender whose packet timestamps disagree materially with this host's clock.</summary>
    public void RecordClockSkew() => Interlocked.Increment(ref _clockSkewedSenders);

    /// <summary>
    /// Recomputes the packet and bit rates from the delta since the previous call. Driven by
    /// <see cref="StatsSampler"/> on a fixed tick so the reported rate reflects a known window rather
    /// than however long it has been since someone last looked at <c>/status</c>.
    /// </summary>
    public void SampleRates(TimeSpan elapsed)
    {
        if (elapsed <= TimeSpan.Zero)
        {
            return;
        }

        long packets = Interlocked.Read(ref _packetsReceived);
        long bytes = Interlocked.Read(ref _bytesReceived);

        long packetDelta = packets - _rateBaselinePackets;
        long byteDelta = bytes - _rateBaselineBytes;

        _rateBaselinePackets = packets;
        _rateBaselineBytes = bytes;

        Volatile.Write(ref _packetsPerSecond, packetDelta / elapsed.TotalSeconds);
        Volatile.Write(ref _bitsPerSecond, byteDelta * 8 / elapsed.TotalSeconds);
    }

    public IngestSnapshot Snapshot() => new(
        Interlocked.Read(ref _packetsReceived),
        Interlocked.Read(ref _bytesReceived),
        Interlocked.Read(ref _framesStored),
        Interlocked.Read(ref _bytesStored),
        Volatile.Read(ref _packetsPerSecond),
        Volatile.Read(ref _bitsPerSecond),
        Interlocked.Read(ref _keepalives),
        Interlocked.Read(ref _emptyPayloads),
        Interlocked.Read(ref _unsupportedEncapsulation),
        Interlocked.Read(ref _parseErrors),
        Interlocked.Read(ref _receiveErrors),
        Interlocked.Read(ref _truncatedFrames),
        Interlocked.Read(ref _pcapStreamErrors),
        Interlocked.Read(ref _captureLoopSuspects),
        Interlocked.Read(ref _clockSkewedSenders),
        [.. _sensors.Values
            .Select(counters => new SensorStats(
                counters.Address,
                counters.LinkType,
                Interlocked.Read(ref counters.Packets),
                Interlocked.Read(ref counters.Bytes),
                new DateTime(Interlocked.Read(ref counters.LastSeenTicks), DateTimeKind.Utc)))
            .OrderBy(sensor => sensor.Address, StringComparer.Ordinal)]);

    private sealed class Counters(string address, ushort linkType)
    {
        public string Address { get; } = address;

        public ushort LinkType { get; } = linkType;

        public long Packets;
        public long Bytes;
        public long LastSeenTicks;
    }
}

/// <summary>Ticks <see cref="IngestStats.SampleRates"/> so the reported rates cover a fixed window.</summary>
internal sealed class StatsSampler(IngestStats stats) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            stats.SampleRates(Interval);
        }
    }
}
