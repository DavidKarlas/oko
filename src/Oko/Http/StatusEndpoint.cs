using System.Diagnostics;
using Oko.Capture;

namespace Oko.Http;

internal sealed record ListenStatus(int UdpPort, int PcapTcpPort, string Bind);

internal sealed record IngestStatus(
    long PacketsReceived,
    long BytesReceived,
    long FramesStored,
    long BytesStored,
    long PacketsPerSecond,
    long BitsPerSecond,
    long TzspParseErrors,
    long Keepalives,
    long EmptyPayloads,
    long UnsupportedEncapsulation,
    long TruncatedFrames,
    long ReceiveErrors,
    long? SocketDrops,
    int SocketReceiveBufferBytes,
    long PcapStreamErrors,
    long CaptureLoopSuspects,
    long ClockSkewedSenders);

internal sealed record SensorStatus(string Address, ushort LinkType, long Packets, long Bytes, DateTime LastSeenUtc);

internal sealed record MemoryStatus(int ActiveBytes, int SealedBlocks, long SealedBytes, long PendingFlushBytes);

internal sealed record StorageStatus(
    int Segments,
    long Bytes,
    DateTime? OldestUtc,
    DateTime? NewestUtc,
    long RetentionBytes,
    string RetentionDuration);

internal sealed record LiveStatus(int Subscribers, long DroppedBatches);

/// <summary>
/// When the host started. Captured at startup and injected, because a static initialiser in the
/// reporter would instead be evaluated on the first request and report an uptime of zero forever.
/// </summary>
internal sealed class OkoStartTime
{
    private readonly long _startTimestamp = Stopwatch.GetTimestamp();

    public TimeSpan Elapsed => Stopwatch.GetElapsedTime(_startTimestamp);
}

internal sealed record StatusResponse(
    string Version,
    double UptimeSeconds,
    ListenStatus Listen,
    IngestStatus Ingest,
    IReadOnlyList<SensorStatus> Sensors,
    MemoryStatus Memory,
    StorageStatus Storage,
    LiveStatus Live);

/// <summary>
/// Builds the <c>/status</c> payload.
/// </summary>
/// <remarks>
/// Weighted towards diagnosing a UDP-fed capture, where the characteristic failure is loss that
/// nothing in the resulting file admits to. <see cref="IngestStatus.SocketDrops"/> and a
/// <see cref="IngestStatus.SocketReceiveBufferBytes"/> smaller than requested are the two numbers that
/// explain most "why are packets missing" questions.
/// </remarks>
internal sealed class StatusReporter(
    OkoOptions options,
    CaptureStore store,
    IngestStats stats,
    LiveHub live,
    UdpDropReader drops,
    OkoStartTime startTime)
{
    public StatusResponse Build()
    {
        IngestSnapshot ingest = stats.Snapshot();
        StorageStats storage = store.GetStorageStats();
        MemoryStats memory = store.GetMemoryStats();

        return new StatusResponse(
            OkoVersion.Version,
            Math.Round(startTime.Elapsed.TotalSeconds, 1),
            new ListenStatus(options.UdpPort, options.PcapTcpPort, options.UdpBind.ToString()),
            new IngestStatus(
                ingest.PacketsReceived,
                ingest.BytesReceived,
                ingest.FramesStored,
                ingest.BytesStored,
                (long)Math.Round(ingest.PacketsPerSecond),
                (long)Math.Round(ingest.BitsPerSecond),
                ingest.ParseErrors,
                ingest.Keepalives,
                ingest.EmptyPayloads,
                ingest.UnsupportedEncapsulation,
                ingest.TruncatedFrames,
                ingest.ReceiveErrors,
                drops.TryReadDrops(),
                options.SocketReceiveBuffer,
                ingest.PcapStreamErrors,
                ingest.CaptureLoopSuspects,
                ingest.ClockSkewedSenders),
            [.. ingest.Sensors.Select(sensor => new SensorStatus(
                sensor.Address,
                sensor.LinkType,
                sensor.Packets,
                sensor.Bytes,
                sensor.LastSeenUtc))],
            new MemoryStatus(memory.ActiveBytes, memory.SealedBlocks, memory.SealedBytes, memory.PendingFlushBytes),
            new StorageStatus(
                storage.Segments,
                storage.Bytes,
                storage.OldestUtc,
                storage.NewestUtc,
                options.RetentionBytes,
                options.RetentionDuration.ToString()),
            new LiveStatus(live.SubscriberCount, live.DroppedBatches));
    }
}
