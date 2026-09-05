using System.Buffers;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;
using Oko.Pcapng;

namespace Oko.Capture;

/// <summary>
/// Drains sealed blocks and writes them to segment files.
/// </summary>
/// <remarks>
/// A segment is written once <see cref="OkoOptions.FlushBytes"/> has accumulated, or
/// <see cref="OkoOptions.FlushInterval"/> has passed since the first packet arrived at the collector.
/// Sealing a block does not restart that deadline. Idle polling, scheduling and disk I/O add latency.
/// </remarks>
internal sealed class SegmentWriter(
    OkoOptions options,
    CaptureStore store,
    InterfaceTable interfaces,
    ILogger<SegmentWriter> logger) : BackgroundService
{
    /// <summary>How long to wait before retrying after a failed write.</summary>
    private static readonly TimeSpan WriteRetryDelay = TimeSpan.FromSeconds(5);

    private readonly List<CaptureBlock> _pending = [];
    private readonly Lock _stopGate = new();
    private Task? _stopTask;

    /// <summary>
    /// Stops the worker, then drains once. In .NET 10 cancellation can prevent ExecuteAsync from ever
    /// being called, so the final drain must belong to the hosted-service lifecycle instead.
    /// </summary>
    public override Task StopAsync(CancellationToken cancellationToken)
    {
        lock (_stopGate)
        {
            // A host timeout stops waiting, but must not start a concurrent drain while the worker
            // still owns pending blocks or an in-flight write. Later stop calls await the same drain.
            _stopTask ??= StopAndDrainAsync();
            return _stopTask.WaitAsync(cancellationToken);
        }
    }

    private async Task StopAndDrainAsync()
    {
        await base.StopAsync(CancellationToken.None).ConfigureAwait(false);
        Debug.Assert(ExecuteTask is null || ExecuteTask.IsCompleted);
        await DrainOnShutdownAsync(store.FlushQueue, _pending).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Runs alongside the write loop: the write loop can only react to blocks that have already been
        // sealed, so something has to seal a partially-filled one when the link is quiet.
        Task idleSealing = SealIdleBlocksAsync(stoppingToken);

        try
        {
            await WriteLoopAsync(stoppingToken).ConfigureAwait(false);
        }
        finally
        {
            await idleSealing.ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Seals the active block once its first arrival exceeds the flush interval, so data reaches disk
    /// on a schedule rather than only when a block happens to fill.
    /// </summary>
    private async Task SealIdleBlocksAsync(CancellationToken stoppingToken)
    {
        // Checking several times per interval keeps the actual delay close to the configured one.
        TimeSpan period = TimeSpan.FromMilliseconds(Math.Max(250, options.FlushInterval.TotalMilliseconds / 4));
        using var timer = new PeriodicTimer(period, store.TimeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                if (store.SealActiveIfOlderThan(options.FlushInterval))
                {
                    logger.LogDebug("Sealed a partially-filled block after {Interval}.", options.FlushInterval);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown; DrainOnShutdownAsync seals whatever is left.
        }
    }

    private async Task WriteLoopAsync(CancellationToken stoppingToken)
    {
        ChannelReader<CaptureBlock> reader = store.FlushQueue;

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!await TryAccumulateAsync(reader, _pending, stoppingToken).ConfigureAwait(false))
            {
                break;
            }

            if (await TryWriteSegmentAsync(_pending).ConfigureAwait(false))
            {
                _pending.Clear();
                continue;
            }

            // Keep the blocks: they stay queryable from memory and get retried after a delay.
            // If storage is genuinely broken this grows memory, which CaptureStore
            // reports loudly — better than discarding capture data quietly.
            try
            {
                logger.LogWarning("Retrying pending capture write in {Delay}.", WriteRetryDelay);
                await Task.Delay(WriteRetryDelay, store.TimeProvider, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Collects blocks until the size threshold or the flush interval is reached. Returns false only
    /// when shutdown was requested before anything arrived.
    /// </summary>
    private async Task<bool> TryAccumulateAsync(
        ChannelReader<CaptureBlock> reader,
        List<CaptureBlock> pending,
        CancellationToken stoppingToken)
    {
        if (pending.Count == 0)
        {
            try
            {
                pending.Add(await reader.ReadAsync(stoppingToken).ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        long pendingBytes = pending.Sum(block => (long)block.Length);
        // The store seals nonempty blocks in append order and this is its only queue reader. Keeping
        // the first block across retries also keeps the original deadline; retries must not reset it.
        Debug.Assert(pending.Count > 0);
        Debug.Assert(pending.All(block => block.PacketCount > 0));
        Debug.Assert(pending.All(block => block.FirstArrivalTimestamp >= pending[0].FirstArrivalTimestamp));
        long firstArrival = pending[0].FirstArrivalTimestamp;

        while (pendingBytes < options.FlushBytes)
        {
            TimeSpan remaining = options.FlushInterval - store.TimeProvider.GetElapsedTime(firstArrival);
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            using var deadlineTimer = new CancellationTokenSource(remaining, store.TimeProvider);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, deadlineTimer.Token);

            try
            {
                CaptureBlock next = await reader.ReadAsync(timeout.Token).ConfigureAwait(false);
                pending.Add(next);
                pendingBytes += next.Length;
            }
            catch (OperationCanceledException)
            {
                // Either the flush interval elapsed or the host is shutting down; write what we have.
                break;
            }
        }

        return true;
    }

    private async Task DrainOnShutdownAsync(ChannelReader<CaptureBlock> reader, List<CaptureBlock> pending)
    {
        // The partially-filled block would otherwise be lost on a clean stop.
        store.SealActive();

        while (reader.TryRead(out CaptureBlock? block))
        {
            pending.Add(block);
        }

        if (pending.Count == 0)
        {
            return;
        }

        logger.LogInformation("Flushing {Count} pending block(s) before shutdown.", pending.Count);
        if (await TryWriteSegmentAsync(pending).ConfigureAwait(false))
        {
            pending.Clear();
        }
        else
        {
            logger.LogError("Shutdown flush failed; {Count} block(s) remain only in memory.", pending.Count);
        }
    }

    /// <summary>
    /// Writes one segment without cancellation, allowing in-flight I/O to finish during graceful
    /// shutdown. Only complete files are renamed into place. A forced process exit or storage failure
    /// can still lose memory-only data; the host's shutdown timeout does not guarantee a disk flush.
    /// </summary>
    private async Task<bool> TryWriteSegmentAsync(List<CaptureBlock> blocks)
    {
        List<CaptureBlock> populated = [.. blocks.Where(block => block.PacketCount > 0)];
        if (populated.Count == 0)
        {
            return true;
        }

        DateTime startUtc = MonotonicClock.ToUtc(populated.Min(block => block.EarliestTimestampNanoseconds));
        DateTime endUtc = MonotonicClock.ToUtc(populated.Max(block => block.LatestTimestampNanoseconds));
        long number = store.NextSegmentNumber();

        string path = SegmentIndex.BuildPath(options.SegmentsDirectory, startUtc, endUtc, number);
        string temporaryPath = SegmentIndex.ToTemporaryPath(path);

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1 << 16,
                FileOptions.Asynchronous))
            {
                await stream.WriteAsync(BuildHeader(populated)).ConfigureAwait(false);

                foreach (CaptureBlock block in populated)
                {
                    await stream.WriteAsync(block.WrittenMemory).ConfigureAwait(false);
                }

                // Durable before the rename, so a segment that exists is always complete.
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            logger.LogError(
                exception,
                "Failed to write segment {Path}. Capture data remains in memory.",
                path);

            TryDeleteTemporary(temporaryPath);
            return false;
        }

        long size = new FileInfo(path).Length;
        store.CompleteFlush(populated, new SegmentRef(path, startUtc, endUtc, size, number));

        logger.LogInformation(
            "Wrote {Path} ({Bytes} bytes, {Packets} packets, {Start:HH:mm:ss.fff}-{End:HH:mm:ss.fff}Z).",
            path,
            size,
            populated.Sum(block => block.PacketCount),
            startUtc,
            endUtc);

        return true;
    }

    /// <summary>
    /// Builds the SHB plus the whole interface table.
    /// </summary>
    /// <remarks>
    /// Every segment carries every known interface, not just the ones it contains. That costs 32 bytes
    /// per unused interface and buys a read path that can emit one IDB list up front and then copy
    /// each segment's packet bytes verbatim, with no interface-ID remapping.
    /// </remarks>
    private ReadOnlyMemory<byte> BuildHeader(List<CaptureBlock> blocks)
    {
        SensorInterface[] table = interfaces.Snapshot();

        var metadata = new SegmentMetadata(
            blocks.Sum(block => block.PacketCount),
            blocks.Min(block => block.FirstSequence),
            blocks.Max(block => block.LastSequence),
            [.. table.Select(entry => entry.Name)]);

        var writer = new ArrayBufferWriter<byte>(1024);
        PcapngWriter.WriteSectionHeader(
            writer,
            OkoVersion.UserApplication,
            JsonSerializer.Serialize(metadata, OkoJson.Default.SegmentMetadata));

        foreach (SensorInterface entry in table)
        {
            PcapngWriter.WriteInterfaceDescription(
                writer,
                entry.LinkType,
                (uint)options.SnapshotLength,
                entry.Name,
                entry.Description);
        }

        return writer.WrittenMemory;
    }

    private void TryDeleteTemporary(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException exception)
        {
            logger.LogWarning(exception, "Could not remove partial segment {Path}.", path);
        }
    }
}

/// <summary>
/// Recorded in each segment's SHB comment, so a file copied off the volume explains itself without
/// Oko being involved.
/// </summary>
internal sealed record SegmentMetadata(int Packets, ulong FirstSequence, ulong LastSequence, string[] Sensors);
