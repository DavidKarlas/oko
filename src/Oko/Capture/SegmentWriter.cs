using System.Buffers;
using System.Text.Json;
using System.Threading.Channels;
using Oko.Pcapng;

namespace Oko.Capture;

/// <summary>
/// Drains sealed blocks and writes them to segment files.
/// </summary>
/// <remarks>
/// A segment is written once <see cref="OkoOptions.FlushBytes"/> has accumulated, or
/// <see cref="OkoOptions.FlushInterval"/> has passed since the first pending block — the timer is what
/// makes a quiet link still reach disk instead of sitting in memory indefinitely.
/// </remarks>
internal sealed class SegmentWriter(
    OkoOptions options,
    CaptureStore store,
    InterfaceTable interfaces,
    ILogger<SegmentWriter> logger) : BackgroundService
{
    /// <summary>How long to wait before retrying after a failed write.</summary>
    private static readonly TimeSpan WriteRetryDelay = TimeSpan.FromSeconds(5);

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
    /// Seals the active block once its oldest packet exceeds the flush interval, so data reaches disk on
    /// a schedule rather than only when a block happens to fill.
    /// </summary>
    private async Task SealIdleBlocksAsync(CancellationToken stoppingToken)
    {
        // Checking several times per interval keeps the actual delay close to the configured one.
        TimeSpan period = TimeSpan.FromMilliseconds(Math.Max(250, options.FlushInterval.TotalMilliseconds / 4));
        using var timer = new PeriodicTimer(period);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                if (store.SealActiveIfOlderThan(options.FlushInterval, DateTime.UtcNow))
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
        var pending = new List<CaptureBlock>();

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!await TryAccumulateAsync(reader, pending, stoppingToken).ConfigureAwait(false))
            {
                break;
            }

            if (await TryWriteSegmentAsync(pending).ConfigureAwait(false))
            {
                pending.Clear();
                continue;
            }

            // Keep the blocks: they stay queryable from memory and get retried with whatever else has
            // arrived by then. If storage is genuinely broken this grows memory, which CaptureStore
            // reports loudly — better than discarding capture data quietly.
            try
            {
                await Task.Delay(WriteRetryDelay, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        await DrainOnShutdownAsync(reader, pending).ConfigureAwait(false);
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
        DateTime deadline = DateTime.UtcNow + options.FlushInterval;

        while (pendingBytes < options.FlushBytes)
        {
            TimeSpan remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            timeout.CancelAfter(remaining);

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
        await TryWriteSegmentAsync(pending).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes one segment. Deliberately takes no cancellation token: an in-flight segment is at most a
    /// few megabytes and always finishes, so shutdown can never leave a half-written file behind or
    /// abandon captured data. Cancellation is honoured between segments instead.
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
                "Failed to write segment {Path}; will retry in {Delay}. Data stays in memory until then.",
                path,
                WriteRetryDelay);

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
