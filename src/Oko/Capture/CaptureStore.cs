using System.Threading.Channels;

namespace Oko.Capture;

/// <summary>
/// A consistent view of everything Oko holds, taken atomically so a query can span disk and memory.
/// </summary>
/// <param name="Segments">Matching segment files, oldest first.</param>
/// <param name="SealedBlocks">Full blocks not yet written to disk.</param>
/// <param name="ActiveBlock">A copy of the still-filling block.</param>
/// <param name="LastSequence">
/// Sequence of the newest packet in this snapshot. A follow-mode reader uses it to discard live
/// batches it has already emitted as history.
/// </param>
internal sealed record CaptureSnapshot(
    SegmentRef[] Segments,
    CaptureBlock[] SealedBlocks,
    CaptureBlockSnapshot ActiveBlock,
    ulong LastSequence);

internal sealed record StorageStats(int Segments, long Bytes, DateTime? OldestUtc, DateTime? NewestUtc);

internal sealed record MemoryStats(int ActiveBytes, int SealedBlocks, long SealedBytes, long PendingFlushBytes);

/// <summary>
/// Owns the in-memory blocks and the segment index behind a single lock.
/// </summary>
/// <remarks>
/// <para>
/// The tricky case in the whole design is a query arriving exactly as data moves from memory to disk.
/// Correctness comes from one invariant: <see cref="CompleteFlush"/> adds a segment to the index and
/// drops the corresponding blocks <b>inside the same lock</b> that <see cref="Snapshot"/> uses. So a
/// packet is never in both lists and never missing from both, and no reference counting or block
/// pooling is needed to make it safe.
/// </para>
/// <para>
/// The lock is also taken by <see cref="Append"/> on every packet. It is uncontended in the common
/// case and costs tens of nanoseconds, which is nothing next to the receive syscall. Deliberately no
/// I/O happens while it is held.
/// </para>
/// </remarks>
internal sealed class CaptureStore
{
    /// <summary>Pending unflushed bytes above which the disk is clearly not keeping up.</summary>
    private const long PendingFlushWarningBytes = 256L * 1024 * 1024;

    private readonly Lock _gate = new();
    private readonly List<CaptureBlock> _sealedBlocks = [];
    private readonly Channel<CaptureBlock> _flushQueue = Channel.CreateUnbounded<CaptureBlock>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });

    private readonly SegmentIndex _index;
    private readonly int _blockBytes;
    private readonly ILogger<CaptureStore> _logger;

    private CaptureBlock _active;
    private ulong _nextSequence = 1;
    private long _pendingFlushBytes;
    private bool _warnedAboutPendingFlush;

    public CaptureStore(OkoOptions options, ILogger<CaptureStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger;
        _blockBytes = options.BlockBytes;
        _index = SegmentIndex.Rebuild(options.SegmentsDirectory, logger);
        _active = new CaptureBlock(_blockBytes);
    }

    /// <summary>Sealed blocks awaiting a segment write. Drained by <see cref="SegmentWriter"/>.</summary>
    public ChannelReader<CaptureBlock> FlushQueue => _flushQueue.Reader;

    /// <summary>Number assigned to the next segment file, for unique file names.</summary>
    public long NextSegmentNumber()
    {
        lock (_gate)
        {
            return _index.HighestNumber + 1;
        }
    }

    /// <summary>Encodes a frame into the active block, sealing it first if it is full.</summary>
    /// <returns>The sequence number assigned to this packet.</returns>
    public ulong Append(
        uint interfaceId,
        ulong timestampNanoseconds,
        ReadOnlySpan<byte> frame,
        uint originalLength)
    {
        lock (_gate)
        {
            ulong sequence = _nextSequence++;

            if (!_active.TryAppend(interfaceId, timestampNanoseconds, frame, originalLength, sequence))
            {
                SealActiveLocked();

                if (!_active.TryAppend(interfaceId, timestampNanoseconds, frame, originalLength, sequence))
                {
                    // Unreachable: OkoOptions enforces a block size larger than the biggest possible EPB.
                    throw new InvalidOperationException(
                        $"a {frame.Length}-byte frame does not fit in an empty {_blockBytes}-byte block");
                }
            }

            return sequence;
        }
    }

    /// <summary>
    /// Seals the active block even if it is not full, so a quiet link still reaches disk and a clean
    /// shutdown does not discard the tail.
    /// </summary>
    public void SealActive()
    {
        lock (_gate)
        {
            SealActiveLocked();
        }
    }

    /// <summary>
    /// Seals the active block if its oldest packet is older than <paramref name="maximumAge"/>.
    /// </summary>
    /// <remarks>
    /// Without this, the flush interval would only start once a block filled, so a link too slow to
    /// fill a 1 MB block would hold everything in memory indefinitely and lose it all on a crash —
    /// exactly the "leave it running at a remote site" case Oko exists for.
    /// </remarks>
    /// <returns>Whether a block was sealed.</returns>
    public bool SealActiveIfOlderThan(TimeSpan maximumAge, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_active.IsEmpty)
            {
                return false;
            }

            DateTime oldest = MonotonicClock.ToUtc(_active.EarliestTimestampNanoseconds);
            if (nowUtc - oldest < maximumAge)
            {
                return false;
            }

            SealActiveLocked();
            return true;
        }
    }

    /// <summary>
    /// Takes a consistent view of disk plus memory for a time range.
    /// </summary>
    /// <remarks>
    /// Returns segment references rather than open file handles: opening files would mean disk I/O
    /// while the ingest lock is held. The caller opens them immediately afterwards with
    /// <see cref="FileShare.Delete"/> and skips any that retention removed in between.
    /// </remarks>
    public CaptureSnapshot Snapshot(DateTime fromUtc, DateTime toUtc)
    {
        lock (_gate)
        {
            return new CaptureSnapshot(
                _index.Range(fromUtc, toUtc),
                [.. _sealedBlocks],
                _active.SnapshotFilled(),
                _nextSequence - 1);
        }
    }

    /// <summary>
    /// Publishes a written segment and releases the blocks it contains, atomically.
    /// </summary>
    public void CompleteFlush(IReadOnlyList<CaptureBlock> flushed, SegmentRef segment)
    {
        ArgumentNullException.ThrowIfNull(flushed);

        lock (_gate)
        {
            _index.Add(segment);

            foreach (CaptureBlock block in flushed)
            {
                if (_sealedBlocks.Remove(block))
                {
                    _pendingFlushBytes -= block.Length;
                }
            }
        }
    }

    /// <summary>
    /// Removes segments that retention has decided to drop and returns them so the caller can delete
    /// the files.
    /// </summary>
    /// <remarks>
    /// Index removal happens first on purpose: a reader can then never obtain a reference to a file
    /// that is about to disappear. If the subsequent delete fails, the file is simply orphaned and
    /// gets picked up again by <see cref="SegmentIndex.Rebuild"/> on the next start.
    /// </remarks>
    public SegmentRef[] EvictSegments(long retentionBytes, TimeSpan retentionDuration, DateTime nowUtc)
    {
        var evicted = new List<SegmentRef>();
        DateTime cutoff = nowUtc - retentionDuration;

        lock (_gate)
        {
            while (_index.Oldest is { } oldest &&
                   (_index.TotalBytes > retentionBytes || oldest.EndUtc < cutoff) &&
                   _index.Count > 0)
            {
                _index.Remove(oldest);
                evicted.Add(oldest);
            }
        }

        return [.. evicted];
    }

    public StorageStats GetStorageStats()
    {
        lock (_gate)
        {
            return new StorageStats(
                _index.Count,
                _index.TotalBytes,
                _index.Oldest?.StartUtc,
                _index.Newest?.EndUtc);
        }
    }

    public MemoryStats GetMemoryStats()
    {
        lock (_gate)
        {
            return new MemoryStats(
                _active.Length,
                _sealedBlocks.Count,
                _sealedBlocks.Sum(block => (long)block.Length),
                _pendingFlushBytes);
        }
    }

    private void SealActiveLocked()
    {
        if (_active.IsEmpty)
        {
            return;
        }

        CaptureBlock sealedBlock = _active;
        _active = new CaptureBlock(_blockBytes);

        _sealedBlocks.Add(sealedBlock);
        _pendingFlushBytes += sealedBlock.Length;

        // Unbounded on purpose: a stalled disk must never stall ingest, and recent data should stay
        // queryable from memory even while writes are failing. The trade-off is unbounded growth, so
        // say so loudly rather than dying silently with an OutOfMemoryException.
        if (_pendingFlushBytes > PendingFlushWarningBytes && !_warnedAboutPendingFlush)
        {
            _warnedAboutPendingFlush = true;
            _logger.LogError(
                "{Bytes} bytes are waiting to be written to {Directory}. Storage is not keeping up with " +
                "ingest; memory will keep growing until it does.",
                _pendingFlushBytes,
                nameof(OkoOptions.SegmentsDirectory));
        }
        else if (_pendingFlushBytes < PendingFlushWarningBytes / 2)
        {
            _warnedAboutPendingFlush = false;
        }

        _flushQueue.Writer.TryWrite(sealedBlock);
    }
}
