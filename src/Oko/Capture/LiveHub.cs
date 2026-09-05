using System.Buffers;
using System.Diagnostics;
using System.Threading.Channels;
using Oko.Pcapng;

namespace Oko.Capture;

/// <summary>
/// Fans freshly-received packets out to live HTTP subscribers.
/// </summary>
/// <remarks>
/// <para>
/// Packets are coalesced into batches, flushed when the buffer reaches
/// <see cref="CoalesceBytes"/> or when <see cref="OkoOptions.LiveFlushInterval"/> elapses. Waiting for
/// a full 1 MB capture block would add seconds of latency on a quiet link, which defeats the point of
/// a live view; the timer bounds it instead.
/// </para>
/// <para>
/// One byte stream is shared by all subscribers, so they must agree on interface numbering. The
/// globally stable, append-only <see cref="InterfaceTable"/> provides that: a subscriber joining
/// mid-stream is first sent the SHB plus every interface known at that moment, which aligns its
/// numbering, and interfaces discovered later get an IDB emitted inline in the shared stream.
/// </para>
/// </remarks>
internal sealed class LiveHub
{
    /// <summary>Batch size that triggers a flush before the timer does.</summary>
    private const int CoalesceBytes = 32 * 1024;

    private readonly Lock _gate = new();
    private readonly List<LiveSubscription> _subscribers = [];
    private readonly ArrayBufferWriter<byte> _batch = new(CoalesceBytes * 2);
    private readonly List<ulong> _batchSequences = [];
    private readonly InterfaceTable _interfaces;
    private readonly OkoOptions _options;
    private readonly ILogger<LiveHub> _logger;

    /// <summary>Interfaces already announced in the shared stream, so a new one is announced once.</summary>
    private int _announcedInterfaces;
    private long _droppedBatches;

    public LiveHub(OkoOptions options, InterfaceTable interfaces, ILogger<LiveHub> logger)
    {
        _options = options;
        _interfaces = interfaces;
        _logger = logger;
    }

    public int SubscriberCount
    {
        get
        {
            lock (_gate)
            {
                return _subscribers.Count;
            }
        }
    }

    /// <summary>
    /// Readers terminated by queue overflow since startup. The historical name is retained for the
    /// status API; each reader is detached at its first rejection, so this is not a total loss count.
    /// </summary>
    public long DroppedBatches => Interlocked.Read(ref _droppedBatches);

    /// <summary>
    /// Appends a packet to the current batch. Called from the receive loop; does no I/O and never
    /// blocks on a subscriber.
    /// </summary>
    public void Publish(
        uint interfaceId,
        ulong timestampNanoseconds,
        ReadOnlySpan<byte> frame,
        uint originalLength,
        ulong sequence)
    {
        lock (_gate)
        {
            if (_subscribers.Count == 0)
            {
                // Nothing to do, but keep the announced-interface count aligned with the table so a
                // later subscriber is not told about an interface twice.
                _announcedInterfaces = _interfaces.Count;
                _batch.Clear();
                _batchSequences.Clear();
                return;
            }

            AnnounceNewInterfacesLocked(_interfaces.Snapshot());

            var span = _batch.GetSpan(PcapngWriter.EnhancedPacketSize(frame.Length));
            int written = PcapngWriter.WriteEnhancedPacket(
                span,
                interfaceId,
                timestampNanoseconds,
                frame,
                originalLength);
            _batch.Advance(written);
            _batchSequences.Add(sequence);

            if (_batch.WrittenCount >= CoalesceBytes)
            {
                FlushLocked();
            }
        }
    }

    /// <summary>Flushes a partially-filled batch. Driven by <see cref="LiveFlusher"/>.</summary>
    public void FlushPending()
    {
        lock (_gate)
        {
            FlushLocked();
        }
    }

    /// <summary>
    /// Registers a subscriber and returns its stream, primed with the SHB and the interface table so
    /// its interface numbering matches the shared byte stream.
    /// </summary>
    /// <returns><see langword="null"/> when the subscriber limit is already reached.</returns>
    public LiveSubscription? TrySubscribe()
    {
        var preamble = new ArrayBufferWriter<byte>(512);
        PcapngWriter.WriteSectionHeader(preamble, OkoVersion.UserApplication);

        lock (_gate)
        {
            if (_subscribers.Count >= _options.LiveMaxSubscribers)
            {
                return null;
            }

            SensorInterface[] table = _interfaces.Snapshot();

            // Existing readers must learn about every interface in the new reader's preamble before
            // advancing the shared announcement count. Use one snapshot: discovery can run concurrently.
            if (_subscribers.Count > 0)
            {
                AnnounceNewInterfacesLocked(table);
            }

            FlushLocked();

            foreach (SensorInterface entry in table)
            {
                PcapngWriter.WriteInterfaceDescription(
                    preamble,
                    entry.LinkType,
                    (uint)_options.SnapshotLength,
                    entry.Name,
                    entry.Description);
            }

            _announcedInterfaces = table.Length;

            var subscription = new LiveSubscription(this, preamble.WrittenSpan.ToArray());
            _subscribers.Add(subscription);
            _logger.LogInformation("Live subscriber attached ({Count} active).", _subscribers.Count);
            return subscription;
        }
    }

    internal void Unsubscribe(LiveSubscription subscription)
    {
        lock (_gate)
        {
            if (_subscribers.Remove(subscription))
            {
                _logger.LogInformation("Live subscriber detached ({Count} active).", _subscribers.Count);
            }

            // Serialize completion with publishing so a normal disconnect cannot count as overflow.
            subscription.Complete();
        }
    }

    /// <summary>
    /// Emits IDBs for interfaces discovered since the last batch. pcapng permits IDBs anywhere in a
    /// section, and readers assign IDs by order of appearance — which is why the table is append-only.
    /// </summary>
    private void AnnounceNewInterfacesLocked(SensorInterface[] table)
    {
        if (table.Length == _announcedInterfaces)
        {
            return;
        }

        for (int index = _announcedInterfaces; index < table.Length; index++)
        {
            PcapngWriter.WriteInterfaceDescription(
                _batch,
                table[index].LinkType,
                (uint)_options.SnapshotLength,
                table[index].Name,
                table[index].Description);
        }

        _announcedInterfaces = table.Length;
    }

    private void FlushLocked()
    {
        if (_batch.WrittenCount == 0)
        {
            return;
        }

        var payload = new LiveBatch(_batch.WrittenSpan.ToArray(), [.. _batchSequences]);
        _batch.Clear();
        _batchSequences.Clear();

        for (int index = _subscribers.Count - 1; index >= 0; index--)
        {
            LiveSubscription subscriber = _subscribers[index];
            if (!subscriber.TryEnqueue(payload))
            {
                // Stop this stream at its first gap, freeing its slot without affecting other readers.
                Interlocked.Increment(ref _droppedBatches);
                _subscribers.RemoveAt(index);
                _logger.LogWarning("Live subscriber overflowed; terminating its incomplete capture.");
            }
        }
    }
}

/// <summary>
/// A coalesced run of pcapng blocks, with one sequence number per packet block in publication order.
/// Publications from different senders can arrive out of sequence, so a batch boundary cannot dedupe it.
/// </summary>
internal sealed record LiveBatch(byte[] Bytes, ulong[] PacketSequences)
{
    /// <summary>
    /// Writes packets not already covered by the history snapshot. Interface descriptions always pass
    /// through: even an entirely historical batch can introduce an interface needed by a later packet.
    /// </summary>
    public void WriteExcludingHistory(
        IBufferWriter<byte> output, ulong lastHistorySequence, ulong fromNanoseconds, ulong toNanoseconds)
    {
        int packet = 0;
        for (int offset = 0; offset < Bytes.Length;)
        {
            ReadOnlySpan<byte> block = Bytes.AsSpan(offset);
            Debug.Assert(block.Length >= PcapngReader.MinimumBlockLength,
                "Internally generated live batches must contain complete block headers and trailers.");
            int length = checked((int)PcapngReader.ReadBlockTotalLength(block));
            Debug.Assert(length >= PcapngReader.MinimumBlockLength && length % 4 == 0 && length <= block.Length,
                "Each live block must have a positive, aligned length within the remaining batch.");
            bool coveredByHistory = false;
            if (PcapngReader.ReadBlockType(block) == BlockType.EnhancedPacket)
            {
                Debug.Assert(length >= PcapngReader.EnhancedPacketFieldsLength + sizeof(uint),
                    "Packet blocks must contain the packet fields and trailing length.");
                Debug.Assert(packet < PacketSequences.Length,
                    "Every packet block must have a corresponding sequence number.");
                ulong timestamp = PcapngReader.ReadEnhancedPacketTimestamp(block);
                coveredByHistory = PacketSequences[packet++] <= lastHistorySequence &&
                    timestamp >= fromNanoseconds && timestamp <= toNanoseconds;
            }

            if (!coveredByHistory)
            {
                output.Write(block[..length]);
            }

            offset += length;
        }

        Debug.Assert(packet == PacketSequences.Length,
            "The sequence count must equal the number of packet blocks in the batch.");
    }
}

/// <summary>A live response is incomplete because its reader could not keep up.</summary>
internal sealed class LiveStreamOverflowException()
    : Exception("Live capture queue overflowed; download the missing interval from history.");

/// <summary>One live HTTP reader's queue.</summary>
internal sealed class LiveSubscription : IDisposable
{
    private readonly LiveHub _hub;
    private readonly Channel<LiveBatch> _batches = Channel.CreateBounded<LiveBatch>(
        new BoundedChannelOptions(256)
        {
            // TryWrite fails when full in Wait mode; we never await writes on the capture path.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });

    internal LiveSubscription(LiveHub hub, byte[] preamble)
    {
        _hub = hub;
        Preamble = preamble;
    }

    /// <summary>SHB plus the interface table as of subscription time. Must be written first.</summary>
    public byte[] Preamble { get; }

    private long _droppedBatches;

    /// <summary>Zero until this reader overflows, then one; subsequent batches are no longer offered.</summary>
    public long DroppedBatches => Interlocked.Read(ref _droppedBatches);

    public ChannelReader<LiveBatch> Batches => _batches.Reader;

    internal bool TryEnqueue(LiveBatch batch)
    {
        if (_batches.Writer.TryWrite(batch))
        {
            return true;
        }

        Interlocked.Increment(ref _droppedBatches);
        _batches.Writer.TryComplete(new LiveStreamOverflowException());
        return false;
    }

    internal void Complete() => _batches.Writer.TryComplete();

    public void Dispose() => _hub.Unsubscribe(this);
}

/// <summary>Bounds live latency by flushing a partially-filled batch on a fixed tick.</summary>
internal sealed class LiveFlusher(OkoOptions options, LiveHub hub) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(options.LiveFlushInterval);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            hub.FlushPending();
        }
    }
}
