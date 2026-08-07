using System.Buffers;
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

    /// <summary>Batches a subscriber may fall behind by before it is considered too slow.</summary>
    private const int SubscriberCapacity = 256;

    private readonly Lock _gate = new();
    private readonly List<LiveSubscription> _subscribers = [];
    private readonly ArrayBufferWriter<byte> _batch = new(CoalesceBytes * 2);
    private readonly InterfaceTable _interfaces;
    private readonly OkoOptions _options;
    private readonly ILogger<LiveHub> _logger;

    /// <summary>Interfaces already announced in the shared stream, so a new one is announced once.</summary>
    private int _announcedInterfaces;
    private ulong _batchLastSequence;

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

    public long DroppedBatches { get; private set; }

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
                return;
            }

            AnnounceNewInterfacesLocked();

            var span = _batch.GetSpan(PcapngWriter.EnhancedPacketSize(frame.Length));
            int written = PcapngWriter.WriteEnhancedPacket(
                span,
                interfaceId,
                timestampNanoseconds,
                frame,
                originalLength);
            _batch.Advance(written);
            _batchLastSequence = sequence;

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

            // Flush first so the new subscriber's preamble cannot be interleaved with a batch that
            // referenced interfaces it has not been told about yet.
            FlushLocked();

            SensorInterface[] table = _interfaces.Snapshot();
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
        }
    }

    /// <summary>
    /// Emits IDBs for interfaces discovered since the last batch. pcapng permits IDBs anywhere in a
    /// section, and readers assign IDs by order of appearance — which is why the table is append-only.
    /// </summary>
    private void AnnounceNewInterfacesLocked()
    {
        SensorInterface[] table = _interfaces.Snapshot();
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

        var payload = new LiveBatch(_batch.WrittenSpan.ToArray(), _batchLastSequence);
        _batch.Clear();

        foreach (LiveSubscription subscriber in _subscribers)
        {
            if (!subscriber.TryEnqueue(payload))
            {
                // The reader cannot keep up. Degrade that one client rather than the collector.
                DroppedBatches++;
            }
        }
    }
}

/// <summary>A coalesced run of pcapng blocks, tagged with the highest sequence number it contains.</summary>
internal sealed record LiveBatch(byte[] Bytes, ulong LastSequence);

/// <summary>One live HTTP reader's queue.</summary>
internal sealed class LiveSubscription : IDisposable
{
    private readonly LiveHub _hub;
    private readonly Channel<LiveBatch> _batches = Channel.CreateBounded<LiveBatch>(
        new BoundedChannelOptions(256)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
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

    public long DroppedBatches { get; private set; }

    public ChannelReader<LiveBatch> Batches => _batches.Reader;

    internal bool TryEnqueue(LiveBatch batch)
    {
        if (_batches.Writer.TryWrite(batch))
        {
            return true;
        }

        DroppedBatches++;
        return false;
    }

    public void Dispose()
    {
        _batches.Writer.TryComplete();
        _hub.Unsubscribe(this);
    }
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
