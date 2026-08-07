using Oko.Pcapng;

namespace Oko.Capture;

/// <summary>
/// A fixed-size buffer of finished pcapng Enhanced Packet Blocks.
/// </summary>
/// <remarks>
/// <para>
/// Frames are encoded to their final EPB bytes on arrival, so flushing a block to disk and streaming
/// it to an HTTP response are both plain copies, and the pcapng encoder is exercised by every path.
/// </para>
/// <para>
/// Blocks are deliberately <b>not</b> pooled. A pool would have to guarantee that no HTTP reader still
/// holds a block the flusher has recycled, and getting that wrong yields corrupted captures that are
/// nearly impossible to diagnose. At roughly eight 1 MB allocations per segment the GC cost is
/// irrelevant, so this trades throughput nobody needs for a whole class of bug.
/// </para>
/// </remarks>
internal sealed class CaptureBlock
{
    private readonly byte[] _buffer;

    public CaptureBlock(int capacity) => _buffer = new byte[capacity];

    public int Length { get; private set; }

    public int PacketCount { get; private set; }

    public bool IsEmpty => Length == 0;

    /// <summary>Sequence number of the first packet in this block.</summary>
    public ulong FirstSequence { get; private set; }

    /// <summary>Sequence number of the last packet in this block.</summary>
    public ulong LastSequence { get; private set; }

    /// <summary>Oldest timestamp in this block. A true minimum, not the first one appended.</summary>
    public ulong EarliestTimestampNanoseconds { get; private set; }

    /// <summary>Newest timestamp in this block. A true maximum, not the last one appended.</summary>
    public ulong LatestTimestampNanoseconds { get; private set; }

    /// <summary>The finished bytes. Only safe to read once the block has been sealed.</summary>
    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, Length);

    public ReadOnlyMemory<byte> WrittenMemory => _buffer.AsMemory(0, Length);

    /// <summary>
    /// Encodes one frame into this block. Returns <see langword="false"/> when the block is full, in
    /// which case the caller seals it and retries against a fresh one.
    /// </summary>
    public bool TryAppend(
        uint interfaceId,
        ulong timestampNanoseconds,
        ReadOnlySpan<byte> frame,
        uint originalLength,
        ulong sequence)
    {
        int required = PcapngWriter.EnhancedPacketSize(frame.Length);
        if (Length + required > _buffer.Length)
        {
            return false;
        }

        int written = PcapngWriter.WriteEnhancedPacket(
            _buffer.AsSpan(Length),
            interfaceId,
            timestampNanoseconds,
            frame,
            originalLength);

        if (PacketCount == 0)
        {
            FirstSequence = sequence;
            EarliestTimestampNanoseconds = timestampNanoseconds;
            LatestTimestampNanoseconds = timestampNanoseconds;
        }
        else
        {
            // True minimum and maximum rather than first-and-last seen. Frames arriving over a pcap
            // stream carry the capturing host's own timestamps, which can be slightly out of order; a
            // first/last pair would then invert and produce a segment whose file name claims it ends
            // before it starts, which the range index would never match.
            EarliestTimestampNanoseconds = Math.Min(EarliestTimestampNanoseconds, timestampNanoseconds);
            LatestTimestampNanoseconds = Math.Max(LatestTimestampNanoseconds, timestampNanoseconds);
        }

        Length += written;
        PacketCount++;
        LastSequence = sequence;
        return true;
    }

    /// <summary>
    /// Copies the bytes written so far. Used for the still-filling block, whose buffer the receive loop
    /// keeps mutating, so a reader must take a copy rather than a reference.
    /// </summary>
    public CaptureBlockSnapshot SnapshotFilled() =>
        new(_buffer.AsSpan(0, Length).ToArray(), PacketCount, FirstSequence, LastSequence);
}

/// <summary>An immutable copy of a partially-filled block, safe to hand to a reader.</summary>
internal sealed record CaptureBlockSnapshot(byte[] Bytes, int PacketCount, ulong FirstSequence, ulong LastSequence)
{
    public bool IsEmpty => Bytes.Length == 0;
}
