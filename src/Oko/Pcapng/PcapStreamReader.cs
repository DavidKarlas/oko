using System.Buffers.Binary;

namespace Oko.Pcapng;

/// <summary>What a classic pcap stream's global header told us.</summary>
/// <param name="LinkType">Link type for every packet in the stream.</param>
/// <param name="SnapshotLength">The writer's snapshot length, or 0 when unset.</param>
/// <param name="NanosecondTimestamps">Whether the fractional field is nanoseconds rather than microseconds.</param>
/// <param name="BigEndian">Whether multi-byte fields are big-endian.</param>
internal sealed record PcapStreamHeader(
    ushort LinkType,
    uint SnapshotLength,
    bool NanosecondTimestamps,
    bool BigEndian);

/// <summary>One packet lifted out of a pcap stream.</summary>
/// <param name="TimestampNanoseconds">Capture time from the stream, in nanoseconds since the epoch.</param>
/// <param name="CapturedLength">Bytes actually present.</param>
/// <param name="OriginalLength">Length before the capturing host truncated it.</param>
internal readonly record struct PcapPacketHeader(
    ulong TimestampNanoseconds,
    int CapturedLength,
    uint OriginalLength);

/// <summary>
/// Thrown when an inbound stream is not classic pcap. Carries an actionable message because the usual
/// cause is a tool defaulting to pcapng.
/// </summary>
internal sealed class UnsupportedCaptureStreamException(string message) : Exception(message);

/// <summary>
/// Reads a classic pcap stream, of the kind <c>tcpdump -w -</c> produces.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately classic pcap only. That is what <c>tcpdump -w -</c> emits, and it keeps this path small:
/// a 24-byte global header, then a 16-byte header per packet. pcapng arriving here is detected and
/// reported with the flag needed to fix it, rather than half-parsed.
/// </para>
/// <para>
/// Both endiannesses are handled, because the magic number records the writing host's byte order and a
/// capture could legitimately be pushed from a big-endian machine.
/// </para>
/// </remarks>
internal static class PcapStreamReader
{
    public const int GlobalHeaderLength = 24;
    public const int PacketHeaderLength = 16;

    /// <summary>Largest packet Oko will accept, as a guard against a desynchronised stream.</summary>
    public const int MaxPacketLength = 4 * 1024 * 1024;

    private const uint MagicMicroseconds = 0xA1B2C3D4;
    private const uint MagicNanoseconds = 0xA1B23C4D;
    private const uint MagicMicrosecondsSwapped = 0xD4C3B2A1;
    private const uint MagicNanosecondsSwapped = 0x4D3CB2A1;
    private const uint PcapngSectionHeader = 0x0A0D0D0A;

    /// <summary>Parses the 24-byte global header.</summary>
    public static PcapStreamHeader ParseGlobalHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < GlobalHeaderLength)
        {
            throw new UnsupportedCaptureStreamException(
                $"expected a {GlobalHeaderLength}-byte pcap header but the stream ended after {header.Length} bytes");
        }

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header);

        if (magic == PcapngSectionHeader)
        {
            throw new UnsupportedCaptureStreamException(
                "this is a pcapng stream, and Oko's TCP ingest reads classic pcap. " +
                "Use 'tcpdump -w -' (which writes pcap), or add '-F pcap' to tshark, or '-P' to dumpcap.");
        }

        bool bigEndian;
        bool nanoseconds;

        switch (magic)
        {
            case MagicMicroseconds:
                bigEndian = false;
                nanoseconds = false;
                break;
            case MagicNanoseconds:
                bigEndian = false;
                nanoseconds = true;
                break;
            case MagicMicrosecondsSwapped:
                bigEndian = true;
                nanoseconds = false;
                break;
            case MagicNanosecondsSwapped:
                bigEndian = true;
                nanoseconds = true;
                break;
            default:
                throw new UnsupportedCaptureStreamException(
                    $"not a pcap stream: leading bytes are 0x{magic:X8}, expected a pcap magic number. " +
                    "Is the sender piping something other than 'tcpdump -w -'?");
        }

        uint snapshotLength = ReadUInt32(header[16..], bigEndian);
        uint linkType = ReadUInt32(header[20..], bigEndian);

        if (linkType > ushort.MaxValue)
        {
            throw new UnsupportedCaptureStreamException($"pcap link type {linkType} is out of range");
        }

        return new PcapStreamHeader((ushort)linkType, snapshotLength, nanoseconds, bigEndian);
    }

    /// <summary>Parses a 16-byte per-packet header.</summary>
    public static PcapPacketHeader ParsePacketHeader(ReadOnlySpan<byte> header, PcapStreamHeader stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        uint seconds = ReadUInt32(header, stream.BigEndian);
        uint fraction = ReadUInt32(header[4..], stream.BigEndian);
        uint capturedLength = ReadUInt32(header[8..], stream.BigEndian);
        uint originalLength = ReadUInt32(header[12..], stream.BigEndian);

        if (capturedLength > MaxPacketLength)
        {
            throw new UnsupportedCaptureStreamException(
                $"packet claims to be {capturedLength} bytes, which exceeds the {MaxPacketLength}-byte limit; " +
                "the stream is probably corrupt or out of sync");
        }

        ulong timestamp = ((ulong)seconds * 1_000_000_000UL)
            + (stream.NanosecondTimestamps ? fraction : fraction * 1_000UL);

        // A capturing host may report a captured length above the original; clamp so the resulting EPB
        // stays valid pcapng.
        return new PcapPacketHeader(timestamp, (int)capturedLength, Math.Max(originalLength, capturedLength));
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> source, bool bigEndian) =>
        bigEndian
            ? BinaryPrimitives.ReadUInt32BigEndian(source)
            : BinaryPrimitives.ReadUInt32LittleEndian(source);
}
