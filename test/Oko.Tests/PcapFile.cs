using System.Buffers.Binary;

namespace Oko.Tests;

/// <summary>
/// Builds classic pcap streams, matching what <c>tcpdump -w -</c> writes. Used to feed Oko's TCP ingest
/// without needing a privileged live capture in the test.
/// </summary>
internal static class PcapFile
{
    public const uint MagicMicroseconds = 0xA1B2C3D4;
    public const uint MagicNanoseconds = 0xA1B23C4D;

    /// <param name="linkType">e.g. 1 for Ethernet, 276 for Linux cooked v2.</param>
    /// <param name="nanoseconds">Selects the nanosecond magic number and scales the fraction field.</param>
    /// <param name="bigEndian">Writes the whole stream big-endian, as a big-endian host would.</param>
    public static byte[] Build(
        ushort linkType,
        IEnumerable<(DateTime TimestampUtc, byte[] Frame)> packets,
        bool nanoseconds = false,
        bool bigEndian = false,
        uint snapshotLength = 262144,
        uint? originalLengthOverride = null)
    {
        ArgumentNullException.ThrowIfNull(packets);

        var stream = new MemoryStream();

        // Global header: magic, version 2.4, thiszone, sigfigs, snaplen, linktype.
        Span<byte> header = stackalloc byte[24];
        WriteUInt32(header, nanoseconds ? MagicNanoseconds : MagicMicroseconds, bigEndian);
        WriteUInt16(header[4..], 2, bigEndian);
        WriteUInt16(header[6..], 4, bigEndian);
        WriteUInt32(header[8..], 0, bigEndian);
        WriteUInt32(header[12..], 0, bigEndian);
        WriteUInt32(header[16..], snapshotLength, bigEndian);
        WriteUInt32(header[20..], linkType, bigEndian);
        stream.Write(header);

        Span<byte> packetHeader = stackalloc byte[16];

        foreach ((DateTime timestamp, byte[] frame) in packets)
        {
            long ticksSinceEpoch = timestamp.ToUniversalTime().Ticks - DateTime.UnixEpoch.Ticks;
            long seconds = ticksSinceEpoch / TimeSpan.TicksPerSecond;
            long remainderTicks = ticksSinceEpoch % TimeSpan.TicksPerSecond;
            long fraction = nanoseconds ? remainderTicks * 100 : remainderTicks / 10;

            WriteUInt32(packetHeader, (uint)seconds, bigEndian);
            WriteUInt32(packetHeader[4..], (uint)fraction, bigEndian);
            WriteUInt32(packetHeader[8..], (uint)frame.Length, bigEndian);
            WriteUInt32(packetHeader[12..], originalLengthOverride ?? (uint)frame.Length, bigEndian);
            stream.Write(packetHeader);
            stream.Write(frame);
        }

        return stream.ToArray();
    }

    /// <summary>Just the 24-byte global header, for tests that only exercise header handling.</summary>
    public static byte[] GlobalHeaderOnly(
        ushort linkType,
        bool nanoseconds = false,
        bool bigEndian = false) =>
        Build(linkType, [], nanoseconds, bigEndian);

    /// <summary>
    /// A Linux cooked v2 frame wrapping an IPv4 payload, which is what <c>tcpdump -i any</c> produces on
    /// any current Linux. The 20-byte header leads with the protocol type.
    /// </summary>
    public static byte[] LinuxSll2(byte[] ipv4Packet)
    {
        ArgumentNullException.ThrowIfNull(ipv4Packet);

        var frame = new byte[20 + ipv4Packet.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, 0x0800);          // protocol type: IPv4
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), 0);     // reserved
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(4), 2);     // interface index
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(8), 1);     // ARPHRD_ETHER
        frame[10] = 0;                                                 // packet type: host
        frame[11] = 6;                                                 // link-layer address length
        ipv4Packet.CopyTo(frame, 20);
        return frame;
    }

    /// <summary>The IPv4/UDP portion of <see cref="TestFrames.Udp"/>, without the Ethernet header.</summary>
    public static byte[] Ipv4UdpPayload(int frameLength, ushort identification) =>
        TestFrames.Udp(frameLength, identification)[14..];

    private static void WriteUInt16(Span<byte> destination, ushort value, bool bigEndian)
    {
        if (bigEndian)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination, value);
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(destination, value);
        }
    }

    private static void WriteUInt32(Span<byte> destination, uint value, bool bigEndian)
    {
        if (bigEndian)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination, value);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(destination, value);
        }
    }
}
