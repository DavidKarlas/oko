using System.Buffers.Binary;

namespace Oko.Tests;

/// <summary>
/// Synthetic Ethernet frames for tests. They are built to dissect cleanly in Wireshark, so a
/// "[Malformed Packet]" in tshark's output means Oko wrote something wrong rather than that the
/// fixture was sloppy.
/// </summary>
internal static class TestFrames
{
    /// <summary>A complete 42-byte ARP request from 10.0.0.1 asking for 10.0.0.2.</summary>
    public static byte[] ArpRequest { get; } =
    [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,       // destination MAC: broadcast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,       // source MAC
        0x08, 0x06,                               // EtherType: ARP
        0x00, 0x01,                               // hardware type: Ethernet
        0x08, 0x00,                               // protocol type: IPv4
        0x06, 0x04,                               // hardware / protocol address lengths
        0x00, 0x01,                               // operation: request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,       // sender MAC
        0x0a, 0x00, 0x00, 0x01,                   // sender IP: 10.0.0.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // target MAC
        0x0a, 0x00, 0x00, 0x02,                   // target IP: 10.0.0.2
    ];

    /// <summary>Smallest frame <see cref="Udp"/> can produce: Ethernet + IPv4 + UDP with no payload.</summary>
    public const int MinimumUdpFrameLength = 14 + 20 + 8;

    /// <summary>
    /// Builds an Ethernet/IPv4/UDP frame of exactly <paramref name="frameLength"/> bytes, with a correct
    /// IPv4 header checksum so tshark has nothing to complain about. Varying the length across a range
    /// exercises all four pcapng padding cases.
    /// </summary>
    public static byte[] Udp(int frameLength, ushort identification = 0)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(frameLength, MinimumUdpFrameLength);

        var frame = new byte[frameLength];
        int payloadLength = frameLength - MinimumUdpFrameLength;

        // Ethernet II
        "\xff\xff\xff\xff\xff\xff"u8.CopyTo(frame);
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(frame, 6);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x0800);

        // IPv4
        Span<byte> ip = frame.AsSpan(14, 20);
        ip[0] = 0x45;                                                    // version 4, 5 words of header
        ip[1] = 0x00;                                                    // DSCP / ECN
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(20 + 8 + payloadLength));
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], identification);
        BinaryPrimitives.WriteUInt16BigEndian(ip[6..], 0);               // no flags, no fragment offset
        ip[8] = 64;                                                      // TTL
        ip[9] = 17;                                                      // protocol: UDP
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], 0);              // checksum placeholder
        new byte[] { 10, 0, 0, 1 }.CopyTo(frame, 26);                    // source 10.0.0.1
        new byte[] { 10, 0, 0, 2 }.CopyTo(frame, 30);                    // destination 10.0.0.2
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], InternetChecksum(ip));

        // UDP. A zero checksum is explicitly "not computed" over IPv4, so this stays valid.
        // Both ports are unassigned on purpose: a well-known port such as 53 would make Wireshark
        // dissect the synthetic payload as DNS and report it as malformed.
        Span<byte> udp = frame.AsSpan(34, 8);
        BinaryPrimitives.WriteUInt16BigEndian(udp, 40000);
        BinaryPrimitives.WriteUInt16BigEndian(udp[2..], 40001);
        BinaryPrimitives.WriteUInt16BigEndian(udp[4..], (ushort)(8 + payloadLength));
        BinaryPrimitives.WriteUInt16BigEndian(udp[6..], 0);

        for (int i = 0; i < payloadLength; i++)
        {
            frame[MinimumUdpFrameLength + i] = (byte)i;
        }

        return frame;
    }

    /// <summary>An Ethernet/IPv4/TCP frame, for exercising the TCP branch of the frame inspector.</summary>
    public static byte[] Tcp(ushort destinationPort, ushort sourcePort = 50000)
    {
        var frame = new byte[14 + 20 + 20];

        "\xff\xff\xff\xff\xff\xff"u8.CopyTo(frame);
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(frame, 6);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x0800);

        Span<byte> ip = frame.AsSpan(14, 20);
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], 40);
        ip[8] = 64;
        ip[9] = 6; // TCP
        new byte[] { 10, 0, 0, 1 }.CopyTo(frame, 26);
        new byte[] { 10, 0, 0, 2 }.CopyTo(frame, 30);
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], InternetChecksum(ip));

        Span<byte> tcp = frame.AsSpan(34, 20);
        BinaryPrimitives.WriteUInt16BigEndian(tcp, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], destinationPort);
        tcp[12] = 0x50; // data offset 5 words
        tcp[13] = 0x02; // SYN
        return frame;
    }

    /// <summary>An Ethernet/IPv6/UDP frame with no extension headers.</summary>
    public static byte[] Ipv6Udp(ushort destinationPort, ushort sourcePort = 50000)
    {
        var frame = new byte[14 + 40 + 8];

        "\xff\xff\xff\xff\xff\xff"u8.CopyTo(frame);
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(frame, 6);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x86DD);

        Span<byte> ip = frame.AsSpan(14, 40);
        ip[0] = 0x60;                                          // version 6
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], 8);     // payload length
        ip[6] = 17;                                            // next header: UDP
        ip[7] = 64;                                            // hop limit
        ip[8] = 0x20; ip[9] = 0x01;                            // source 2001::1
        ip[23] = 0x01;
        ip[24] = 0x20; ip[25] = 0x01;                          // destination 2001::2
        ip[39] = 0x02;

        Span<byte> udp = frame.AsSpan(54, 8);
        BinaryPrimitives.WriteUInt16BigEndian(udp, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[2..], destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[4..], 8);
        return frame;
    }

    /// <summary>Standard ones' complement header checksum.</summary>
    private static ushort InternetChecksum(ReadOnlySpan<byte> header)
    {
        uint sum = 0;
        for (int i = 0; i + 1 < header.Length; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(header[i..]);
        }

        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }
}
