using System.Buffers.Binary;
using Oko.Pcapng;

namespace Oko.Capture;

/// <summary>
/// Peeks at a captured frame far enough to find its transport destination port.
/// </summary>
/// <remarks>
/// <para>
/// This exists for one purpose: catching a capture feedback loop. If a host taps an interface without
/// excluding the traffic it is sending to Oko, every captured packet produces another packet, which is
/// itself captured — each round slightly larger, until the link saturates. <c>oko-tap</c> makes that
/// structurally impossible by always injecting its own exclusion filter, but a hand-rolled
/// <c>tcpdump | socat</c> pipeline can still get it wrong, and the failure is expensive enough to be
/// worth a cheap backstop.
/// </para>
/// <para>
/// Only the link types Oko realistically receives are decoded, and only far enough to read a port. This
/// is a diagnostic, not a dissector: anything it cannot parse is simply not flagged.
/// </para>
/// </remarks>
internal static class FrameInspector
{
    private const ushort EtherTypeIPv4 = 0x0800;
    private const ushort EtherTypeIPv6 = 0x86DD;
    private const ushort EtherTypeVlan = 0x8100;
    private const ushort EtherTypeQinQ = 0x88A8;

    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;

    /// <summary>
    /// Extracts the destination port of a TCP or UDP frame.
    /// </summary>
    /// <returns><see langword="false"/> when the frame is not TCP/UDP over IP, or cannot be parsed.</returns>
    public static bool TryGetDestinationPort(ReadOnlySpan<byte> frame, ushort linkType, out ushort port)
    {
        port = 0;

        if (!TryGetNetworkLayer(frame, linkType, out ReadOnlySpan<byte> network, out ushort etherType))
        {
            return false;
        }

        return etherType switch
        {
            EtherTypeIPv4 => TryGetPortFromIPv4(network, out port),
            EtherTypeIPv6 => TryGetPortFromIPv6(network, out port),
            _ => false,
        };
    }

    /// <summary>Strips the link-layer header and reports the payload's EtherType.</summary>
    private static bool TryGetNetworkLayer(
        ReadOnlySpan<byte> frame,
        ushort linkType,
        out ReadOnlySpan<byte> network,
        out ushort etherType)
    {
        network = default;
        etherType = 0;

        switch (linkType)
        {
            case LinkType.Ethernet:
                return TryStripEthernet(frame, out network, out etherType);

            case LinkType.LinuxSll:
                // 16-byte header; the last two bytes before the payload are the protocol type.
                if (frame.Length < 16)
                {
                    return false;
                }

                etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[14..]);
                network = frame[16..];
                return true;

            case LinkType.LinuxSll2:
                // 20-byte header, and here the protocol type comes first. This is what 'tcpdump -i any'
                // produces on any current Linux.
                if (frame.Length < 20)
                {
                    return false;
                }

                etherType = BinaryPrimitives.ReadUInt16BigEndian(frame);
                network = frame[20..];
                return true;

            case LinkType.Raw:
                // No link header at all; infer the family from the IP version nibble.
                if (frame.Length < 1)
                {
                    return false;
                }

                etherType = (frame[0] >> 4) switch
                {
                    4 => EtherTypeIPv4,
                    6 => EtherTypeIPv6,
                    _ => 0,
                };
                network = frame;
                return etherType != 0;

            default:
                return false;
        }
    }

    private static bool TryStripEthernet(ReadOnlySpan<byte> frame, out ReadOnlySpan<byte> network, out ushort etherType)
    {
        network = default;
        etherType = 0;

        const int macAddresses = 12;
        int offset = macAddresses;

        if (frame.Length < offset + 2)
        {
            return false;
        }

        etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[offset..]);
        offset += 2;

        // Walk up to two levels of VLAN tagging, which is common on a trunk port.
        for (int depth = 0; depth < 2 && etherType is EtherTypeVlan or EtherTypeQinQ; depth++)
        {
            if (frame.Length < offset + 4)
            {
                return false;
            }

            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + 2)..]);
            offset += 4;
        }

        if (frame.Length <= offset)
        {
            return false;
        }

        network = frame[offset..];
        return true;
    }

    private static bool TryGetPortFromIPv4(ReadOnlySpan<byte> packet, out ushort port)
    {
        port = 0;

        if (packet.Length < 20 || (packet[0] >> 4) != 4)
        {
            return false;
        }

        int headerLength = (packet[0] & 0x0F) * 4;
        if (headerLength < 20 || packet.Length < headerLength)
        {
            return false;
        }

        // A fragment other than the first has no transport header to read.
        ushort fragmentField = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
        if ((fragmentField & 0x1FFF) != 0)
        {
            return false;
        }

        return TryGetPortFromTransport(packet[headerLength..], packet[9], out port);
    }

    private static bool TryGetPortFromIPv6(ReadOnlySpan<byte> packet, out ushort port)
    {
        port = 0;

        if (packet.Length < 40 || (packet[0] >> 4) != 6)
        {
            return false;
        }

        // Extension headers are not walked: a tapped stream that Oko is receiving will not be using them,
        // and guessing wrong is worse than declining to flag the frame.
        return TryGetPortFromTransport(packet[40..], packet[6], out port);
    }

    private static bool TryGetPortFromTransport(ReadOnlySpan<byte> transport, byte protocol, out ushort port)
    {
        port = 0;

        if (protocol is not (ProtocolTcp or ProtocolUdp) || transport.Length < 4)
        {
            return false;
        }

        port = BinaryPrimitives.ReadUInt16BigEndian(transport[2..]);
        return true;
    }
}
