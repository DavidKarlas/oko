using System.Buffers.Binary;
using Oko.Capture;
using Oko.Pcapng;

namespace Oko.Tests;

/// <summary>
/// The frame inspector exists to catch a capture feedback loop, where a tap fails to exclude the stream
/// it is itself producing and amplifies without bound. These tests cover the link types Oko actually
/// receives.
/// </summary>
public class FrameInspectorTests
{
    [Fact]
    public void ReadsTheDestinationPortOfAnEthernetIPv4UdpFrame()
    {
        byte[] frame = TestFrames.Udp(200);

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out ushort port));
        Assert.Equal(40001, port);
    }

    [Fact]
    public void ReadsThroughASingleVlanTag()
    {
        byte[] frame = WithVlanTags(TestFrames.Udp(200), 1);

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out ushort port));
        Assert.Equal(40001, port);
    }

    [Fact]
    public void ReadsThroughStackedVlanTags()
    {
        byte[] frame = WithVlanTags(TestFrames.Udp(200), 2);

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out ushort port));
        Assert.Equal(40001, port);
    }

    [Fact]
    public void ReadsALinuxCookedV2FrameFromTcpdumpAny()
    {
        byte[] frame = PcapFile.LinuxSll2(PcapFile.Ipv4UdpPayload(200, 1));

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.LinuxSll2, out ushort port));
        Assert.Equal(40001, port);
    }

    [Fact]
    public void ReadsARawIpFrameWithNoLinkHeader()
    {
        byte[] frame = PcapFile.Ipv4UdpPayload(200, 1);

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.Raw, out ushort port));
        Assert.Equal(40001, port);
    }

    [Fact]
    public void ReadsATcpDestinationPort()
    {
        byte[] frame = TestFrames.Tcp(destinationPort: 37009);

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out ushort port));
        Assert.Equal(37009, port);
    }

    [Fact]
    public void ReadsAnIPv6UdpFrame()
    {
        byte[] frame = TestFrames.Ipv6Udp(destinationPort: 37009);

        Assert.True(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out ushort port));
        Assert.Equal(37009, port);
    }

    [Fact]
    public void DeclinesNonIpFrames()
    {
        // ARP has no ports. Declining is correct; guessing would produce false loop reports.
        Assert.False(FrameInspector.TryGetDestinationPort(TestFrames.ArpRequest, LinkType.Ethernet, out _));
    }

    [Fact]
    public void DeclinesANonFirstIpv4Fragment()
    {
        // A later fragment carries no transport header, so there is no port to read.
        byte[] frame = TestFrames.Udp(200);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(14 + 6), 0x0001); // non-zero fragment offset

        Assert.False(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(20)]
    [InlineData(33)]
    public void DeclinesTruncatedFramesWithoutThrowing(int length)
    {
        // Frames arrive from an untrusted sender, possibly snaplen-truncated mid-header.
        byte[] frame = TestFrames.Udp(200)[..Math.Min(length, 200)];

        Assert.False(FrameInspector.TryGetDestinationPort(frame, LinkType.Ethernet, out _));
    }

    [Fact]
    public void DeclinesLinkTypesItDoesNotUnderstand()
    {
        Assert.False(FrameInspector.TryGetDestinationPort(TestFrames.Udp(200), LinkType.Fddi, out _));
    }

    /// <summary>Inserts <paramref name="depth"/> 802.1Q tags between the MACs and the EtherType.</summary>
    private static byte[] WithVlanTags(byte[] frame, int depth)
    {
        var tagged = new List<byte>(frame[..12]);

        for (int i = 0; i < depth; i++)
        {
            tagged.AddRange([0x81, 0x00, 0x00, (byte)(100 + i)]);
        }

        tagged.AddRange(frame[12..]);
        return [.. tagged];
    }
}
