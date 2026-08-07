using Oko.Pcapng;

namespace Oko.Tests;

public class PcapStreamReaderTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void ParsesGlobalHeaderInEitherEndiannessAndTimestampResolution(bool nanoseconds, bool bigEndian)
    {
        byte[] header = PcapFile.GlobalHeaderOnly(LinkType.Ethernet, nanoseconds, bigEndian);

        PcapStreamHeader parsed = PcapStreamReader.ParseGlobalHeader(header);

        Assert.Equal(LinkType.Ethernet, parsed.LinkType);
        Assert.Equal(nanoseconds, parsed.NanosecondTimestamps);
        Assert.Equal(bigEndian, parsed.BigEndian);
        Assert.Equal(262144u, parsed.SnapshotLength);
    }

    [Fact]
    public void ParsesTheLinuxCookedV2LinkTypeThatTcpdumpAnyProduces()
    {
        // 'tcpdump -i any' is the obvious thing to run on a VM, and 276 is what it emits. TZSP cannot
        // carry this at all, which is a large part of why the TCP path exists.
        byte[] header = PcapFile.GlobalHeaderOnly(LinkType.LinuxSll2);

        Assert.Equal(LinkType.LinuxSll2, PcapStreamReader.ParseGlobalHeader(header).LinkType);
    }

    [Fact]
    public void RejectsPcapngWithAMessageNamingTheFlagsThatFixIt()
    {
        // The likeliest misconfiguration by far, since tshark and dumpcap default to pcapng.
        byte[] pcapng = [0x0A, 0x0D, 0x0D, 0x0A, .. new byte[20]];

        var exception = Assert.Throws<UnsupportedCaptureStreamException>(
            () => PcapStreamReader.ParseGlobalHeader(pcapng));

        Assert.Contains("pcapng", exception.Message, StringComparison.Ordinal);
        Assert.Contains("-F pcap", exception.Message, StringComparison.Ordinal);
        Assert.Contains("-P", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsSomethingThatIsNotACaptureAtAll()
    {
        byte[] garbage = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n........");

        var exception = Assert.Throws<UnsupportedCaptureStreamException>(
            () => PcapStreamReader.ParseGlobalHeader(garbage));

        Assert.Contains("not a pcap stream", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsATruncatedGlobalHeader()
    {
        Assert.Throws<UnsupportedCaptureStreamException>(
            () => PcapStreamReader.ParseGlobalHeader(new byte[10]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConvertsPacketTimestampsToNanosecondsSinceTheEpoch(bool nanoseconds)
    {
        var when = new DateTime(2026, 7, 29, 14, 3, 12, DateTimeKind.Utc).AddTicks(4_567_890);
        byte[] stream = PcapFile.Build(LinkType.Ethernet, [(when, TestFrames.ArpRequest)], nanoseconds);

        PcapStreamHeader header = PcapStreamReader.ParseGlobalHeader(stream);
        PcapPacketHeader packet = PcapStreamReader.ParsePacketHeader(stream.AsSpan(24, 16), header);

        // Microsecond streams lose the sub-microsecond part, which is expected rather than a defect.
        ulong expected = nanoseconds
            ? Capture.MonotonicClock.ToNanoseconds(when)
            : Capture.MonotonicClock.ToNanoseconds(when) / 1_000 * 1_000;

        Assert.Equal(expected, packet.TimestampNanoseconds);
        Assert.Equal(TestFrames.ArpRequest.Length, packet.CapturedLength);
    }

    [Fact]
    public void ReportsTheOriginalLengthOfATruncatedPacket()
    {
        var when = new DateTime(2026, 7, 29, 14, 3, 12, DateTimeKind.Utc);
        byte[] stream = PcapFile.Build(
            LinkType.Ethernet,
            [(when, TestFrames.ArpRequest[..20])],
            originalLengthOverride: 1514);

        PcapStreamHeader header = PcapStreamReader.ParseGlobalHeader(stream);
        PcapPacketHeader packet = PcapStreamReader.ParsePacketHeader(stream.AsSpan(24, 16), header);

        Assert.Equal(20, packet.CapturedLength);
        Assert.Equal(1514u, packet.OriginalLength);
    }

    [Fact]
    public void ClampsAnOriginalLengthBelowTheCapturedLength()
    {
        // Would otherwise produce an EPB with captured > original, which is invalid pcapng.
        var when = new DateTime(2026, 7, 29, 14, 3, 12, DateTimeKind.Utc);
        byte[] stream = PcapFile.Build(
            LinkType.Ethernet,
            [(when, TestFrames.ArpRequest)],
            originalLengthOverride: 5);

        PcapStreamHeader header = PcapStreamReader.ParseGlobalHeader(stream);
        PcapPacketHeader packet = PcapStreamReader.ParsePacketHeader(stream.AsSpan(24, 16), header);

        Assert.Equal((uint)packet.CapturedLength, packet.OriginalLength);
    }

    [Fact]
    public void RejectsAnAbsurdPacketLengthRatherThanTryingToAllocateIt()
    {
        // A desynchronised stream reads garbage as a length; without a bound this would be a trivial way
        // to make Oko attempt a huge allocation.
        byte[] header = PcapFile.GlobalHeaderOnly(LinkType.Ethernet);
        PcapStreamHeader parsed = PcapStreamReader.ParseGlobalHeader(header);

        var packetHeader = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(packetHeader.AsSpan(8), 0x7FFFFFFF);

        var exception = Assert.Throws<UnsupportedCaptureStreamException>(
            () => PcapStreamReader.ParsePacketHeader(packetHeader, parsed));

        Assert.Contains("out of sync", exception.Message, StringComparison.Ordinal);
    }
}
