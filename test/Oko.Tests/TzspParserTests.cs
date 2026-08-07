using System.Net;
using Oko.Pcapng;
using Oko.Tzsp;

namespace Oko.Tests;

public class TzspParserTests
{
    private static readonly byte[] Frame = TestFrames.ArpRequest;

    [Fact]
    public void ParsesMinimalEthernetDatagram()
    {
        byte[] datagram = TzspDatagram.Create().End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(TzspPacketType.Received, frame.Type);
        Assert.Equal(TzspEncapsulation.Ethernet, frame.Encapsulation);
        Assert.Equal(TzspParser.HeaderLength + 1, frame.PayloadOffset);
        Assert.Equal(Frame.Length, frame.PayloadLength);
        Assert.Equal((uint)Frame.Length, frame.OriginalLength);
        Assert.True(frame.CarriesFrame);
        Assert.False(frame.HasSensorAddress);
        Assert.Equal(Frame, datagram.AsSpan(frame.PayloadOffset, frame.PayloadLength).ToArray());
    }

    [Fact]
    public void SkipsPaddingTagsWhichCarryNoLengthByte()
    {
        byte[] datagram = TzspDatagram.Create().Padding(3).End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(Frame, datagram.AsSpan(frame.PayloadOffset, frame.PayloadLength).ToArray());
    }

    [Fact]
    public void SkipsUnknownTags()
    {
        byte[] datagram = TzspDatagram.Create()
            .Tag(0x63, 0xAA, 0xBB, 0xCC)          // undefined tag, 3 bytes
            .Tag(TzspTags.Timestamp, 1, 2, 3, 4)  // known but deliberately ignored
            .End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(Frame, datagram.AsSpan(frame.PayloadOffset, frame.PayloadLength).ToArray());
    }

    [Fact]
    public void HonoursOriginalLengthTagWhenSensorTruncated()
    {
        byte[] datagram = TzspDatagram.Create().OriginalLength(1500).End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(Frame.Length, frame.PayloadLength);
        Assert.Equal(1500u, frame.OriginalLength);
    }

    [Fact]
    public void ClampsOriginalLengthThatIsShorterThanTheCapturedFrame()
    {
        // An EPB whose captured length exceeds its original length is invalid pcapng, so a sensor
        // reporting nonsense must not be able to produce one.
        byte[] datagram = TzspDatagram.Create().OriginalLength(10).End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal((uint)Frame.Length, frame.OriginalLength);
        Assert.True(frame.OriginalLength >= (uint)frame.PayloadLength);
    }

    [Fact]
    public void ParsesSensorAddressTag()
    {
        byte[] datagram = TzspDatagram.Create().SensorAddress(10, 0, 0, 1).End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.True(frame.HasSensorAddress);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), frame.GetSensorAddress());
    }

    [Fact]
    public void ReportsOkWithEmptyPayloadForKeepalives()
    {
        byte[] datagram = TzspDatagram.Create(TzspPacketType.Keepalive).End();

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(TzspPacketType.Keepalive, frame.Type);
        Assert.Equal(0, frame.PayloadLength);
        Assert.False(frame.CarriesFrame);
    }

    [Fact]
    public void ReportsOkWithEmptyPayloadWhenEndTagIsTheLastByte()
    {
        byte[] datagram = TzspDatagram.Create().End();

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(0, frame.PayloadLength);
        Assert.True(frame.CarriesFrame);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void RejectsDatagramShorterThanTheFixedHeader(int length)
    {
        Assert.Equal(TzspParseResult.TooShort, TzspParser.TryParse(new byte[length], out _));
    }

    [Fact]
    public void RejectsUnsupportedVersion()
    {
        byte[] datagram = TzspDatagram.Create(version: 2).End(Frame);

        Assert.Equal(TzspParseResult.UnsupportedVersion, TzspParser.TryParse(datagram, out _));
    }

    [Fact]
    public void RejectsTagListWithNoEndTag()
    {
        byte[] datagram = TzspDatagram.Create().Padding(2).WithoutEnd();

        Assert.Equal(TzspParseResult.MissingEndTag, TzspParser.TryParse(datagram, out _));
    }

    [Fact]
    public void RejectsTagWhoseLengthRunsPastTheDatagram()
    {
        // Tag 41 claims 8 bytes but only 2 follow.
        byte[] datagram = TzspDatagram.Create().RawBytes(TzspTags.OriginalLength, 0x08, 0x00, 0x00).WithoutEnd();

        Assert.Equal(TzspParseResult.MalformedTag, TzspParser.TryParse(datagram, out _));
    }

    [Fact]
    public void RejectsTagMissingItsLengthByte()
    {
        byte[] datagram = TzspDatagram.Create().RawBytes(TzspTags.OriginalLength).WithoutEnd();

        Assert.Equal(TzspParseResult.MalformedTag, TzspParser.TryParse(datagram, out _));
    }

    [Fact]
    public void PreservesEncapsulationForNonEthernetSensors()
    {
        byte[] datagram = TzspDatagram.Create(encapsulation: TzspEncapsulation.Ieee80211).End(Frame);

        Assert.Equal(TzspParseResult.Ok, TzspParser.TryParse(datagram, out var frame));
        Assert.Equal(TzspEncapsulation.Ieee80211, frame.Encapsulation);
    }

    [Theory]
    [InlineData(TzspEncapsulation.Ethernet, LinkType.Ethernet)]
    [InlineData(TzspEncapsulation.Ppp, LinkType.Ppp)]
    [InlineData(TzspEncapsulation.Raw, LinkType.Raw)]
    [InlineData(TzspEncapsulation.Ieee80211, LinkType.Ieee80211)]
    [InlineData(TzspEncapsulation.Ieee80211Radiotap, LinkType.Ieee80211Radiotap)]
    public void MapsKnownEncapsulationsToLinkTypes(ushort encapsulation, ushort expected)
    {
        Assert.True(LinkTypeMap.TryResolve(encapsulation, out ushort linkType));
        Assert.Equal(expected, linkType);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    [InlineData(999)]
    public void RefusesToGuessAtUnknownEncapsulations(ushort encapsulation)
    {
        Assert.False(LinkTypeMap.TryResolve(encapsulation, out ushort linkType));
        Assert.Equal(0, linkType);
    }
}
