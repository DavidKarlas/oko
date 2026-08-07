using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using Oko.Pcapng;

namespace Oko.Tests;

public class PcapngWriterTests : IDisposable
{
    private const string UserApplication = "Oko/0.1.0-test";

    private readonly string _directory =
        Directory.CreateTempSubdirectory("oko-pcapng-tests-").FullName;

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    // ---- EPB layout ----------------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(42)]
    [InlineData(60)]
    [InlineData(1514)]
    public void EnhancedPacketSizePredictsBytesWrittenExactly(int frameLength)
    {
        byte[] frame = CreateFrame(frameLength);
        int predicted = PcapngWriter.EnhancedPacketSize(frameLength);
        var destination = new byte[predicted + 16];

        int written = PcapngWriter.WriteEnhancedPacket(destination, 0, 1, frame, (uint)frameLength);

        Assert.Equal(predicted, written);
        Assert.Equal(0, written % 4);
        // Nothing was written past the predicted size.
        Assert.All(destination[written..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void EnhancedPacketFieldsLandAtTheirSpecifiedOffsets()
    {
        byte[] frame = TestFrames.ArpRequest;
        const ulong timestamp = 0x0123456789ABCDEFUL;
        var destination = new byte[PcapngWriter.EnhancedPacketSize(frame.Length)];

        int written = PcapngWriter.WriteEnhancedPacket(destination, 7, timestamp, frame, 1500);

        Assert.Equal(0x00000006u, BinaryPrimitives.ReadUInt32LittleEndian(destination));
        Assert.Equal(written, BinaryPrimitives.ReadInt32LittleEndian(destination.AsSpan(4)));
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32LittleEndian(destination.AsSpan(8)));
        Assert.Equal(0x01234567u, BinaryPrimitives.ReadUInt32LittleEndian(destination.AsSpan(12)));
        Assert.Equal(0x89ABCDEFu, BinaryPrimitives.ReadUInt32LittleEndian(destination.AsSpan(16)));
        Assert.Equal((uint)frame.Length, BinaryPrimitives.ReadUInt32LittleEndian(destination.AsSpan(20)));
        Assert.Equal(1500u, BinaryPrimitives.ReadUInt32LittleEndian(destination.AsSpan(24)));
        Assert.Equal(frame, destination.AsSpan(28, frame.Length).ToArray());

        // Block Total Length is repeated in the last four bytes so readers can walk backwards.
        Assert.Equal(written, BinaryPrimitives.ReadInt32LittleEndian(destination.AsSpan(written - 4)));
    }

    [Fact]
    public void EnhancedPacketPadsFrameDataWithZerosToA32BitBoundary()
    {
        byte[] frame = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]; // 5 bytes -> 3 bytes of padding
        var destination = new byte[PcapngWriter.EnhancedPacketSize(frame.Length)];

        int written = PcapngWriter.WriteEnhancedPacket(destination, 0, 0, frame, (uint)frame.Length);

        Assert.Equal(40, written);
        // Captured Packet Length excludes the padding.
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(destination.AsSpan(20)));
        Assert.Equal(new byte[] { 0, 0, 0 }, destination.AsSpan(33, 3).ToArray());
    }

    // ---- SHB / IDB layout ----------------------------------------------------------------------

    [Fact]
    public void SectionHeaderHasByteOrderMagicAndMatchingLengthFields()
    {
        var writer = new ArrayBufferWriter<byte>();
        PcapngWriter.WriteSectionHeader(writer, UserApplication);
        byte[] block = writer.WrittenSpan.ToArray();

        Assert.Equal(0x0A0D0D0Au, BinaryPrimitives.ReadUInt32LittleEndian(block));
        Assert.Equal(0x1A2B3C4Du, BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(8)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(12)));  // major
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(14)));  // minor
        Assert.Equal(-1L, BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(16))); // section length unknown
        AssertBlockLengthsAgree(block);
    }

    [Fact]
    public void InterfaceDescriptionRecordsLinkTypeSnapLenAndNanosecondResolution()
    {
        var writer = new ArrayBufferWriter<byte>();
        PcapngWriter.WriteInterfaceDescription(writer, LinkType.Ethernet, 65535, "10.0.0.1", "TZSP sensor");
        byte[] block = writer.WrittenSpan.ToArray();

        Assert.Equal(0x00000001u, BinaryPrimitives.ReadUInt32LittleEndian(block));
        Assert.Equal(LinkType.Ethernet, BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(8)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(10))); // reserved
        Assert.Equal(65535u, BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(12)));
        AssertBlockLengthsAgree(block);

        // if_tsresol = 9 is what makes the EPB timestamps nanoseconds rather than microseconds.
        Assert.Equal(PcapngWriter.NanosecondResolution, FindOptionValue(block, 16, OptionCode.IfTsResol)[0]);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("ab")]
    [InlineData("abc")]
    [InlineData("abcd")]
    [InlineData("abcde")]
    [InlineData("sensor-äöü")] // multi-byte UTF-8, so byte count != char count
    public void BlocksStay32BitAlignedForEveryOptionLength(string name)
    {
        var writer = new ArrayBufferWriter<byte>();
        PcapngWriter.WriteSectionHeader(writer, name, comment: name);
        PcapngWriter.WriteInterfaceDescription(writer, LinkType.Ethernet, 0, name, name);

        Assert.Equal(0, writer.WrittenCount % 4);
    }

    // ---- Validation against the real Wireshark tools -------------------------------------------

    [Fact]
    public void WiresharkAcceptsAFileOkoWrote()
    {
        string path = WriteCaptureFile(
            "single-sensor.pcapng",
            [("10.0.0.1", LinkType.Ethernet)],
            [(0, 1_700_000_000_123_456_789UL, TestFrames.ArpRequest)]);

        Wireshark.AssertFileIsValid(path);
        Assert.Equal(["1"], Wireshark.ReadField(path, "frame.number"));
    }

    [Fact]
    public void WiresharkAttributesEachFrameToTheRightSensorInterface()
    {
        // This is the payoff for choosing pcapng over classic pcap: the source router survives.
        string path = WriteCaptureFile(
            "two-sensors.pcapng",
            [("10.0.0.1", LinkType.Ethernet), ("10.0.0.2", LinkType.Ethernet)],
            [
                (0, 1_700_000_000_000_000_000UL, TestFrames.ArpRequest),
                (1, 1_700_000_000_100_000_000UL, TestFrames.ArpRequest),
                (0, 1_700_000_000_200_000_000UL, TestFrames.ArpRequest),
            ]);

        Wireshark.AssertFileIsValid(path);
        Assert.Equal(
            ["10.0.0.1", "10.0.0.2", "10.0.0.1"],
            Wireshark.ReadField(path, "frame.interface_name"));
    }

    [Fact]
    public void WiresharkReadsBackFullNanosecondPrecision()
    {
        // 987654321 ns would be truncated to 987654000 if if_tsresol were microseconds.
        const ulong timestamp = 1_700_000_000_987_654_321UL;
        string path = WriteCaptureFile(
            "nanoseconds.pcapng",
            [("10.0.0.1", LinkType.Ethernet)],
            [(0, timestamp, TestFrames.ArpRequest)]);

        string[] epochs = Wireshark.ReadField(path, "frame.time_epoch");

        Assert.Equal(
            (timestamp / 1_000_000_000UL).ToString(CultureInfo.InvariantCulture) + ".987654321",
            epochs.Single());
    }

    [Fact]
    public void WiresharkReportsTheOriginalLengthOfATruncatedFrame()
    {
        byte[] truncated = TestFrames.ArpRequest[..20];
        string path = WriteCaptureFile(
            "truncated.pcapng",
            [("10.0.0.1", LinkType.Ethernet)],
            [(0, 1_700_000_000_000_000_000UL, truncated)],
            originalLength: 1514);

        var capinfos = Wireshark.Run("capinfos", path);
        Assert.Equal(0, capinfos.ExitCode);
        Assert.Equal(["20"], Wireshark.ReadField(path, "frame.cap_len"));
        Assert.Equal(["1514"], Wireshark.ReadField(path, "frame.len"));
    }

    [Fact]
    public void WiresharkAcceptsAManyPacketFileWithMixedFrameLengths()
    {
        // Consecutive lengths cover all four padding cases repeatedly across a realistic block sequence.
        var packets = new List<(uint, ulong, byte[])>();
        for (int i = 0; i < 200; i++)
        {
            packets.Add((
                0,
                1_700_000_000_000_000_000UL + ((ulong)i * 1_000_000UL),
                TestFrames.Udp(TestFrames.MinimumUdpFrameLength + i, identification: (ushort)i)));
        }

        string path = WriteCaptureFile("many.pcapng", [("10.0.0.1", LinkType.Ethernet)], packets);

        Wireshark.AssertFileIsValid(path);
        Assert.Equal(200, Wireshark.ReadField(path, "frame.number").Length);
    }

    // ---- helpers -------------------------------------------------------------------------------

    private string WriteCaptureFile(
        string fileName,
        (string Name, ushort LinkType)[] interfaces,
        IEnumerable<(uint InterfaceId, ulong TimestampNanoseconds, byte[] Frame)> packets,
        uint originalLength = 0)
    {
        var writer = new ArrayBufferWriter<byte>();
        PcapngWriter.WriteSectionHeader(writer, UserApplication, comment: $"written by {nameof(PcapngWriterTests)}");

        foreach ((string name, ushort linkType) in interfaces)
        {
            PcapngWriter.WriteInterfaceDescription(writer, linkType, 0, name, $"TZSP sensor {name}");
        }

        foreach ((uint interfaceId, ulong timestamp, byte[] frame) in packets)
        {
            var span = writer.GetSpan(PcapngWriter.EnhancedPacketSize(frame.Length));
            int written = PcapngWriter.WriteEnhancedPacket(
                span,
                interfaceId,
                timestamp,
                frame,
                originalLength == 0 ? (uint)frame.Length : originalLength);
            writer.Advance(written);
        }

        string path = Path.Combine(_directory, fileName);
        File.WriteAllBytes(path, writer.WrittenSpan.ToArray());
        return path;
    }

    private static byte[] CreateFrame(int length)
    {
        var frame = new byte[length];
        for (int i = 0; i < length; i++)
        {
            frame[i] = (byte)(i + 1);
        }

        return frame;
    }

    private static void AssertBlockLengthsAgree(byte[] block)
    {
        int declared = BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(4));
        Assert.Equal(block.Length, declared);
        Assert.Equal(0, declared % 4);
        Assert.Equal(declared, BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(declared - 4)));
    }

    /// <summary>Walks a block's option list looking for <paramref name="code"/>.</summary>
    private static byte[] FindOptionValue(byte[] block, int optionsOffset, ushort code)
    {
        int cursor = optionsOffset;
        int end = block.Length - 4;

        while (cursor + 4 <= end)
        {
            ushort optionCode = BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(cursor));
            ushort length = BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(cursor + 2));

            if (optionCode == OptionCode.EndOfOpt)
            {
                break;
            }

            if (optionCode == code)
            {
                return block.AsSpan(cursor + 4, length).ToArray();
            }

            cursor += 4 + ((length + 3) & ~3);
        }

        Assert.Fail($"option {code} not present in block");
        return [];
    }
}
