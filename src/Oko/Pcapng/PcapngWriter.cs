using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace Oko.Pcapng;

/// <summary>
/// Emits pcapng blocks. Always little-endian: Wireshark requires pcapng read from a pipe to match the
/// host's endianness, and every platform Oko targets is little-endian.
/// </summary>
/// <remarks>
/// Oko encodes each frame into its final EPB bytes at ingest time, so <see cref="WriteEnhancedPacket"/>
/// is on the hot path and must stay allocation-free. The section and interface blocks are written once
/// per segment (or once per newly-seen sensor) and can afford to be straightforward.
/// </remarks>
internal static class PcapngWriter
{
    /// <summary>
    /// Value for the <c>if_tsresol</c> option: MSB clear means 10^-n, so 9 selects nanoseconds.
    /// </summary>
    public const byte NanosecondResolution = 9;

    /// <summary>Fixed overhead of an EPB: 8 bytes of block header, 20 of fields, 4 of trailing length.</summary>
    private const int EnhancedPacketOverhead = 32;

    private static readonly byte[] NanosecondResolutionValue = [NanosecondResolution];

    /// <summary>Exact number of bytes <see cref="WriteEnhancedPacket"/> will write for this capture length.</summary>
    public static int EnhancedPacketSize(int capturedLength) => EnhancedPacketOverhead + Align4(capturedLength);

    /// <summary>
    /// Writes one Enhanced Packet Block into <paramref name="destination"/> and returns the number of
    /// bytes written. The caller must have reserved at least <see cref="EnhancedPacketSize"/> bytes.
    /// </summary>
    /// <param name="timestampNanoseconds">
    /// Nanoseconds since the Unix epoch, matching the <c>if_tsresol</c> of 9 that
    /// <see cref="WriteInterfaceDescription"/> records.
    /// </param>
    public static int WriteEnhancedPacket(
        Span<byte> destination,
        uint interfaceId,
        ulong timestampNanoseconds,
        ReadOnlySpan<byte> frame,
        uint originalLength)
    {
        Debug.Assert(originalLength >= (uint)frame.Length, "captured length must not exceed original length");

        int padding = (-frame.Length) & 3;
        int total = EnhancedPacketOverhead + frame.Length + padding;

        BinaryPrimitives.WriteUInt32LittleEndian(destination, BlockType.EnhancedPacket);
        BinaryPrimitives.WriteInt32LittleEndian(destination[4..], total);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], interfaceId);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], (uint)(timestampNanoseconds >> 32));
        BinaryPrimitives.WriteUInt32LittleEndian(destination[16..], (uint)timestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[20..], (uint)frame.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[24..], originalLength);
        frame.CopyTo(destination[28..]);
        destination.Slice(28 + frame.Length, padding).Clear();
        BinaryPrimitives.WriteInt32LittleEndian(destination[(total - 4)..], total);

        return total;
    }

    /// <summary>Writes the Section Header Block that opens every pcapng stream Oko produces.</summary>
    /// <param name="comment">
    /// Optional <c>opt_comment</c>. Segment files carry their metadata here so a file copied off the
    /// volume explains itself.
    /// </param>
    public static void WriteSectionHeader(IBufferWriter<byte> writer, string userApplication, string? comment = null)
    {
        int userApplicationBytes = Encoding.UTF8.GetByteCount(userApplication);
        int commentBytes = comment is null ? 0 : Encoding.UTF8.GetByteCount(comment);

        int options = OptionSize(userApplicationBytes)
            + (comment is null ? 0 : OptionSize(commentBytes))
            + EndOfOptionsSize;

        // 8 block header + 16 fixed fields + options + 4 trailing length.
        int total = 28 + options;
        var span = writer.GetSpan(total);
        var cursor = new SpanWriter(span);

        cursor.WriteUInt32(BlockType.SectionHeader);
        cursor.WriteInt32(total);
        cursor.WriteUInt32(0x1A2B3C4D); // byte-order magic
        cursor.WriteUInt16(1);          // major version
        cursor.WriteUInt16(0);          // minor version
        cursor.WriteInt64(-1);          // section length: unknown

        cursor.WriteStringOption(OptionCode.ShbUserAppl, userApplication, userApplicationBytes);
        if (comment is not null)
        {
            cursor.WriteStringOption(OptionCode.Comment, comment, commentBytes);
        }

        cursor.WriteEndOfOptions();
        cursor.WriteInt32(total);

        Debug.Assert(cursor.Position == total, "SHB size calculation disagrees with what was written");
        writer.Advance(total);
    }

    /// <summary>
    /// Writes an Interface Description Block. Interface IDs are implicit: the n-th IDB in a section is
    /// interface n, which is why Oko emits its whole interface table in a stable order.
    /// </summary>
    /// <param name="snapshotLength">Zero means no limit.</param>
    public static void WriteInterfaceDescription(
        IBufferWriter<byte> writer,
        ushort linkType,
        uint snapshotLength,
        string name,
        string description)
    {
        int nameBytes = Encoding.UTF8.GetByteCount(name);
        int descriptionBytes = Encoding.UTF8.GetByteCount(description);

        int options = OptionSize(nameBytes)
            + OptionSize(descriptionBytes)
            + OptionSize(NanosecondResolutionValue.Length)
            + EndOfOptionsSize;

        // 8 block header + 8 fixed fields + options + 4 trailing length.
        int total = 20 + options;
        var span = writer.GetSpan(total);
        var cursor = new SpanWriter(span);

        cursor.WriteUInt32(BlockType.InterfaceDescription);
        cursor.WriteInt32(total);
        cursor.WriteUInt16(linkType);
        cursor.WriteUInt16(0); // reserved
        cursor.WriteUInt32(snapshotLength);

        cursor.WriteStringOption(OptionCode.IfName, name, nameBytes);
        cursor.WriteStringOption(OptionCode.IfDescription, description, descriptionBytes);
        cursor.WriteOption(OptionCode.IfTsResol, NanosecondResolutionValue);

        cursor.WriteEndOfOptions();
        cursor.WriteInt32(total);

        Debug.Assert(cursor.Position == total, "IDB size calculation disagrees with what was written");
        writer.Advance(total);
    }

    /// <summary>Option header plus value plus padding to a 32-bit boundary.</summary>
    private static int OptionSize(int valueLength) => 4 + Align4(valueLength);

    /// <summary><c>opt_endofopt</c> is a bare header with a zero length.</summary>
    private const int EndOfOptionsSize = 4;

    private static int Align4(int value) => (value + 3) & ~3;

    /// <summary>Sequential little-endian writer over a caller-provided span.</summary>
    private ref struct SpanWriter
    {
        private readonly Span<byte> _destination;
        private int _position;

        public SpanWriter(Span<byte> destination)
        {
            _destination = destination;
            _position = 0;
        }

        public int Position => _position;

        public void WriteUInt16(ushort value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(_destination[_position..], value);
            _position += 2;
        }

        public void WriteUInt32(uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(_destination[_position..], value);
            _position += 4;
        }

        public void WriteInt32(int value)
        {
            BinaryPrimitives.WriteInt32LittleEndian(_destination[_position..], value);
            _position += 4;
        }

        public void WriteInt64(long value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(_destination[_position..], value);
            _position += 8;
        }

        public void WriteStringOption(ushort code, string value, int utf8ByteCount)
        {
            WriteUInt16(code);
            WriteUInt16((ushort)utf8ByteCount);
            Encoding.UTF8.GetBytes(value, _destination.Slice(_position, utf8ByteCount));
            _position += utf8ByteCount;
            Pad();
        }

        public void WriteOption(ushort code, ReadOnlySpan<byte> value)
        {
            WriteUInt16(code);
            WriteUInt16((ushort)value.Length);
            value.CopyTo(_destination[_position..]);
            _position += value.Length;
            Pad();
        }

        public void WriteEndOfOptions()
        {
            WriteUInt16(OptionCode.EndOfOpt);
            WriteUInt16(0);
        }

        /// <summary>Zero-fills up to the next 32-bit boundary. Option lengths exclude this padding.</summary>
        private void Pad()
        {
            int padding = (-_position) & 3;
            _destination.Slice(_position, padding).Clear();
            _position += padding;
        }
    }
}
