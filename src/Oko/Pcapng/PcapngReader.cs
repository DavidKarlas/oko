using System.Buffers.Binary;

namespace Oko.Pcapng;

/// <summary>Just enough pcapng reading for Oko's own segment files.</summary>
internal static class PcapngReader
{
    /// <summary>Smallest legal block: type, total length, and the repeated total length.</summary>
    public const int MinimumBlockLength = 12;

    /// <summary>Type plus total length.</summary>
    public const int BlockHeaderLength = 8;

    /// <summary>Fields preceding the packet data in an EPB.</summary>
    public const int EnhancedPacketFieldsLength = 28;

    /// <summary>
    /// Offset of the first packet block, i.e. the end of the SHB and IDB preamble.
    /// </summary>
    /// <remarks>
    /// This is what makes the read path cheap: because every segment carries the whole interface table
    /// in a stable order, a reader can emit one preamble of its own and then take each segment's bytes
    /// from here on without rewriting any interface IDs. Only a handful of blocks are walked, since
    /// block lengths are self-delimiting.
    /// </remarks>
    public static long FindFirstPacketBlockOffset(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        Span<byte> header = stackalloc byte[BlockHeaderLength];
        long offset = 0;
        long length = stream.Length;

        while (offset + BlockHeaderLength <= length)
        {
            stream.Position = offset;
            stream.ReadExactly(header);

            uint blockType = BinaryPrimitives.ReadUInt32LittleEndian(header);
            uint totalLength = BinaryPrimitives.ReadUInt32LittleEndian(header[4..]);

            if (blockType is BlockType.EnhancedPacket or BlockType.SimplePacket)
            {
                return offset;
            }

            if (totalLength < MinimumBlockLength || totalLength % 4 != 0 || offset + totalLength > length)
            {
                throw new InvalidDataException(
                    $"malformed pcapng block at offset {offset}: type 0x{blockType:X8}, length {totalLength}");
            }

            offset += totalLength;
        }

        // A segment with no packet blocks at all; nothing to copy.
        return length;
    }

    /// <summary>
    /// Reads an EPB's timestamp. The caller must have positioned <paramref name="block"/> at the start
    /// of a block whose type is <see cref="BlockType.EnhancedPacket"/>.
    /// </summary>
    public static ulong ReadEnhancedPacketTimestamp(ReadOnlySpan<byte> block) =>
        ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(block[12..]) << 32) |
        BinaryPrimitives.ReadUInt32LittleEndian(block[16..]);

    public static uint ReadBlockType(ReadOnlySpan<byte> block) =>
        BinaryPrimitives.ReadUInt32LittleEndian(block);

    public static uint ReadBlockTotalLength(ReadOnlySpan<byte> block) =>
        BinaryPrimitives.ReadUInt32LittleEndian(block[4..]);
}
