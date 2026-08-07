using Oko.Tzsp;

namespace Oko.Tests;

/// <summary>Builds TZSP datagrams byte by byte so parser tests read like the wire format.</summary>
internal sealed class TzspDatagram
{
    private readonly List<byte> _bytes = [];

    private TzspDatagram(byte version, TzspPacketType type, ushort encapsulation)
    {
        _bytes.Add(version);
        _bytes.Add((byte)type);
        _bytes.Add((byte)(encapsulation >> 8));
        _bytes.Add((byte)encapsulation);
    }

    public static TzspDatagram Create(
        TzspPacketType type = TzspPacketType.Received,
        ushort encapsulation = TzspEncapsulation.Ethernet,
        byte version = TzspParser.SupportedVersion) => new(version, type, encapsulation);

    public TzspDatagram Padding(int count = 1)
    {
        for (int i = 0; i < count; i++)
        {
            _bytes.Add(TzspTags.Padding);
        }

        return this;
    }

    public TzspDatagram Tag(byte tag, params byte[] value)
    {
        _bytes.Add(tag);
        _bytes.Add((byte)value.Length);
        _bytes.AddRange(value);
        return this;
    }

    /// <summary>Appends a tag byte and length byte only, to exercise truncation handling.</summary>
    public TzspDatagram RawBytes(params byte[] bytes)
    {
        _bytes.AddRange(bytes);
        return this;
    }

    public TzspDatagram OriginalLength(ushort length) =>
        Tag(TzspTags.OriginalLength, (byte)(length >> 8), (byte)length);

    public TzspDatagram SensorAddress(byte a, byte b, byte c, byte d) =>
        Tag(TzspTags.SensorAddress, a, b, c, d);

    /// <summary>Terminates the tag list and appends the encapsulated frame.</summary>
    public byte[] End(ReadOnlySpan<byte> frame = default)
    {
        _bytes.Add(TzspTags.End);
        _bytes.AddRange(frame);
        return [.. _bytes];
    }

    /// <summary>Returns the datagram without a TAG_END, to exercise the unterminated case.</summary>
    public byte[] WithoutEnd() => [.. _bytes];
}
