using System.Buffers.Binary;
using System.Net;

namespace Oko.Tzsp;

/// <summary>Outcome of decoding a single TZSP datagram.</summary>
internal enum TzspParseResult
{
    /// <summary>Header and tag list are well-formed. The payload may still be empty.</summary>
    Ok,

    /// <summary>Fewer bytes than the fixed 4-byte header.</summary>
    TooShort,

    /// <summary>Version byte was not 1.</summary>
    UnsupportedVersion,

    /// <summary>A tag's length field ran past the end of the datagram.</summary>
    MalformedTag,

    /// <summary>The tag list ran to the end of the datagram without a TAG_END.</summary>
    MissingEndTag,
}

/// <summary>
/// A decoded TZSP datagram. Holds offsets into the caller's buffer rather than a span, so it can be
/// stored in locals and fields without <c>ref struct</c> restrictions.
/// </summary>
internal readonly struct TzspFrame
{
    /// <summary>Offset of the encapsulated frame within the datagram.</summary>
    public int PayloadOffset { get; init; }

    /// <summary>Length of the encapsulated frame. Zero for keepalives and other frameless types.</summary>
    public int PayloadLength { get; init; }

    /// <summary>Raw TZSP encapsulated-protocol code. Map it with <see cref="LinkTypeMap"/>.</summary>
    public ushort Encapsulation { get; init; }

    /// <summary>
    /// Frame length before the sensor truncated it, from TAG_ORIGINAL_LENGTH. Never less than
    /// <see cref="PayloadLength"/> — a pcapng EPB with <c>captured &gt; original</c> is invalid.
    /// </summary>
    public uint OriginalLength { get; init; }

    public TzspPacketType Type { get; init; }

    /// <summary>IPv4 address from TAG_SENSOR as a big-endian-read integer; zero when the tag is absent.</summary>
    public uint SensorAddressV4 { get; init; }

    public bool HasSensorAddress => SensorAddressV4 != 0;

    /// <summary>True for the two types that actually carry a frame.</summary>
    public bool CarriesFrame => Type is TzspPacketType.Received or TzspPacketType.Transmitted;

    public IPAddress GetSensorAddress()
    {
        Span<byte> octets = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(octets, SensorAddressV4);
        return new IPAddress(octets);
    }
}

/// <summary>
/// Decoder for the Tazmen Sniffer Protocol. Allocation-free, and tolerant of anything a sensor may
/// add: unknown tags are skipped, as the protocol requires.
/// </summary>
internal static class TzspParser
{
    /// <summary>Version, type, and the 16-bit encapsulation code.</summary>
    public const int HeaderLength = 4;

    public const byte SupportedVersion = 1;

    /// <summary>
    /// Decodes <paramref name="datagram"/>. Returns <see cref="TzspParseResult.Ok"/> whenever the
    /// header and tag list are structurally sound; deciding whether the result is worth storing
    /// (frame-carrying type, non-empty payload, supported encapsulation) is the caller's job, so
    /// each reason can be counted separately.
    /// </summary>
    public static TzspParseResult TryParse(ReadOnlySpan<byte> datagram, out TzspFrame frame)
    {
        frame = default;

        if (datagram.Length < HeaderLength)
        {
            return TzspParseResult.TooShort;
        }

        if (datagram[0] != SupportedVersion)
        {
            return TzspParseResult.UnsupportedVersion;
        }

        var type = (TzspPacketType)datagram[1];
        ushort encapsulation = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);

        uint taggedOriginalLength = 0;
        uint sensorAddressV4 = 0;
        int cursor = HeaderLength;

        while (true)
        {
            if (cursor >= datagram.Length)
            {
                return TzspParseResult.MissingEndTag;
            }

            byte tag = datagram[cursor++];

            if (tag == TzspTags.End)
            {
                break;
            }

            // PAD and END are the only tags without a length field.
            if (tag == TzspTags.Padding)
            {
                continue;
            }

            if (cursor >= datagram.Length)
            {
                return TzspParseResult.MalformedTag;
            }

            byte length = datagram[cursor++];

            if (cursor + length > datagram.Length)
            {
                return TzspParseResult.MalformedTag;
            }

            ReadOnlySpan<byte> value = datagram.Slice(cursor, length);

            switch (tag)
            {
                case TzspTags.OriginalLength when length == 2:
                    taggedOriginalLength = BinaryPrimitives.ReadUInt16BigEndian(value);
                    break;

                case TzspTags.SensorAddress when length == 4:
                    sensorAddressV4 = BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;
            }

            cursor += length;
        }

        int payloadLength = datagram.Length - cursor;

        frame = new TzspFrame
        {
            PayloadOffset = cursor,
            PayloadLength = payloadLength,
            Encapsulation = encapsulation,
            // A sensor that reports a shorter original length than it actually sent would produce an
            // EPB where captured > original, which Wireshark reports as malformed. Clamp instead.
            OriginalLength = Math.Max(taggedOriginalLength, (uint)payloadLength),
            Type = type,
            SensorAddressV4 = sensorAddressV4,
        };

        return TzspParseResult.Ok;
    }
}
