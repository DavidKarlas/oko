namespace Oko.Tzsp;

/// <summary>
/// TZSP tagged-field type codes. Values match Wireshark's <c>epan/dissectors/packet-tzsp.c</c>.
/// </summary>
/// <remarks>
/// <see cref="Padding"/> and <see cref="End"/> are one byte wide and carry no length field.
/// Every other tag is <c>[type][length][value]</c>. Decoders must skip tags they do not know.
/// </remarks>
internal static class TzspTags
{
    public const byte Padding = 0;
    public const byte End = 1;

    // 802.11 radio header tags — only meaningful for the IEEE 802.11 encapsulations.
    public const byte WlanRadioSignal = 10;
    public const byte WlanRadioNoise = 11;
    public const byte WlanRadioRate = 12;
    public const byte WlanRadioTimestamp = 13;
    public const byte WlanRadioMessageType = 14;
    public const byte WlanRadioContentionFree = 15;
    public const byte WlanRadioUndecrypted = 16;
    public const byte WlanRadioFcsError = 17;
    public const byte WlanRadioChannel = 18;

    public const byte WlanStation = 30;
    public const byte WlanPacket = 31;

    /// <summary>Sensor-assigned packet counter. Reserved for future upstream-loss detection.</summary>
    public const byte PacketId = 40;

    /// <summary>Frame length before the sensor truncated it. Two bytes, big-endian.</summary>
    public const byte OriginalLength = 41;

    /// <summary>Sensor's own address. Four bytes for IPv4.</summary>
    public const byte SensorAddress = 60;

    public const byte DeviceName = 80;
    public const byte CaptureLocation = 81;

    /// <summary>Sensor timestamp. Deliberately ignored — its epoch is unspecified.</summary>
    public const byte Timestamp = 82;

    public const byte Info = 83;
    public const byte CaptureId = 84;
}

/// <summary>TZSP packet types. Only <see cref="Received"/> and <see cref="Transmitted"/> carry a frame.</summary>
internal enum TzspPacketType : byte
{
    Received = 0,
    Transmitted = 1,
    Configuration = 3,

    /// <summary>Keepalive. Sent to hold a NAT mapping open; carries no frame.</summary>
    Keepalive = 4,

    PortOpener = 5,
}

/// <summary>TZSP encapsulated-protocol codes, as carried in bytes 2-3 of the header.</summary>
internal static class TzspEncapsulation
{
    public const ushort Ethernet = 1;
    public const ushort TokenRing = 2;
    public const ushort Slip = 3;
    public const ushort Ppp = 4;
    public const ushort Fddi = 5;
    public const ushort Raw = 7;
    public const ushort Ieee80211 = 18;
    public const ushort Ieee80211Prism = 119;
    public const ushort Ieee80211Radiotap = 126;
    public const ushort Ieee80211Avs = 127;
}
