namespace Oko.Pcapng;

/// <summary>pcapng block type codes.</summary>
internal static class BlockType
{
    /// <summary>Palindromic on purpose: it detects a file mangled by CRLF translation.</summary>
    public const uint SectionHeader = 0x0A0D0D0A;

    public const uint InterfaceDescription = 0x00000001;
    public const uint SimplePacket = 0x00000003;
    public const uint InterfaceStatistics = 0x00000005;
    public const uint EnhancedPacket = 0x00000006;
}

/// <summary>
/// pcapng option codes. Codes are scoped to their containing block type, so the same numeric value
/// means different things in an SHB and an IDB.
/// </summary>
internal static class OptionCode
{
    public const ushort EndOfOpt = 0;
    public const ushort Comment = 1;

    public const ushort ShbHardware = 2;
    public const ushort ShbOs = 3;
    public const ushort ShbUserAppl = 4;

    public const ushort IfName = 2;
    public const ushort IfDescription = 3;
    public const ushort IfTsResol = 9;
    public const ushort IfTsOffset = 14;
    public const ushort IfHardware = 15;

    public const ushort EpbDropCount = 4;
}

/// <summary>LinkType codes shared by pcap and pcapng.</summary>
internal static class LinkType
{
    public const ushort Ethernet = 1;
    public const ushort TokenRing = 6;
    public const ushort Slip = 8;
    public const ushort Ppp = 9;
    public const ushort Fddi = 10;
    public const ushort Raw = 101;
    public const ushort Ieee80211 = 105;

    /// <summary>Linux cooked capture. What older <c>tcpdump -i any</c> produced.</summary>
    public const ushort LinuxSll = 113;

    public const ushort Ieee80211Prism = 119;
    public const ushort Ieee80211Radiotap = 127;
    public const ushort Ieee80211Avs = 163;

    /// <summary>
    /// Linux cooked capture v2, which current <c>tcpdump -i any</c> produces. Note that TZSP has no
    /// encapsulation code for this, so it can only reach Oko over the pcap TCP ingest.
    /// </summary>
    public const ushort LinuxSll2 = 276;
}
