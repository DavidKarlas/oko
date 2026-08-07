using Oko.Pcapng;

namespace Oko.Tzsp;

/// <summary>Maps a TZSP encapsulated-protocol code onto the pcapng LinkType Oko records in the IDB.</summary>
internal static class LinkTypeMap
{
    /// <summary>
    /// Resolves <paramref name="encapsulation"/> to a pcapng LinkType.
    /// Returns <see langword="false"/> for encapsulations Oko will not store, so the caller can
    /// count and drop the datagram rather than write a frame under the wrong link type.
    /// </summary>
    public static bool TryResolve(ushort encapsulation, out ushort linkType)
    {
        linkType = encapsulation switch
        {
            TzspEncapsulation.Ethernet => LinkType.Ethernet,
            TzspEncapsulation.TokenRing => LinkType.TokenRing,
            TzspEncapsulation.Slip => LinkType.Slip,
            TzspEncapsulation.Ppp => LinkType.Ppp,
            TzspEncapsulation.Fddi => LinkType.Fddi,
            TzspEncapsulation.Raw => LinkType.Raw,
            TzspEncapsulation.Ieee80211 => LinkType.Ieee80211,
            TzspEncapsulation.Ieee80211Prism => LinkType.Ieee80211Prism,
            TzspEncapsulation.Ieee80211Radiotap => LinkType.Ieee80211Radiotap,
            TzspEncapsulation.Ieee80211Avs => LinkType.Ieee80211Avs,
            _ => 0,
        };

        return linkType != 0;
    }

    /// <summary>Human-readable name for a link type, used in the IDB's <c>if_description</c>.</summary>
    public static string DescribeLinkType(ushort linkType) => linkType switch
    {
        LinkType.Ethernet => "Ethernet",
        LinkType.TokenRing => "Token Ring",
        LinkType.Slip => "SLIP",
        LinkType.Ppp => "PPP",
        LinkType.Fddi => "FDDI",
        LinkType.Raw => "Raw IP",
        LinkType.Ieee80211 => "IEEE 802.11",
        LinkType.LinuxSll => "Linux cooked",
        LinkType.Ieee80211Prism => "IEEE 802.11 + Prism",
        LinkType.Ieee80211Radiotap => "IEEE 802.11 + Radiotap",
        LinkType.Ieee80211Avs => "IEEE 802.11 + AVS",
        LinkType.LinuxSll2 => "Linux cooked v2",
        _ => $"link type {linkType}",
    };
}
