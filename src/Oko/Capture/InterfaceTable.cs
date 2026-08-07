using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Oko.Tzsp;

namespace Oko.Capture;

/// <summary>One pcapng interface: a distinct (sensor address, link type) pair.</summary>
internal sealed record SensorInterface(uint Id, IPAddress Address, ushort LinkType)
{
    /// <summary>Becomes the IDB's <c>if_name</c>, which Wireshark shows as <c>frame.interface_name</c>.</summary>
    public string Name => Address.ToString();

    public string Description => $"TZSP sensor {Address} ({LinkTypeMap.DescribeLinkType(LinkType)})";
}

/// <summary>
/// Append-only map from sensor to pcapng interface ID, persisted across restarts.
/// </summary>
/// <remarks>
/// <para>
/// IDs are positions in a pcapng section, so they are only meaningful relative to the IDB list a
/// reader has seen. Oko therefore assigns an ID once and never reuses or renumbers it, and every
/// segment writes the whole table in ID order. That is what lets a range query emit one IDB list up
/// front and then copy each segment's packet bytes verbatim — no interface-ID remapping.
/// </para>
/// <para>
/// The corollary is that losing this file would make every existing segment misattribute its frames,
/// so it is fsynced and atomically renamed before the caller writes any EPB referencing a new ID, and
/// retention must never delete it.
/// </para>
/// </remarks>
internal sealed class InterfaceTable
{
    private readonly Lock _gate = new();
    private readonly List<SensorInterface> _interfaces = [];
    private readonly Dictionary<(IPAddress Address, ushort LinkType), uint> _byKey = [];
    private readonly string _path;

    public InterfaceTable(string path)
    {
        _path = path;
        Load();
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _interfaces.Count;
            }
        }
    }

    /// <summary>
    /// Returns the interface for a sensor, assigning and persisting a new one on first sight.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns the whole <see cref="SensorInterface"/> rather than just the ID so callers use the
    /// canonical, normalised address. Returning only the ID previously let <c>/status</c> report
    /// <c>::ffff:127.0.0.1</c> for a sensor whose IDB said <c>127.0.0.1</c>.
    /// </para>
    /// <para>
    /// Persisting here means a synchronous disk write on the receive path, but only ever once per
    /// sensor. Doing it lazily would risk a segment referencing an ID that no longer exists after a
    /// crash.
    /// </para>
    /// </remarks>
    public SensorInterface Resolve(IPAddress address, ushort linkType)
    {
        ArgumentNullException.ThrowIfNull(address);
        address = Normalize(address);

        lock (_gate)
        {
            if (_byKey.TryGetValue((address, linkType), out uint existing))
            {
                return _interfaces[(int)existing];
            }

            var added = new SensorInterface((uint)_interfaces.Count, address, linkType);
            _interfaces.Add(added);
            _byKey[(address, linkType)] = added.Id;
            Save();
            return added;
        }
    }

    /// <summary>The whole table in ID order, which is the order IDBs must be written in.</summary>
    public SensorInterface[] Snapshot()
    {
        lock (_gate)
        {
            return [.. _interfaces];
        }
    }

    /// <summary>
    /// An IPv4 datagram arriving on a dual-mode socket is reported as <c>::ffff:10.0.0.1</c>; without
    /// normalising, the same router would get two interface IDs depending on how Oko was bound.
    /// </summary>
    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private void Load()
    {
        if (!File.Exists(_path))
        {
            return;
        }

        PersistedInterface[]? persisted;
        try
        {
            using FileStream stream = File.OpenRead(_path);
            persisted = JsonSerializer.Deserialize(stream, OkoJson.Default.PersistedInterfaceArray);
        }
        catch (Exception exception) when (exception is JsonException or IOException)
        {
            throw new InvalidOperationException(
                $"'{_path}' could not be read. It maps sensors to pcapng interface IDs; starting without " +
                "it would make existing segments attribute frames to the wrong sensor. Move the segment " +
                "directory aside if you intend to start fresh.",
                exception);
        }

        if (persisted is null)
        {
            return;
        }

        // IDs are positions, so restore them in order and fail loudly on a gap rather than silently
        // shifting every interface.
        foreach (PersistedInterface entry in persisted.OrderBy(entry => entry.Id))
        {
            if (entry.Id != (uint)_interfaces.Count)
            {
                throw new InvalidOperationException(
                    $"'{_path}' has a gap or duplicate at interface ID {entry.Id}; IDs must be dense and " +
                    "start at 0 because pcapng interface IDs are positional.");
            }

            if (!IPAddress.TryParse(entry.Address, out IPAddress? address))
            {
                throw new InvalidOperationException($"'{_path}' has an unparseable address '{entry.Address}'.");
            }

            var restored = new SensorInterface(entry.Id, Normalize(address), entry.LinkType);
            _interfaces.Add(restored);
            _byKey[(restored.Address, restored.LinkType)] = restored.Id;
        }
    }

    /// <summary>Writes the table durably: fsync then atomic rename, so a crash cannot leave it torn.</summary>
    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

        PersistedInterface[] persisted =
            [.. _interfaces.Select(entry => new PersistedInterface(entry.Id, entry.Address.ToString(), entry.LinkType))];

        string temporaryPath = _path + ".tmp";
        using (var stream = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, persisted, OkoJson.Default.PersistedInterfaceArray);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporaryPath, _path, overwrite: true);
    }

    internal sealed record PersistedInterface(uint Id, string Address, ushort LinkType);
}

[JsonSerializable(typeof(InterfaceTable.PersistedInterface[]))]
[JsonSerializable(typeof(SegmentMetadata))]
[JsonSerializable(typeof(Oko.Http.StatusResponse))]
[JsonSourceGenerationOptions(WriteIndented = true)]
internal sealed partial class OkoJson : JsonSerializerContext;
