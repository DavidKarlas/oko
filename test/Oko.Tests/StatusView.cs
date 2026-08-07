using System.Globalization;
using System.Text.Json;

namespace Oko.Tests;

/// <summary>
/// Reads <c>/status</c> from JSON. Deliberately parsed loosely rather than deserialised into the
/// production records, so a test failure means the wire contract changed — which is what a consumer
/// would experience — rather than just an internal type moving.
/// </summary>
internal sealed record StatusView(JsonDocument Document)
{
    public static StatusView Parse(string json) => new(JsonDocument.Parse(json));

    public double UptimeSeconds => Number("UptimeSeconds");

    public long FramesStored => (long)Number("Ingest", "FramesStored");

    public long PacketsReceived => (long)Number("Ingest", "PacketsReceived");

    public long Keepalives => (long)Number("Ingest", "Keepalives");

    public long ParseErrors => (long)Number("Ingest", "TzspParseErrors");

    public long UnsupportedEncapsulation => (long)Number("Ingest", "UnsupportedEncapsulation");

    public long PcapStreamErrors => (long)Number("Ingest", "PcapStreamErrors");

    public long CaptureLoopSuspects => (long)Number("Ingest", "CaptureLoopSuspects");

    public long ClockSkewedSenders => (long)Number("Ingest", "ClockSkewedSenders");

    public int UdpPort => (int)Number("Listen", "UdpPort");

    public int PcapTcpPort => (int)Number("Listen", "PcapTcpPort");

    public int Segments => (int)Number("Storage", "Segments");

    public long StorageBytes => (long)Number("Storage", "Bytes");

    public int ActiveBytes => (int)Number("Memory", "ActiveBytes");

    public long SealedBytes => (long)Number("Memory", "SealedBytes");

    public int LiveSubscribers => (int)Number("Live", "Subscribers");

    public string[] SensorAddresses =>
    [
        .. Document.RootElement.GetProperty("Sensors").EnumerateArray()
            .Select(sensor => sensor.GetProperty("Address").GetString() ?? ""),
    ];

    private double Number(params string[] path)
    {
        JsonElement element = Document.RootElement;
        foreach (string segment in path)
        {
            element = element.GetProperty(segment);
        }

        return element.GetDouble();
    }

    public override string ToString() => string.Create(
        CultureInfo.InvariantCulture,
        $"stored={FramesStored} segments={Segments} active={ActiveBytes} sealed={SealedBytes}");
}
