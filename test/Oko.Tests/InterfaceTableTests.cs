using System.Net;
using Oko.Capture;
using Oko.Pcapng;

namespace Oko.Tests;

public class InterfaceTableTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-interfaces-").FullName;

    private string Path => System.IO.Path.Combine(_directory, "interfaces.json");

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void AssignsDenseIdsStartingAtZeroBecausePcapngIdsArePositional()
    {
        var table = new InterfaceTable(Path);

        Assert.Equal(0u, table.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id);
        Assert.Equal(1u, table.Resolve(IPAddress.Parse("10.0.0.2"), LinkType.Ethernet).Id);
        Assert.Equal(2u, table.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ieee80211).Id);
        Assert.Equal(3, table.Count);
    }

    [Fact]
    public void ReturnsTheSameIdForARepeatedSensor()
    {
        var table = new InterfaceTable(Path);
        var address = IPAddress.Parse("192.168.88.1");

        uint first = table.Resolve(address, LinkType.Ethernet).Id;

        Assert.Equal(first, table.Resolve(address, LinkType.Ethernet).Id);
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void TreatsAnIPv4MappedAddressAsTheSameSensor()
    {
        // A dual-mode socket reports IPv4 senders as ::ffff:10.0.0.1. Without normalising, the same
        // router would get two interface IDs depending on how Oko happened to be bound.
        var table = new InterfaceTable(Path);

        uint viaIPv4 = table.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
        uint viaMapped = table.Resolve(IPAddress.Parse("::ffff:10.0.0.1"), LinkType.Ethernet).Id;

        Assert.Equal(viaIPv4, viaMapped);
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void PersistsIdsAcrossRestartsSoOlderSegmentsStayCorrect()
    {
        var original = new InterfaceTable(Path);
        original.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet);
        original.Resolve(IPAddress.Parse("10.0.0.2"), LinkType.Ethernet);

        var reloaded = new InterfaceTable(Path);

        Assert.Equal(2, reloaded.Count);
        Assert.Equal(0u, reloaded.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id);
        Assert.Equal(1u, reloaded.Resolve(IPAddress.Parse("10.0.0.2"), LinkType.Ethernet).Id);

        // A sensor first seen after the restart must continue the sequence, never reuse an ID.
        Assert.Equal(2u, reloaded.Resolve(IPAddress.Parse("10.0.0.3"), LinkType.Ethernet).Id);
    }

    [Fact]
    public void SnapshotIsOrderedByIdBecauseThatIsTheOrderIdbsMustBeWrittenIn()
    {
        var table = new InterfaceTable(Path);
        table.Resolve(IPAddress.Parse("10.0.0.9"), LinkType.Ethernet);
        table.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet);
        table.Resolve(IPAddress.Parse("10.0.0.5"), LinkType.Ethernet);

        SensorInterface[] snapshot = table.Snapshot();

        Assert.Equal([0u, 1u, 2u], snapshot.Select(entry => entry.Id));
        Assert.Equal(["10.0.0.9", "10.0.0.1", "10.0.0.5"], snapshot.Select(entry => entry.Name));
    }

    [Fact]
    public void RefusesToLoadATableWithAGapRatherThanShiftEveryInterface()
    {
        // Silently renumbering would make every existing segment attribute frames to the wrong sensor.
        File.WriteAllText(Path, """
            [
              { "Id": 0, "Address": "10.0.0.1", "LinkType": 1 },
              { "Id": 2, "Address": "10.0.0.2", "LinkType": 1 }
            ]
            """);

        var exception = Assert.Throws<InvalidOperationException>(() => new InterfaceTable(Path));
        Assert.Contains("positional", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesToStartOnACorruptTableRatherThanMisattributeExistingSegments()
    {
        File.WriteAllText(Path, "{ not json");

        Assert.Throws<InvalidOperationException>(() => new InterfaceTable(Path));
    }

    [Fact]
    public void DescriptionNamesTheSensorAndItsLinkType()
    {
        var table = new InterfaceTable(Path);
        table.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet);

        SensorInterface entry = table.Snapshot().Single();

        Assert.Equal("10.0.0.1", entry.Name);
        Assert.Contains("Ethernet", entry.Description, StringComparison.Ordinal);
    }
}
