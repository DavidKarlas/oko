using System.Globalization;
using Oko.Pcapng;

namespace Oko.Tests;

/// <summary>
/// End-to-end coverage of the pcap-over-TCP ingest, which is how a Linux VM feeds Oko with plain
/// <c>tcpdump | socat</c> and no custom software.
/// </summary>
[Collection(nameof(ServiceEndToEndTests))]
public class PcapTcpIngestTests : IDisposable
{
    private static readonly DateTime BaseTime = new(2026, 8, 7, 12, 0, 0, DateTimeKind.Utc);

    private readonly string _directory = Directory.CreateTempSubdirectory("oko-pcaptcp-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A killed service may still hold a handle.
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task AcceptsAClassicPcapStreamAndServesItBackAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        byte[] stream = PcapFile.Build(
            LinkType.Ethernet,
            [.. Enumerable.Range(0, 300).Select(i =>
                (BaseTime.AddMilliseconds(i), TestFrames.Udp(200, (ushort)i)))]);

        await oko.PushPcapStreamAsync(stream);
        StatusView status = await oko.WaitForQuietAsync();

        Assert.Equal(300, status.FramesStored);

        string capture = await oko.DownloadCaptureAsync(
            $"{oko.Token}/from/{Stamp(BaseTime.AddMinutes(-1))}/to/{Stamp(BaseTime.AddMinutes(10))}",
            "tcp-ingest.pcapng");

        Wireshark.AssertFileIsValid(capture);
        Assert.Equal(
            [.. Enumerable.Range(0, 300)],
            Wireshark.ReadField(capture, "ip.id").Select(id => Convert.ToInt32(id, 16)));
    }

    [Fact]
    public async Task KeepsTheTimestampsTheCapturingHostRecordedAsync()
    {
        // Capture-time stamps from the sending kernel are more accurate than arrival time, and are what
        // make a range query mean "when the packet was on the wire".
        await using OkoService oko = await OkoService.StartAsync(_directory);

        DateTime when = BaseTime.AddTicks(9_876_543);
        byte[] stream = PcapFile.Build(
            LinkType.Ethernet,
            [(when, TestFrames.Udp(120))],
            nanoseconds: true);

        await oko.PushPcapStreamAsync(stream);
        await oko.WaitForQuietAsync();

        string capture = await oko.DownloadCaptureAsync(
            $"{oko.Token}/from/{Stamp(BaseTime.AddMinutes(-1))}/to/{Stamp(BaseTime.AddMinutes(10))}",
            "timestamps.pcapng");

        string epoch = Wireshark.ReadField(capture, "frame.time_epoch").Single();

        // Integer arithmetic on purpose: computing this in double loses the last few nanoseconds and
        // would make the test disagree with a correct result.
        long ticks = (when - DateTime.UnixEpoch).Ticks;
        string expected = string.Create(
            CultureInfo.InvariantCulture,
            $"{ticks / TimeSpan.TicksPerSecond}.{ticks % TimeSpan.TicksPerSecond * 100:D9}");

        // Not arrival time: the recorded stamp is the one the sender captured with, in 2026-08-07.
        Assert.Equal(expected, epoch);
    }

    [Fact]
    public async Task AcceptsLinuxCookedV2FromTcpdumpAnyAsync()
    {
        // 'tcpdump -i any' is the obvious command to run on a VM and produces LINKTYPE_LINUX_SLL2 (276),
        // which TZSP cannot carry at all. This is the main reason the TCP path exists.
        await using OkoService oko = await OkoService.StartAsync(_directory);

        byte[] stream = PcapFile.Build(
            LinkType.LinuxSll2,
            [.. Enumerable.Range(0, 50).Select(i =>
                (BaseTime.AddMilliseconds(i), PcapFile.LinuxSll2(PcapFile.Ipv4UdpPayload(200, (ushort)i))))]);

        await oko.PushPcapStreamAsync(stream);
        StatusView status = await oko.WaitForQuietAsync();

        Assert.Equal(50, status.FramesStored);

        string capture = await oko.DownloadCaptureAsync(
            $"{oko.Token}/from/{Stamp(BaseTime.AddMinutes(-1))}/to/{Stamp(BaseTime.AddMinutes(10))}",
            "sll2.pcapng");

        // The whole point: Wireshark must dissect these as Linux cooked v2 and still find the IP layer.
        Wireshark.AssertFileIsValid(capture);
        Assert.Equal("Linux cooked-mode capture v2", Wireshark.Run("capinfos", capture)
            .StandardOutput
            .Split('\n')
            .First(line => line.Contains("encapsulation", StringComparison.OrdinalIgnoreCase))
            .Split(':', 2)[1]
            .Trim());
        Assert.Equal(50, Wireshark.ReadField(capture, "ip.id").Length);
    }

    [Fact]
    public async Task GivesEachSenderItsOwnInterfaceEvenOnTheSameLinkTypeAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        // Both connections come from 127.0.0.1, so they share one interface. What must not happen is a
        // new interface per connection, which would grow the table without bound as senders reconnect.
        await oko.PushPcapStreamAsync(PcapFile.Build(
            LinkType.Ethernet,
            [(BaseTime, TestFrames.Udp(120, 1))]));
        await oko.WaitForQuietAsync();

        await oko.PushPcapStreamAsync(PcapFile.Build(
            LinkType.Ethernet,
            [(BaseTime.AddSeconds(1), TestFrames.Udp(120, 2))]));
        StatusView status = await oko.WaitForQuietAsync();

        Assert.Equal(["127.0.0.1"], status.SensorAddresses);
        Assert.Equal(2, status.FramesStored);
    }

    [Fact]
    public async Task SeparatesTheSameSenderIntoOneInterfacePerLinkTypeAsync()
    {
        // A host tapping both a real interface and 'any' produces two link types. They cannot share a
        // pcapng interface, because the IDB records exactly one link type.
        await using OkoService oko = await OkoService.StartAsync(_directory);

        await oko.PushPcapStreamAsync(PcapFile.Build(
            LinkType.Ethernet,
            [(BaseTime, TestFrames.Udp(120, 1))]));
        await oko.WaitForQuietAsync();

        await oko.PushPcapStreamAsync(PcapFile.Build(
            LinkType.LinuxSll2,
            [(BaseTime.AddSeconds(1), PcapFile.LinuxSll2(PcapFile.Ipv4UdpPayload(200, 2)))]));
        await oko.WaitForQuietAsync();

        string interfaces = await File.ReadAllTextAsync(
            Path.Combine(_directory, "interfaces.json"),
            TestContext.Current.CancellationToken);

        Assert.Contains("\"LinkType\": 1", interfaces, StringComparison.Ordinal);
        Assert.Contains("\"LinkType\": 276", interfaces, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RejectsAPcapngStreamWithoutAffectingTheServiceAsync()
    {
        // tshark and dumpcap default to pcapng, so this is the likeliest misconfiguration.
        await using OkoService oko = await OkoService.StartAsync(_directory);

        byte[] pcapng = [0x0A, 0x0D, 0x0D, 0x0A, .. new byte[64]];
        await oko.PushPcapStreamAsync(pcapng);

        StatusView status = await oko.WaitForStatusAsync(s => s.PcapStreamErrors >= 1);

        Assert.Equal(0, status.FramesStored);

        // The message must tell the operator how to fix it, and the service must still be usable.
        Assert.Contains("pcapng", oko.Output, StringComparison.Ordinal);
        Assert.Contains("-F pcap", oko.Output, StringComparison.Ordinal);

        await oko.PushPcapStreamAsync(PcapFile.Build(LinkType.Ethernet, [(BaseTime, TestFrames.Udp(120))]));
        Assert.Equal(1, (await oko.WaitForQuietAsync()).FramesStored);
    }

    [Fact]
    public async Task RejectsGarbageWithoutStoringAnythingAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        await oko.PushPcapStreamAsync(System.Text.Encoding.ASCII.GetBytes(
            "GET / HTTP/1.1\r\nHost: oko\r\nUser-Agent: confused\r\n\r\n"));

        StatusView status = await oko.WaitForStatusAsync(s => s.PcapStreamErrors >= 1);
        Assert.Equal(0, status.FramesStored);
    }

    [Fact]
    public async Task FlagsFramesAddressedToItsOwnIngestPortAsACaptureLoopAsync()
    {
        // The backstop for a hand-written pipeline whose filter fails to exclude its own stream. oko-tap
        // makes this impossible, but the failure is expensive enough to detect anyway.
        await using OkoService oko = await OkoService.StartAsync(_directory);

        byte[] stream = PcapFile.Build(
            LinkType.Ethernet,
            [.. Enumerable.Range(0, 10).Select(i =>
                (BaseTime.AddMilliseconds(i), TestFrames.Tcp(destinationPort: (ushort)oko.PcapTcpPort)))]);

        await oko.PushPcapStreamAsync(stream);
        StatusView status = await oko.WaitForStatusAsync(s => s.CaptureLoopSuspects >= 10);

        Assert.Equal(10, status.CaptureLoopSuspects);

        // Flagged, not dropped: traffic to that port from somewhere else is still real capture data.
        Assert.Equal(10, status.FramesStored);
    }

    [Fact]
    public async Task DoesNotFlagOrdinaryTrafficAsACaptureLoopAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        await oko.PushPcapStreamAsync(PcapFile.Build(
            LinkType.Ethernet,
            [.. Enumerable.Range(0, 20).Select(i => (BaseTime.AddMilliseconds(i), TestFrames.Udp(200, (ushort)i)))]));

        StatusView status = await oko.WaitForQuietAsync();

        Assert.Equal(20, status.FramesStored);
        Assert.Equal(0, status.CaptureLoopSuspects);
    }

    [Fact]
    public async Task ReportsASenderWhoseClockIsWrongInsteadOfSilentlyRewritingTimeAsync()
    {
        // Oko keeps the sender's timestamps, so a skewed clock makes range queries baffling. Surfacing it
        // is the honest fix; silently substituting arrival time would hide a real problem.
        await using OkoService oko = await OkoService.StartAsync(_directory);

        byte[] stream = PcapFile.Build(
            LinkType.Ethernet,
            [(DateTime.UtcNow.AddDays(-3), TestFrames.Udp(120))]);

        await oko.PushPcapStreamAsync(stream);
        StatusView status = await oko.WaitForStatusAsync(s => s.ClockSkewedSenders >= 1);

        Assert.Equal(1, status.ClockSkewedSenders);
        Assert.Contains("clock", oko.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CanBeDisabledEntirelyAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory, ("OKO_PCAP_TCP_PORT", "0"));

        StatusView status = await oko.ReadStatusAsync();
        Assert.Equal(0, status.PcapTcpPort);

        await Assert.ThrowsAnyAsync<Exception>(() => oko.PushPcapStreamAsync(
            PcapFile.Build(LinkType.Ethernet, [(BaseTime, TestFrames.Udp(120))])));
    }

    [Fact]
    public async Task ReportsBothIngestPortsInStatusAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        StatusView status = await oko.ReadStatusAsync();

        Assert.Equal(oko.UdpPort, status.UdpPort);
        Assert.Equal(oko.PcapTcpPort, status.PcapTcpPort);
    }

    private static string Stamp(DateTime utc) =>
        utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
