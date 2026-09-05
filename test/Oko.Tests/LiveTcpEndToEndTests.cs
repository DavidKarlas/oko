using System.Buffers.Binary;

namespace Oko.Tests;

public sealed class LiveTcpEndToEndTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-live-tcp-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task ConcurrentTcpSendersReachHistoryAndLiveReadersWithValidMixedInterfaces()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory, ("OKO_LIVE_FLUSH_MS", "20"));
        DateTime timestamp = DateTime.UtcNow.AddSeconds(-1);
        await oko.PushPcapStreamAsync(PcapFile.Build(1, [(timestamp, TestFrames.Udp(64, 1))]));
        await oko.WaitForStatusAsync(status => status.FramesStored == 1);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var client = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        using HttpResponseMessage history = await client.GetAsync(
            new Uri($"{oko.BaseAddress}/{oko.Token}/last/1h/live"), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        using HttpResponseMessage live = await client.GetAsync(
            new Uri($"{oko.BaseAddress}/{oko.Token}/live"), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        history.EnsureSuccessStatusCode();
        live.EnsureSuccessStatusCode();

        string historyPath = Path.Combine(_directory, "history-live.pcapng");
        string livePath = Path.Combine(_directory, "live.pcapng");
        Task readHistory = ReadPacketsAsync(history, historyPath, 21, timeout.Token);
        Task readLive = ReadPacketsAsync(live, livePath, 20, timeout.Token);

        byte[] ethernet = PcapFile.Build(1, Enumerable.Range(100, 10)
            .Select(id => (timestamp, TestFrames.Udp(64, (ushort)id))));
        byte[] cooked = PcapFile.Build(276, Enumerable.Range(200, 10)
            .Select(id => (timestamp, PcapFile.LinuxSll2(TestFrames.Udp(64, (ushort)id)[14..]))));
        await Task.WhenAll(oko.PushPcapStreamAsync(ethernet), oko.PushPcapStreamAsync(cooked));
        await Task.WhenAll(readHistory, readLive);

        Wireshark.AssertFileIsValid(historyPath);
        Wireshark.AssertFileIsValid(livePath);
        int[] expected = [.. Enumerable.Range(100, 10), .. Enumerable.Range(200, 10)];
        Assert.Equal(new[] { 1 }.Concat(expected), ReadIds(historyPath));
        Assert.Equal(expected, ReadIds(livePath));
        Assert.Equal(2, Wireshark.ReadField(livePath, "frame.interface_id").Distinct().Count());
    }

    private static int[] ReadIds(string path) =>
        [.. Wireshark.ReadField(path, "ip.id").Select(value => Convert.ToInt32(value, 16)).Order()];

    private static async Task ReadPacketsAsync(
        HttpResponseMessage response, string path, int wantedPackets, CancellationToken cancellationToken)
    {
        await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using FileStream output = File.Create(path);
        var header = new byte[8];
        int packets = 0;
        while (packets < wantedPackets)
        {
            // Stop at a complete block boundary rather than cancelling an arbitrary stream copy,
            // which can itself truncate the test fixture and obscure an interface/packet regression.
            await input.ReadExactlyAsync(header, cancellationToken);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(header);
            int length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4)));
            Assert.InRange(length, 12, 1_000_000);
            var remainder = new byte[length - header.Length];
            await input.ReadExactlyAsync(remainder, cancellationToken);
            await output.WriteAsync(header, cancellationToken);
            await output.WriteAsync(remainder, cancellationToken);
            if (type == 6)
            {
                packets++;
            }
        }
    }
}
