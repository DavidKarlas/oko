using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Oko;
using Oko.Capture;
using Oko.Pcapng;

namespace Oko.Tests;

/// <summary>
/// Regression tests for two bugs that only appeared when the real service was run: a partially-filled
/// block never reaching disk, and the version missing from every capture file.
/// </summary>
public class IdleFlushTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-idle-").FullName;

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void UserApplicationIncludesTheVersion()
    {
        // Version and UserApplication are both static properties; with UserApplication declared first it
        // read Version before it was initialised and every capture recorded a bare "Oko/".
        Assert.NotEqual("Oko/", OkoVersion.UserApplication);
        Assert.StartsWith("Oko/", OkoVersion.UserApplication, StringComparison.Ordinal);
        Assert.Contains(OkoVersion.Version, OkoVersion.UserApplication, StringComparison.Ordinal);
        Assert.NotEmpty(OkoVersion.Version);
    }

    [Fact]
    public void SealActiveIfOlderThanLeavesRecentDataAlone()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);
        var clock = new MonotonicClock();

        store.Append(0, clock.NextTimestampNanoseconds(), TestFrames.Udp(100), 100);

        Assert.False(
            store.SealActiveIfOlderThan(TimeSpan.FromMinutes(1)),
            "a block holding fresh data should not be sealed early");
        Assert.Equal(0, store.GetMemoryStats().SealedBlocks);
    }

    [Fact]
    public void SealActiveIfOlderThanSealsStaleData()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var time = new FakeTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var clock = new MonotonicClock();

        store.Append(0, clock.NextTimestampNanoseconds(), TestFrames.Udp(100), 100);

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(store.SealActiveIfOlderThan(TimeSpan.FromSeconds(1)));
        Assert.Equal(1, store.GetMemoryStats().SealedBlocks);
        Assert.Equal(0, store.GetMemoryStats().ActiveBytes);
    }

    [Fact]
    public void SealActiveIfOlderThanIgnoresAnEmptyBlock()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);

        Assert.False(store.SealActiveIfOlderThan(TimeSpan.Zero));
        Assert.Equal(0, store.GetMemoryStats().SealedBlocks);
    }

    [Fact]
    public async Task WritesASegmentForATrickleOfTrafficWithoutWaitingForAFullBlockAsync()
    {
        // The originally shipped behaviour only started the flush timer once a block sealed, so a link
        // too slow to fill a 1 MB block kept everything in memory until shutdown — and lost it on a
        // crash. A handful of packets must reach disk on the flush interval alone.
        OkoOptions options = TestOptions.Create(
            _directory,
            ("FLUSH_INTERVAL", "00:00:01"),
            ("FLUSH_BYTES", "8388608")); // far above what this test writes

        var interfaces = new InterfaceTable(options.InterfacesPath);
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);
        var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        var clock = new MonotonicClock();

        await writer.StartAsync(CancellationToken.None);
        try
        {
            uint sensor = interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
            for (int i = 0; i < 5; i++)
            {
                store.Append(sensor, clock.NextTimestampNanoseconds(), TestFrames.Udp(120), 120);
            }

            string segments = Path.Combine(_directory, "segments");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            while (!Directory.Exists(segments) ||
                   !Directory.EnumerateFiles(segments, "*.pcapng", SearchOption.AllDirectories).Any())
            {
                timeout.Token.ThrowIfCancellationRequested();
                await Task.Delay(100, timeout.Token);
            }

            string written = Directory
                .EnumerateFiles(segments, "*.pcapng", SearchOption.AllDirectories)
                .Single();

            Wireshark.AssertFileIsValid(written);
            Assert.Equal(5, Wireshark.ReadField(written, "frame.number").Length);
        }
        finally
        {
            await writer.StopAsync(CancellationToken.None);
            writer.Dispose();
        }
    }
}
