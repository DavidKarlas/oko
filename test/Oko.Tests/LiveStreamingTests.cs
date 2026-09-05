using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Oko.Capture;
using Oko.Http;

namespace Oko.Tests;

public sealed class LiveStreamingTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-live-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData(false, 64)]
    [InlineData(true, 64)]
    [InlineData(false, 40_000)]
    [InlineData(true, 40_000)]
    public async Task HistoryAndLiveEmitEachPacketOnceAcrossAnOverlappingBatch(bool reversePublication, int frameLength)
    {
        var fixture = Create();
        SensorInterface sensor = fixture.Interfaces.Resolve(IPAddress.Loopback, 1);
        using LiveSubscription subscription = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        DateTime timestamp = DateTime.UtcNow.AddSeconds(-1);
        byte[] first = TestFrames.Udp(frameLength, 1);
        byte[] second = TestFrames.Udp(frameLength, 2);
        ulong time = MonotonicClock.ToNanoseconds(timestamp);
        ulong firstSequence = fixture.Store.Append(sensor.Id, time, first, (uint)first.Length);

        if (!reversePublication)
        {
            fixture.Hub.Publish(sensor.Id, time, first, (uint)first.Length, firstSequence);
        }

        var window = new CaptureEndpoints.TimeWindow(timestamp.AddMinutes(-1), timestamp.AddMinutes(1), null);
        CaptureSnapshot history = fixture.Store.Snapshot(window.FromUtc, window.ToUtc);
        ulong secondSequence = fixture.Store.Append(sensor.Id, time, second, (uint)second.Length);
        fixture.Hub.Publish(sensor.Id, time, second, (uint)second.Length, secondSequence);

        if (reversePublication)
        {
            fixture.Hub.Publish(sensor.Id, time, first, (uint)first.Length, firstSequence);
        }

        fixture.Hub.FlushPending();
        subscription.Dispose();
        byte[] capture = await ReadHistoryAndLiveAsync(fixture, subscription, history, window);

        Assert.Equal(new ushort[] { 1, 2 }, PacketIds(capture));
    }

    [Fact]
    public async Task SnapshotPacketsOutsideTheHistoryTimeWindowStillArriveLive()
    {
        var fixture = Create();
        SensorInterface sensor = fixture.Interfaces.Resolve(IPAddress.Loopback, 1);
        using LiveSubscription subscription = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        DateTime now = DateTime.UtcNow;
        byte[] frame = TestFrames.Udp(64, 7);
        ulong timestamp = MonotonicClock.ToNanoseconds(now.AddSeconds(1));
        ulong sequence = fixture.Store.Append(sensor.Id, timestamp, frame, (uint)frame.Length);
        fixture.Hub.Publish(sensor.Id, timestamp, frame, (uint)frame.Length, sequence);
        var window = new CaptureEndpoints.TimeWindow(now.AddMinutes(-1), now, null);
        CaptureSnapshot history = fixture.Store.Snapshot(window.FromUtc, window.ToUtc);
        fixture.Hub.FlushPending();
        subscription.Dispose();

        byte[] capture = await ReadHistoryAndLiveAsync(fixture, subscription, history, window);

        Assert.Equal(new ushort[] { 7 }, PacketIds(capture));
    }

    [Fact]
    public async Task JoiningSubscriberDoesNotSuppressNewInterfacesForExistingReaders()
    {
        var fixture = Create();
        fixture.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), 1);
        using LiveSubscription first = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        SensorInterface added = fixture.Interfaces.Resolve(IPAddress.Parse("10.0.0.2"), 1);
        using LiveSubscription second = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        byte[] frame = TestFrames.Udp(64, 9);
        fixture.Hub.Publish(added.Id, MonotonicClock.ToNanoseconds(DateTime.UtcNow), frame, (uint)frame.Length, 1);
        fixture.Hub.FlushPending();
        first.Dispose();
        second.Dispose();

        foreach (LiveSubscription reader in new[] { first, second })
        {
            using var output = new MemoryStream();
            output.Write(reader.Preamble);
            await foreach (LiveBatch batch in reader.Batches.ReadAllAsync(TestContext.Current.CancellationToken))
            {
                output.Write(batch.Bytes);
            }

            Assert.Equal(new ushort[] { 9 }, PacketIds(output.ToArray()));
        }
    }

    [Fact]
    public void QueueOverflowIsCountedAndDetachesOnlyTheSlowSubscriber()
    {
        var fixture = Create();
        SensorInterface sensor = fixture.Interfaces.Resolve(IPAddress.Loopback, 1);
        using LiveSubscription slow = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        using LiveSubscription fast = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        byte[] frame = TestFrames.Udp(64);

        for (ulong sequence = 1; sequence <= 257; sequence++)
        {
            fixture.Hub.Publish(sensor.Id, 1, frame, (uint)frame.Length, sequence);
            fixture.Hub.FlushPending();
            Assert.True(fast.Batches.TryRead(out _));
        }

        Assert.Equal(1, slow.DroppedBatches);
        Assert.Equal(1, fixture.Hub.DroppedBatches);
        Assert.Equal(0, fast.DroppedBatches);
        Assert.Equal(1, fixture.Hub.SubscriberCount);
    }

    [Fact]
    public async Task HistoryAndLiveKeepSeparateInterfaceTablesWithMixedLinkTypes()
    {
        var fixture = Create();
        fixture.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), 1);
        using LiveSubscription subscription = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        DateTime now = DateTime.UtcNow.AddSeconds(-1);
        ulong timestamp = MonotonicClock.ToNanoseconds(now);
        SensorInterface second = fixture.Interfaces.Resolve(IPAddress.Parse("10.0.0.2"), 1);
        byte[] historicalFrame = TestFrames.Udp(64, 11);
        ulong sequence = fixture.Store.Append(second.Id, timestamp, historicalFrame, (uint)historicalFrame.Length);
        fixture.Hub.Publish(second.Id, timestamp, historicalFrame, (uint)historicalFrame.Length, sequence);
        var window = new CaptureEndpoints.TimeWindow(now.AddMinutes(-1), now.AddMinutes(1), null);
        CaptureSnapshot history = fixture.Store.Snapshot(window.FromUtc, window.ToUtc);

        SensorInterface third = fixture.Interfaces.Resolve(IPAddress.Parse("10.0.0.3"), 276);
        byte[] liveFrame = PcapFile.LinuxSll2(TestFrames.Udp(64, 12)[14..]);
        sequence = fixture.Store.Append(third.Id, timestamp, liveFrame, (uint)liveFrame.Length);
        fixture.Hub.Publish(third.Id, timestamp, liveFrame, (uint)liveFrame.Length, sequence);
        fixture.Hub.FlushPending();
        subscription.Dispose();

        byte[] capture = await ReadHistoryAndLiveAsync(fixture, subscription, history, window);
        string path = Path.Combine(_directory, "mixed-live.pcapng");
        await File.WriteAllBytesAsync(path, capture, TestContext.Current.CancellationToken);
        Wireshark.AssertFileIsValid(path);
        Assert.Equal(new[] { "10.0.0.2", "10.0.0.3" }, Wireshark.ReadField(path, "frame.interface_name"));
        Assert.Equal(new[] { "0x000b", "0x000c" }, Wireshark.ReadField(path, "ip.id"));
    }

    [Fact]
    public async Task LiveOnlyKeepsPacketsReceivedBetweenSubscriptionAndSnapshot()
    {
        var fixture = Create();
        SensorInterface sensor = fixture.Interfaces.Resolve(IPAddress.Loopback, 1);
        DateTime now = DateTime.UtcNow;
        ulong timestamp = MonotonicClock.ToNanoseconds(now);
        byte[] oldFrame = TestFrames.Udp(64, 1);
        fixture.Store.Append(sensor.Id, timestamp, oldFrame, (uint)oldFrame.Length);
        using LiveSubscription subscription = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        byte[] newFrame = TestFrames.Udp(64, 2);
        ulong sequence = fixture.Store.Append(sensor.Id, timestamp, newFrame, (uint)newFrame.Length);
        fixture.Hub.Publish(sensor.Id, timestamp, newFrame, (uint)newFrame.Length, sequence);
        var window = new CaptureEndpoints.TimeWindow(now, now, null, IncludeHistory: false);
        CaptureSnapshot history = fixture.Store.Snapshot(now, now);
        fixture.Hub.FlushPending();
        subscription.Dispose();

        byte[] capture = await ReadHistoryAndLiveAsync(fixture, subscription, history, window);

        Assert.Equal(new ushort[] { 2 }, PacketIds(capture));
    }

    [Fact]
    public async Task OverflowAbortsTheHttpResponseInsteadOfEndingSuccessfully()
    {
        var fixture = Create();
        SensorInterface sensor = fixture.Interfaces.Resolve(IPAddress.Loopback, 1);
        using LiveSubscription subscription = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        byte[] frame = TestFrames.Udp(64);
        for (ulong sequence = 1; sequence <= 257; sequence++)
        {
            fixture.Hub.Publish(sensor.Id, 1, frame, (uint)frame.Length, sequence);
            fixture.Hub.FlushPending();
        }

        var window = new CaptureEndpoints.TimeWindow(DateTime.UtcNow, DateTime.UtcNow, null, IncludeHistory: false);
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        await using WebApplication app = builder.Build();
        app.MapGet("/capture", async context =>
        {
            context.Response.ContentType = "application/x-pcapng";
            await fixture.Service.FollowAsync(context, context.Response.BodyWriter, subscription, 0, window,
                context.RequestAborted);
        });
        await app.StartAsync(TestContext.Current.CancellationToken);

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetByteArrayAsync(
            new Uri(app.Urls.Single() + "/capture"), TestContext.Current.CancellationToken));
        await app.StopAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, subscription.DroppedBatches);
        Assert.Equal(0, fixture.Hub.SubscriberCount);
    }

    [Fact]
    public void NormalDisconnectDoesNotCountAsOverflowAndFreesTheSubscriberSlot()
    {
        var fixture = Create(maxSubscribers: 1);
        SensorInterface sensor = fixture.Interfaces.Resolve(IPAddress.Loopback, 1);
        using LiveSubscription first = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        Assert.Null(fixture.Hub.TrySubscribe());
        first.Dispose();
        using LiveSubscription replacement = Assert.IsType<LiveSubscription>(fixture.Hub.TrySubscribe());
        byte[] frame = TestFrames.Udp(64);
        fixture.Hub.Publish(sensor.Id, 1, frame, (uint)frame.Length, 1);
        fixture.Hub.FlushPending();

        Assert.True(replacement.Batches.TryRead(out _));
        Assert.Equal(0, fixture.Hub.DroppedBatches);
        Assert.Equal(0, first.DroppedBatches);
    }

    private Fixture Create(int maxSubscribers = 8)
    {
        var options = TestOptions.Create(_directory,
            ("LIVE_MAX_SUBSCRIBERS", maxSubscribers.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        var interfaces = new InterfaceTable(options.InterfacesPath);
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);
        var hub = new LiveHub(options, interfaces, NullLogger<LiveHub>.Instance);
        var writer = new PcapngResponseWriter(options, interfaces, NullLogger<PcapngResponseWriter>.Instance);
        var service = new CaptureEndpoints.CaptureService(store, writer, hub,
            NullLogger<CaptureEndpoints.CaptureService>.Instance);
        return new Fixture(interfaces, store, hub, writer, service);
    }

    private static async Task<byte[]> ReadHistoryAndLiveAsync(
        Fixture fixture, LiveSubscription subscription, CaptureSnapshot history, CaptureEndpoints.TimeWindow window)
    {
        using var stream = new MemoryStream();
        PipeWriter output = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
        if (window.IncludeHistory)
        {
            fixture.Writer.WritePreamble(output, "regression test");
            await fixture.Writer.WriteSnapshotAsync(output, history, window.FromUtc, window.ToUtc,
                TestContext.Current.CancellationToken);
        }
        await fixture.Service.FollowAsync(new DefaultHttpContext(), output, subscription, history.LastSequence,
            window, TestContext.Current.CancellationToken);
        await output.CompleteAsync();
        return stream.ToArray();
    }

    private static ushort[] PacketIds(byte[] capture)
    {
        var ids = new List<ushort>();
        int interfaces = 0;
        for (int offset = 0; offset < capture.Length;)
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(capture.AsSpan(offset));
            int length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(capture.AsSpan(offset + 4)));
            Assert.InRange(length, 12, capture.Length - offset);
            if (type == 0x0a0d0d0a)
            {
                interfaces = 0;
            }
            else if (type == 1)
            {
                interfaces++;
            }
            else if (type == 6)
            {
                uint sensor = BinaryPrimitives.ReadUInt32LittleEndian(capture.AsSpan(offset + 8));
                Assert.True(sensor < interfaces, $"Packet references undeclared interface {sensor}; known count {interfaces}.");
                ids.Add(BinaryPrimitives.ReadUInt16BigEndian(capture.AsSpan(offset + 28 + 14 + 4)));
            }

            offset += length;
        }

        return [.. ids];
    }

    private sealed record Fixture(InterfaceTable Interfaces, CaptureStore Store, LiveHub Hub,
        PcapngResponseWriter Writer, CaptureEndpoints.CaptureService Service);

}
