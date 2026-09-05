using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Oko;
using Oko.Capture;
using Oko.Pcapng;

namespace Oko.Tests;

/// <summary>Checks persistence deadlines and shutdown independently of packet timestamps.</summary>
public class SegmentWriterTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-writer-").FullName;

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void ActiveBlockAgeStartsAtFirstArrivalAndSurvivesLaterAppends(int senderOffsetDays)
    {
        OkoOptions options = TestOptions.Create(_directory);
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        time.Advance(TimeSpan.FromHours(1)); // Allocating an empty block must not start its deadline.
        ulong timestamp = MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime.AddDays(senderOffsetDays));
        store.Append(0, timestamp, TestFrames.Udp(100), 100);
        time.UtcOffset = TimeSpan.FromDays(senderOffsetDays);
        Assert.False(store.SealActiveIfOlderThan(options.FlushInterval));

        time.Advance(TimeSpan.FromMilliseconds(999));
        store.Append(0, timestamp, TestFrames.Udp(120), 120);
        Assert.False(store.SealActiveIfOlderThan(options.FlushInterval));
        time.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(store.SealActiveIfOlderThan(options.FlushInterval));

        store.Append(0, timestamp, TestFrames.Udp(140), 140);
        Assert.False(store.SealActiveIfOlderThan(options.FlushInterval));
        Assert.Equal(2, Assert.Single(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).SealedBlocks).PacketCount);
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(1, false)]
    [InlineData(-1, true)]
    [InlineData(1, true)]
    public async Task WallClockChangesDoNotMoveTheFlushDeadlineAsync(int clockOffsetDays, bool sealEarly)
    {
        OkoOptions options = TestOptions.Create(_directory, ("FLUSH_BYTES", "8388608"));
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;

        await writer.StartAsync(CancellationToken.None);
        try
        {
            await time.WaitForTimerAsync();
            store.Append(sensor, MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime), TestFrames.Udp(100), 100);
            if (sealEarly)
            {
                store.SealActive();
                await time.WaitForTimerAsync();
            }

            time.UtcOffset = TimeSpan.FromDays(clockOffsetDays);
            time.Advance(options.FlushInterval);
            await WaitForSegmentAsync(store);
            Assert.Equal(0, store.GetMemoryStats().PendingFlushBytes);
        }
        finally
        {
            await writer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task EarlySealingAndLaterBlocksKeepTheFirstPacketsDeadlineAsync()
    {
        OkoOptions options = TestOptions.Create(_directory, ("FLUSH_BYTES", "8388608"));
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;

        await writer.StartAsync(CancellationToken.None);
        try
        {
            await time.WaitForTimerAsync();
            store.Append(sensor, MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime), TestFrames.Udp(100), 100);
            time.Advance(TimeSpan.FromMilliseconds(500));
            store.SealActive();
            await time.WaitForTimerAsync();
            time.Advance(TimeSpan.FromMilliseconds(250));
            store.Append(sensor, MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime), TestFrames.Udp(120), 120);
            store.SealActive();
            await time.WaitForTimerAsync();
            time.Advance(TimeSpan.FromMilliseconds(249));
            Assert.Equal(0, store.GetStorageStats().Segments);
            time.Advance(TimeSpan.FromMilliseconds(1));

            await WaitForSegmentAsync(store);
            string path = Assert.Single(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments).Path;
            Assert.Equal(["100", "120"], Wireshark.ReadField(path, "frame.len"));
        }
        finally
        {
            await writer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task FullBlocksFlushBySizeWithoutAdvancingTimeAsync()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;

        await writer.StartAsync(CancellationToken.None);
        try
        {
            for (int i = 0; i < 200; i++)
            {
                store.Append(sensor, MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime), TestFrames.Udp(1000), 1000);
            }

            await WaitForSegmentAsync(store);
            Assert.True(store.GetMemoryStats().ActiveBytes > 0);
        }
        finally
        {
            await writer.StopAsync(CancellationToken.None);
        }

        SegmentRef[] segments = store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments;
        Assert.Equal(200, segments.Sum(segment => Wireshark.ReadField(segment.Path, "frame.number").Length));
        Assert.Equal(new MemoryStats(0, 0, 0, 0), store.GetMemoryStats());
    }

    [Fact]
    public async Task StorageRecoveryRetriesOverdueBlocksWithoutAnotherFlushIntervalAsync()
    {
        OkoOptions options = TestOptions.Create(_directory, ("FLUSH_BYTES", "8388608"));
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;
        DateTime timestamp = time.GetUtcNow().UtcDateTime;
        string blockedDirectory = Path.GetDirectoryName(SegmentIndex.BuildPath(options.SegmentsDirectory, timestamp, timestamp, 1))!;
        File.WriteAllText(blockedDirectory, "A file prevents creating the segment directory.");

        await writer.StartAsync(CancellationToken.None);
        try
        {
            await time.WaitForTimerAsync();
            store.Append(sensor, MonotonicClock.ToNanoseconds(timestamp), TestFrames.Udp(100), 100);
            time.Advance(options.FlushInterval);
            await time.WaitForTimerAsync(); // Retry registered after the failed write.
            Assert.Equal(0, store.GetStorageStats().Segments);
            Assert.True(store.GetMemoryStats().PendingFlushBytes > 0);

            File.Delete(blockedDirectory);
            time.Advance(TimeSpan.FromSeconds(5));
            await WaitForSegmentAsync(store);
            string path = Assert.Single(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments).Path;
            Assert.Single(Wireshark.ReadField(path, "frame.number"));
            Assert.Equal(0, store.GetMemoryStats().PendingFlushBytes);
        }
        finally
        {
            if (File.Exists(blockedDirectory))
            {
                File.Delete(blockedDirectory);
            }

            await writer.StopAsync(CancellationToken.None);
        }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    public async Task QuietPacketReachesDiskAfterOneIntervalRegardlessOfSenderClockAsync(int senderOffsetDays)
    {
        OkoOptions options = TestOptions.Create(_directory, ("FLUSH_BYTES", "8388608"));
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;
        ulong timestamp = MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime.AddDays(senderOffsetDays));

        await writer.StartAsync(CancellationToken.None);
        try
        {
            // Wait for timer registration before advancing time; thread-pool scheduling cannot move
            // the test's first tick to a later instant. No real-time sleep stands in for FlushInterval.
            await time.WaitForTimerAsync();
            store.Append(sensor, timestamp, TestFrames.Udp(100), 100);
            time.Advance(options.FlushInterval);

            await WaitForSegmentAsync(store);
            string path = Assert.Single(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments).Path;
            Wireshark.AssertFileIsValid(path);
            Assert.Single(Wireshark.ReadField(path, "frame.number"));
            Assert.Equal(MonotonicClock.ToUtc(timestamp), store.GetStorageStats().OldestUtc);
            Assert.Equal(0, store.GetMemoryStats().PendingFlushBytes);
        }
        finally
        {
            await writer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task StopDrainsCapturesEvenWhenExecuteAsyncNeverStartsAsync()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;

        // BackgroundService schedules ExecuteAsync using a linked start/stop token. Cancelling it
        // before scheduling deterministically selects the same path as Stop winning the scheduling
        // race, without starving the process-wide thread pool and disrupting other tests.
        await writer.StartAsync(new CancellationToken(canceled: true));
        store.Append(sensor, MonotonicClock.ToNanoseconds(DateTime.UtcNow), TestFrames.Udp(100), 100);
        store.SealActive();
        store.Append(sensor, MonotonicClock.ToNanoseconds(DateTime.UtcNow), TestFrames.Udp(120), 120);

        await writer.StopAsync(CancellationToken.None);
        Assert.True(writer.ExecuteTask!.IsCanceled);

        string path = Assert.Single(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments).Path;
        Wireshark.AssertFileIsValid(path);
        Assert.Equal(["100", "120"], Wireshark.ReadField(path, "frame.len"));
        Assert.Equal(new MemoryStats(0, 0, 0, 0), store.GetMemoryStats());

        await writer.StopAsync(CancellationToken.None);
        Assert.Single(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments);
    }

    [Fact]
    public async Task TimedOutStopDoesNotDrainAlongsideAnInFlightWriteAsync()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var time = new WriterTimeProvider();
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance, time);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var logger = new PausedWriteLogger();
        using var writer = new SegmentWriter(options, store, interfaces, logger);
        uint sensor = interfaces.Resolve(IPAddress.Loopback, LinkType.Ethernet).Id;
        ulong timestamp = MonotonicClock.ToNanoseconds(time.GetUtcNow().UtcDateTime);

        await writer.StartAsync(CancellationToken.None);
        try
        {
            await time.WaitForTimerAsync();
            store.Append(sensor, timestamp, TestFrames.Udp(100), 100);
            time.Advance(options.FlushInterval);
            await logger.Written.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);

            // The first segment is committed but the worker has not cleared its pending list. A
            // second drain at this point would duplicate that packet and race the queue's reader.
            store.Append(sensor, timestamp, TestFrames.Udp(120), 120);
            store.SealActive();
            store.Append(sensor, timestamp, TestFrames.Udp(140), 140);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => writer.StopAsync(new CancellationToken(canceled: true)));
            Assert.False(writer.ExecuteTask!.IsCompleted);
            Task stopping = writer.StopAsync(CancellationToken.None);
            Assert.False(stopping.IsCompleted);
            logger.Release();
            await stopping.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);

            SegmentRef[] segments = store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments;
            Assert.Equal(["100", "120", "140"], segments.SelectMany(segment => Wireshark.ReadField(segment.Path, "frame.len")));
            Assert.Equal(new MemoryStats(0, 0, 0, 0), store.GetMemoryStats());
        }
        finally
        {
            logger.Release();
            await writer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task StoppingAnEmptyWriterDoesNotCreateASegmentAsync()
    {
        OkoOptions options = TestOptions.Create(_directory);
        var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);
        var interfaces = new InterfaceTable(options.InterfacesPath);
        using var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);
        await writer.StartAsync(CancellationToken.None);
        await writer.StopAsync(CancellationToken.None);
        await writer.StopAsync(CancellationToken.None);
        Assert.Empty(store.Snapshot(DateTime.MinValue, DateTime.MaxValue).Segments);
    }

    private static async Task WaitForSegmentAsync(CaptureStore store)
    {
        // This timeout only bounds asynchronous I/O and scheduling. The collector's clock remains
        // frozen at its deadline: starting a second flush interval cannot make this test pass.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (store.GetStorageStats().Segments == 0)
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    private sealed class WriterTimeProvider : TimeProvider
    {
        private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 5, 12, 0, 0, TimeSpan.Zero));
        private readonly Channel<bool> _timers = Channel.CreateUnbounded<bool>();

        public TimeSpan UtcOffset { get; set; }

        public override long TimestampFrequency => _time.TimestampFrequency;

        public override long GetTimestamp() => _time.GetTimestamp();

        public override DateTimeOffset GetUtcNow() => _time.GetUtcNow() + UtcOffset;

        public void Advance(TimeSpan elapsed) => _time.Advance(elapsed);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            ITimer timer = _time.CreateTimer(callback, state, dueTime, period);
            _timers.Writer.TryWrite(true);
            return timer;
        }

        public async Task WaitForTimerAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await _timers.Reader.ReadAsync(timeout.Token);
        }
    }

    private sealed class PausedWriteLogger : ILogger<SegmentWriter>, IDisposable
    {
        private readonly ManualResetEventSlim _release = new();

        public TaskCompletionSource Written { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (formatter(state, exception).StartsWith("Wrote ", StringComparison.Ordinal) && Written.TrySetResult())
            {
                if (!_release.Wait(TimeSpan.FromSeconds(10)))
                {
                    throw new TimeoutException("The test did not release the paused writer.");
                }
            }
        }

        public void Release() => _release.Set();

        public void Dispose() => _release.Dispose();
    }
}
