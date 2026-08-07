using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Oko;
using Oko.Capture;
using Oko.Pcapng;

namespace Oko.Tests;

/// <summary>
/// Exercises ingest through to segment files on disk without touching a socket, so the pipeline can be
/// verified independently of the network. Segments are validated with the real Wireshark tools.
/// </summary>
public class CapturePipelineTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-pipeline-").FullName;

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task WritesEveryAppendedFrameIntoValidSegmentsAsync()
    {
        const int frames = 500;
        await using Pipeline pipeline = await Pipeline.StartAsync(_directory);

        uint sensor = pipeline.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
        for (int i = 0; i < frames; i++)
        {
            pipeline.Append(sensor, TestFrames.Udp(200, identification: (ushort)i));
        }

        await pipeline.StopAsync();

        string[] segments = pipeline.SegmentFiles();
        Assert.NotEmpty(segments);

        int total = 0;
        foreach (string segment in segments)
        {
            Wireshark.AssertFileIsValid(segment);
            total += Wireshark.ReadField(segment, "frame.number").Length;
        }

        Assert.Equal(frames, total);
    }

    [Fact]
    public async Task FlushesEnoughDataToProduceSeveralSegmentsAsync()
    {
        // FLUSH_BYTES is below BLOCK_BYTES in the test configuration, so each sealed block becomes its
        // own segment. This is what exercises the multi-segment read path in M3.
        await using Pipeline pipeline = await Pipeline.StartAsync(_directory);

        uint sensor = pipeline.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
        for (int i = 0; i < 4_000; i++)
        {
            pipeline.Append(sensor, TestFrames.Udp(300, identification: (ushort)i));
        }

        await pipeline.StopAsync();

        Assert.True(pipeline.SegmentFiles().Length >= 2, "expected more than one segment");
    }

    [Fact]
    public async Task PreservesFramePayloadsByteForByteAsync()
    {
        await using Pipeline pipeline = await Pipeline.StartAsync(_directory);

        uint sensor = pipeline.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
        for (int i = 0; i < 50; i++)
        {
            // ip.id gives each frame a distinguishable marker that survives into the capture file.
            pipeline.Append(sensor, TestFrames.Udp(120 + i, identification: (ushort)(1000 + i)));
        }

        await pipeline.StopAsync();

        List<string> identifications = [];
        List<string> lengths = [];
        foreach (string segment in pipeline.SegmentFiles())
        {
            identifications.AddRange(Wireshark.ReadField(segment, "ip.id"));
            lengths.AddRange(Wireshark.ReadField(segment, "frame.len"));
        }

        Assert.Equal(
            [.. Enumerable.Range(1000, 50).Select(id => "0x" + id.ToString("x4", CultureInfo.InvariantCulture))],
            identifications);
        Assert.Equal(
            [.. Enumerable.Range(0, 50).Select(i => (120 + i).ToString(CultureInfo.InvariantCulture))],
            lengths);
    }

    [Fact]
    public async Task AttributesFramesToTheRightSensorAcrossSegmentsAndRestartsAsync()
    {
        // The point of the stable, persisted interface table: an ID assigned before a restart must mean
        // the same sensor in segments written after it.
        await using (Pipeline first = await Pipeline.StartAsync(_directory))
        {
            uint sensorA = first.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
            for (int i = 0; i < 100; i++)
            {
                first.Append(sensorA, TestFrames.Udp(100));
            }

            await first.StopAsync();
        }

        await using (Pipeline second = await Pipeline.StartAsync(_directory))
        {
            // Re-resolving the original sensor must return its original ID, and a new sensor must
            // continue the sequence rather than reuse it.
            Assert.Equal(0u, second.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id);
            uint sensorB = second.Interfaces.Resolve(IPAddress.Parse("10.0.0.2"), LinkType.Ethernet).Id;
            Assert.Equal(1u, sensorB);

            for (int i = 0; i < 100; i++)
            {
                second.Append(sensorB, TestFrames.Udp(100));
            }

            await second.StopAsync();
        }

        // The first segment predates sensor B and so carries one IDB; the second carries both. Every
        // frame must still resolve to the sensor that produced it.
        var attributions = new List<string>();
        foreach (string segment in Pipeline.SegmentFilesIn(_directory))
        {
            Wireshark.AssertFileIsValid(segment);
            attributions.AddRange(Wireshark.ReadField(segment, "frame.interface_name"));
        }

        Assert.Equal(100, attributions.Count(name => name == "10.0.0.1"));
        Assert.Equal(100, attributions.Count(name => name == "10.0.0.2"));
    }

    [Fact]
    public async Task RecordsSegmentMetadataInTheSectionCommentAsync()
    {
        await using Pipeline pipeline = await Pipeline.StartAsync(_directory);

        uint sensor = pipeline.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;
        pipeline.Append(sensor, TestFrames.Udp(100));

        await pipeline.StopAsync();

        // capinfos surfaces the SHB comment, which is what makes a copied segment self-describing.
        var capinfos = Wireshark.Run("capinfos", pipeline.SegmentFiles().Single());

        Assert.Equal(0, capinfos.ExitCode);
        Assert.Contains("10.0.0.1", capinfos.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("Oko/", capinfos.StandardOutput, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AssignsContiguousSequenceNumbersWithNoGapsOrDuplicatesAsync()
    {
        await using Pipeline pipeline = await Pipeline.StartAsync(_directory);
        uint sensor = pipeline.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;

        var sequences = new List<ulong>();
        for (int i = 0; i < 1_000; i++)
        {
            sequences.Add(pipeline.Append(sensor, TestFrames.Udp(150)));
        }

        Assert.Equal([.. Enumerable.Range(1, 1_000).Select(value => (ulong)value)], sequences);
        await pipeline.StopAsync();
    }

    [Fact]
    public async Task InMemoryBlocksStayContiguousWhileSegmentsAreBeingWrittenAsync()
    {
        // The memory-to-disk handoff is the one genuinely racy part of the design: CompleteFlush adds a
        // segment and drops blocks under the same lock Snapshot uses. If that were wrong, a snapshot
        // taken mid-flush would show a gap or a duplicated block.
        await using Pipeline pipeline = await Pipeline.StartAsync(_directory);
        uint sensor = pipeline.Interfaces.Resolve(IPAddress.Parse("10.0.0.1"), LinkType.Ethernet).Id;

        int inspections = 0;
        for (int i = 0; i < 20_000; i++)
        {
            pipeline.Append(sensor, TestFrames.Udp(400));

            if (i % 100 == 0)
            {
                AssertSnapshotIsContiguous(pipeline.Store.Snapshot(DateTime.MinValue, DateTime.MaxValue));
                inspections++;
            }
        }

        Assert.True(inspections > 100, "expected many snapshots to be inspected");
        await pipeline.StopAsync();
    }

    private static void AssertSnapshotIsContiguous(CaptureSnapshot snapshot)
    {
        ulong? previousLast = null;

        foreach (CaptureBlock block in snapshot.SealedBlocks)
        {
            Assert.Equal((ulong)block.PacketCount, block.LastSequence - block.FirstSequence + 1);

            if (previousLast is { } last)
            {
                Assert.Equal(last + 1, block.FirstSequence);
            }

            previousLast = block.LastSequence;
        }

        if (!snapshot.ActiveBlock.IsEmpty)
        {
            if (previousLast is { } last)
            {
                Assert.Equal(last + 1, snapshot.ActiveBlock.FirstSequence);
            }

            Assert.Equal(snapshot.LastSequence, snapshot.ActiveBlock.LastSequence);
        }
    }

    /// <summary>Drives <see cref="CaptureStore"/> and <see cref="SegmentWriter"/> without a socket.</summary>
    private sealed class Pipeline : IAsyncDisposable
    {
        private readonly SegmentWriter _writer;
        private readonly MonotonicClock _clock = new();
        private bool _stopped;

        private Pipeline(OkoOptions options, CaptureStore store, InterfaceTable interfaces, SegmentWriter writer)
        {
            Options = options;
            Store = store;
            Interfaces = interfaces;
            _writer = writer;
        }

        public OkoOptions Options { get; }

        public CaptureStore Store { get; }

        public InterfaceTable Interfaces { get; }

        public static async Task<Pipeline> StartAsync(string dataDirectory)
        {
            OkoOptions options = TestOptions.Create(dataDirectory);
            var interfaces = new InterfaceTable(options.InterfacesPath);
            var store = new CaptureStore(options, NullLogger<CaptureStore>.Instance);
            var writer = new SegmentWriter(options, store, interfaces, NullLogger<SegmentWriter>.Instance);

            await writer.StartAsync(CancellationToken.None);
            return new Pipeline(options, store, interfaces, writer);
        }

        public ulong Append(uint interfaceId, byte[] frame) =>
            Store.Append(interfaceId, _clock.NextTimestampNanoseconds(), frame, (uint)frame.Length);

        /// <summary>Stops the writer, which seals the active block and flushes everything still pending.</summary>
        public async Task StopAsync()
        {
            if (_stopped)
            {
                return;
            }

            _stopped = true;
            await _writer.StopAsync(CancellationToken.None);
        }

        public string[] SegmentFiles() => SegmentFilesIn(Options.DataDirectory);

        public static string[] SegmentFilesIn(string dataDirectory)
        {
            string segments = Path.Combine(dataDirectory, "segments");
            return Directory.Exists(segments)
                ? [.. Directory.EnumerateFiles(segments, "*.pcapng", SearchOption.AllDirectories).Order(StringComparer.Ordinal)]
                : [];
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
            _writer.Dispose();
        }
    }
}
