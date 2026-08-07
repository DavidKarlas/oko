using Microsoft.Extensions.Logging.Abstractions;
using Oko.Capture;

namespace Oko.Tests;

public class SegmentIndexTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-segments-").FullName;

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void BuiltPathsRoundTripThroughRebuild()
    {
        var start = new DateTime(2026, 7, 29, 14, 3, 12, 123, DateTimeKind.Utc);
        var end = new DateTime(2026, 7, 29, 14, 9, 55, 456, DateTimeKind.Utc);

        string path = SegmentIndex.BuildPath(_directory, start, end, 42);
        WriteSegmentFile(path, bytes: 1024);

        SegmentRef segment = SegmentIndex.Rebuild(_directory, NullLogger.Instance).Snapshot().Single();

        Assert.Equal(start, segment.StartUtc);
        Assert.Equal(end, segment.EndUtc);
        Assert.Equal(42, segment.Number);
        Assert.Equal(1024, segment.SizeBytes);
    }

    [Fact]
    public void PathsAreShardedByDayAndSortLexicographically()
    {
        var early = new DateTime(2026, 7, 29, 1, 0, 0, DateTimeKind.Utc);
        var late = new DateTime(2026, 7, 29, 23, 0, 0, DateTimeKind.Utc);

        string earlyPath = SegmentIndex.BuildPath(_directory, early, early, 1);
        string latePath = SegmentIndex.BuildPath(_directory, late, late, 2);

        Assert.Equal("2026-07-29", Path.GetFileName(Path.GetDirectoryName(earlyPath)));
        Assert.True(
            string.CompareOrdinal(Path.GetFileName(earlyPath), Path.GetFileName(latePath)) < 0,
            "file names must sort chronologically");
    }

    [Fact]
    public void RangeReturnsOverlappingSegmentsNotOnlyContainedOnes()
    {
        var index = new SegmentIndex();
        SegmentRef spanning = Segment("14:00:00", "14:10:00", number: 1);
        index.Add(spanning);
        index.Add(Segment("14:10:00", "14:20:00", number: 2));
        index.Add(Segment("15:00:00", "15:10:00", number: 3));

        // A ten-second query inside the first segment must still find it.
        SegmentRef[] matched = index.Range(At("14:05:00"), At("14:05:10"));

        Assert.Equal([spanning], matched);
    }

    [Fact]
    public void RangeReturnsEverySegmentTouchingTheWindowOldestFirst()
    {
        var index = new SegmentIndex();
        index.Add(Segment("15:00:00", "15:10:00", number: 3));
        index.Add(Segment("14:00:00", "14:10:00", number: 1));
        index.Add(Segment("14:10:00", "14:20:00", number: 2));

        SegmentRef[] matched = index.Range(At("14:05:00"), At("15:05:00"));

        Assert.Equal([1L, 2L, 3L], matched.Select(segment => segment.Number));
    }

    [Fact]
    public void RangeExcludesSegmentsEntirelyOutsideTheWindow()
    {
        var index = new SegmentIndex();
        index.Add(Segment("14:00:00", "14:10:00", number: 1));

        Assert.Empty(index.Range(At("15:00:00"), At("16:00:00")));
        Assert.Empty(index.Range(At("12:00:00"), At("13:00:00")));
    }

    [Fact]
    public void TracksTotalBytesAndTheOldestAndNewestSegments()
    {
        var index = new SegmentIndex();
        SegmentRef oldest = Segment("14:00:00", "14:10:00", number: 1, bytes: 100);
        SegmentRef newest = Segment("15:00:00", "15:10:00", number: 2, bytes: 250);

        index.Add(newest);
        index.Add(oldest);

        Assert.Equal(350, index.TotalBytes);
        Assert.Equal(oldest, index.Oldest);
        Assert.Equal(newest, index.Newest);

        index.Remove(oldest);

        Assert.Equal(250, index.TotalBytes);
        Assert.Equal(newest, index.Oldest);
    }

    [Fact]
    public void RebuildDiscardsPartialSegmentsLeftByAnUncleanShutdown()
    {
        string complete = SegmentIndex.BuildPath(_directory, At("14:00:00"), At("14:10:00"), 1);
        WriteSegmentFile(complete, bytes: 512);

        string partial = SegmentIndex.ToTemporaryPath(
            SegmentIndex.BuildPath(_directory, At("14:10:00"), At("14:20:00"), 2));
        WriteSegmentFile(partial, bytes: 512);

        SegmentIndex index = SegmentIndex.Rebuild(_directory, NullLogger.Instance);

        Assert.Equal(1, index.Count);
        Assert.Equal(complete, index.Snapshot().Single().Path);
        Assert.False(File.Exists(partial), "a torn segment should be deleted, not indexed");
    }

    [Fact]
    public void RebuildIgnoresFilesThatAreNotOkoSegments()
    {
        WriteSegmentFile(Path.Combine(_directory, "notes.txt"), bytes: 10);
        WriteSegmentFile(Path.Combine(_directory, "capture.pcapng"), bytes: 10);
        WriteSegmentFile(Path.Combine(_directory, "20260729T140312123-nonsense-000001.pcapng"), bytes: 10);

        Assert.Equal(0, SegmentIndex.Rebuild(_directory, NullLogger.Instance).Count);
    }

    [Fact]
    public void RebuildRecoversTheHighestNumberSoNamesStayUnique()
    {
        WriteSegmentFile(SegmentIndex.BuildPath(_directory, At("14:00:00"), At("14:10:00"), 7), bytes: 10);
        WriteSegmentFile(SegmentIndex.BuildPath(_directory, At("14:10:00"), At("14:20:00"), 3), bytes: 10);

        Assert.Equal(7, SegmentIndex.Rebuild(_directory, NullLogger.Instance).HighestNumber);
    }

    private static DateTime At(string timeOfDay) =>
        DateTime.Parse($"2026-07-29T{timeOfDay}Z", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);

    private static SegmentRef Segment(string start, string end, long number, long bytes = 1024) =>
        new($"/segments/{number}.pcapng", At(start), At(end), bytes, number);

    private static void WriteSegmentFile(string path, int bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
    }
}
