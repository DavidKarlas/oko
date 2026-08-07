using System.Globalization;

namespace Oko.Capture;

/// <summary>One segment file on disk. Everything here is derived from the file name.</summary>
internal sealed record SegmentRef(string Path, DateTime StartUtc, DateTime EndUtc, long SizeBytes, long Number);

/// <summary>
/// The set of segment files, ordered by start time.
/// </summary>
/// <remarks>
/// <para>
/// The index is derived entirely from file names, so there is no separate index file that could drift
/// out of sync with the data or need repairing after a crash — <see cref="Rebuild"/> just globs the
/// directory.
/// </para>
/// <para>
/// Not thread-safe: <see cref="CaptureStore"/> owns it and guards every access with the same lock it
/// uses for the in-memory blocks, which is what makes a reader's view of "on disk plus in memory"
/// consistent.
/// </para>
/// </remarks>
internal sealed class SegmentIndex
{
    private const string TimestampFormat = "yyyyMMdd'T'HHmmssfff";
    private const string Extension = ".pcapng";
    private const string TemporaryExtension = ".pcapng.tmp";

    /// <summary>Sorted by <see cref="SegmentRef.StartUtc"/>.</summary>
    private readonly List<SegmentRef> _segments = [];

    public int Count => _segments.Count;

    public long TotalBytes { get; private set; }

    public long HighestNumber { get; private set; }

    public SegmentRef? Oldest => _segments.Count > 0 ? _segments[0] : null;

    public SegmentRef? Newest => _segments.Count > 0 ? _segments[^1] : null;

    public void Add(SegmentRef segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        int position = _segments.FindLastIndex(existing => existing.StartUtc <= segment.StartUtc) + 1;
        _segments.Insert(position, segment);
        TotalBytes += segment.SizeBytes;
        HighestNumber = Math.Max(HighestNumber, segment.Number);
    }

    public void Remove(SegmentRef segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        if (_segments.Remove(segment))
        {
            TotalBytes -= segment.SizeBytes;
        }
    }

    public SegmentRef[] Snapshot() => [.. _segments];

    /// <summary>
    /// Segments whose time range overlaps [<paramref name="fromUtc"/>, <paramref name="toUtc"/>],
    /// oldest first. Overlap rather than containment: a query for a 10-second window must still return
    /// the 8 MB segment that happens to span it.
    /// </summary>
    public SegmentRef[] Range(DateTime fromUtc, DateTime toUtc) =>
        [.. _segments.Where(segment => segment.StartUtc <= toUtc && segment.EndUtc >= fromUtc)];

    /// <summary>
    /// Builds the index by scanning <paramref name="segmentsDirectory"/>, discarding any <c>.tmp</c>
    /// files left behind by a crash. A torn segment is at most one flush of data, and recovering it
    /// is not worth the code it would take.
    /// </summary>
    public static SegmentIndex Rebuild(string segmentsDirectory, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        var index = new SegmentIndex();
        Directory.CreateDirectory(segmentsDirectory);

        foreach (string path in Directory.EnumerateFiles(segmentsDirectory, "*" + TemporaryExtension, SearchOption.AllDirectories))
        {
            logger.LogWarning("Discarding incomplete segment {Path} left behind by an unclean shutdown.", path);
            TryDelete(path, logger);
        }

        int unparseable = 0;
        foreach (string path in Directory.EnumerateFiles(segmentsDirectory, "*" + Extension, SearchOption.AllDirectories))
        {
            if (TryParseFileName(path, out SegmentRef? segment))
            {
                index.Add(segment);
            }
            else
            {
                unparseable++;
            }
        }

        if (unparseable > 0)
        {
            logger.LogWarning(
                "Ignored {Count} file(s) under {Directory} whose names do not match Oko's segment format.",
                unparseable,
                segmentsDirectory);
        }

        logger.LogInformation(
            "Segment index rebuilt: {Count} segment(s), {Bytes} bytes, covering {Oldest:o} to {Newest:o}.",
            index.Count,
            index.TotalBytes,
            index.Oldest?.StartUtc,
            index.Newest?.EndUtc);

        return index;
    }

    /// <summary>
    /// Composes the path for a new segment. The name carries the full time range so the index needs
    /// nothing else; the number only keeps names unique when two segments share a millisecond.
    /// </summary>
    public static string BuildPath(string segmentsDirectory, DateTime startUtc, DateTime endUtc, long number)
    {
        string day = startUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        string name = string.Create(
            CultureInfo.InvariantCulture,
            $"{startUtc.ToString(TimestampFormat, CultureInfo.InvariantCulture)}-{endUtc.ToString(TimestampFormat, CultureInfo.InvariantCulture)}-{number:D6}{Extension}");

        return Path.Combine(segmentsDirectory, day, name);
    }

    public static string ToTemporaryPath(string path) => path + ".tmp";

    private static bool TryParseFileName(string path, out SegmentRef segment)
    {
        segment = null!;

        string name = Path.GetFileName(path);
        if (!name.EndsWith(Extension, StringComparison.Ordinal))
        {
            return false;
        }

        string[] parts = name[..^Extension.Length].Split('-');
        if (parts.Length != 3)
        {
            return false;
        }

        if (!TryParseTimestamp(parts[0], out DateTime start) ||
            !TryParseTimestamp(parts[1], out DateTime end) ||
            !long.TryParse(parts[2], CultureInfo.InvariantCulture, out long number))
        {
            return false;
        }

        long size;
        try
        {
            size = new FileInfo(path).Length;
        }
        catch (IOException)
        {
            return false;
        }

        segment = new SegmentRef(path, start, end, size, number);
        return true;
    }

    private static bool TryParseTimestamp(string value, out DateTime utc) =>
        DateTime.TryParseExact(
            value,
            TimestampFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out utc);

    private static void TryDelete(string path, ILogger logger)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException exception)
        {
            logger.LogWarning(exception, "Could not delete {Path}.", path);
        }
    }
}
