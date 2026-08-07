namespace Oko.Capture;

/// <summary>
/// Deletes the oldest segments once storage exceeds the configured size or age limit.
/// </summary>
/// <remarks>
/// Oko is meant to run unattended at a remote site, so unbounded growth is not an option: without
/// this, the volume fills and ingest starts failing at the worst possible moment.
/// </remarks>
internal sealed class RetentionService(
    OkoOptions options,
    CaptureStore store,
    ILogger<RetentionService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "Retention: at most {Bytes} bytes and {Duration} of history.",
            options.RetentionBytes,
            options.RetentionDuration);

        using var timer = new PeriodicTimer(Interval);

        do
        {
            Collect();
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    private void Collect()
    {
        SegmentRef[] evicted = store.EvictSegments(
            options.RetentionBytes,
            options.RetentionDuration,
            DateTime.UtcNow);

        if (evicted.Length == 0)
        {
            return;
        }

        long reclaimed = 0;
        foreach (SegmentRef segment in evicted)
        {
            try
            {
                File.Delete(segment.Path);
                reclaimed += segment.SizeBytes;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // The index has already dropped it, so it will be rediscovered on the next restart.
                logger.LogWarning(exception, "Could not delete expired segment {Path}.", segment.Path);
            }
        }

        logger.LogInformation(
            "Retention removed {Count} segment(s), reclaiming {Bytes} bytes.",
            evicted.Length,
            reclaimed);

        RemoveEmptyDayDirectories();
    }

    /// <summary>Day-sharded directories accumulate as empty shells once their segments are gone.</summary>
    private void RemoveEmptyDayDirectories()
    {
        foreach (string directory in Directory.EnumerateDirectories(options.SegmentsDirectory))
        {
            try
            {
                if (!Directory.EnumerateFileSystemEntries(directory).Any())
                {
                    Directory.Delete(directory);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                logger.LogDebug(exception, "Could not remove empty directory {Directory}.", directory);
            }
        }
    }
}
