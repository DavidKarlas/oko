namespace Oko.Capture;

internal sealed record WriterSnapshot(long Flushes, long Failures, long Bytes, double DurationSeconds,
    double LastSuccessTimestampSeconds, long ConsecutiveFailures);

/// <summary>Writer observations, kept separately from the capture data and sampled under one lock.</summary>
internal sealed class WriterMetrics
{
    private readonly Lock _gate = new();
    private WriterSnapshot _snapshot = new(0, 0, 0, 0, 0, 0);

    public WriterSnapshot Snapshot()
    {
        lock (_gate) { return _snapshot; }
    }

    public void RecordFailure()
    {
        lock (_gate)
        {
            _snapshot = _snapshot with
            {
                Failures = _snapshot.Failures + 1,
                ConsecutiveFailures = _snapshot.ConsecutiveFailures + 1,
            };
        }
    }

    public void RecordSuccess(long bytes, double durationSeconds)
    {
        lock (_gate)
        {
            _snapshot = _snapshot with
            {
                Flushes = _snapshot.Flushes + 1,
                Bytes = _snapshot.Bytes + bytes,
                DurationSeconds = _snapshot.DurationSeconds + durationSeconds,
                LastSuccessTimestampSeconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d,
                ConsecutiveFailures = 0,
            };
        }
    }
}
