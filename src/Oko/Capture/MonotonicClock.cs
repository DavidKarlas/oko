namespace Oko.Capture;

/// <summary>
/// Wall-clock nanoseconds that never go backwards.
/// </summary>
/// <remarks>
/// TZSP carries no usable timestamp — the sensor's TAG_TIMESTAMP has an unspecified epoch — so Oko
/// stamps at receive time. An NTP step could otherwise move the clock backwards mid-capture, which
/// breaks Wireshark's time-delta columns and makes a segment's start/end range a lie. Clamping to
/// non-decreasing costs one comparison per packet.
/// </remarks>
internal sealed class MonotonicClock
{
    private static readonly long UnixEpochTicks = DateTime.UnixEpoch.Ticks;

    private long _last;

    /// <summary>
    /// Nanoseconds since the Unix epoch, never less than the previous result.
    /// </summary>
    /// <remarks>
    /// Not thread-safe by design: it is called only from the single receive loop, and adding
    /// interlocked access would cost more than it buys. <see cref="DateTime.UtcNow"/> has 100 ns
    /// granularity, which is finer than the packet rates Oko targets.
    /// </remarks>
    public ulong NextTimestampNanoseconds()
    {
        long nanoseconds = (DateTime.UtcNow.Ticks - UnixEpochTicks) * 100;

        if (nanoseconds < _last)
        {
            nanoseconds = _last;
        }

        _last = nanoseconds;
        return (ulong)nanoseconds;
    }

    /// <summary>Converts a pcapng nanosecond timestamp back to a <see cref="DateTime"/>.</summary>
    public static DateTime ToUtc(ulong timestampNanoseconds) =>
        new(UnixEpochTicks + (long)(timestampNanoseconds / 100), DateTimeKind.Utc);

    /// <summary>Converts a <see cref="DateTime"/> to the nanosecond scale used in EPB timestamps.</summary>
    public static ulong ToNanoseconds(DateTime utc) =>
        (ulong)((utc.ToUniversalTime().Ticks - UnixEpochTicks) * 100);
}
