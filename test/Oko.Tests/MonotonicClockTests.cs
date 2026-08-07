using Oko.Capture;

namespace Oko.Tests;

public class MonotonicClockTests
{
    [Fact]
    public void NeverGoesBackwardsAcrossManyReads()
    {
        var clock = new MonotonicClock();
        ulong previous = clock.NextTimestampNanoseconds();

        for (int i = 0; i < 100_000; i++)
        {
            ulong current = clock.NextTimestampNanoseconds();
            Assert.True(current >= previous, $"timestamp went backwards at iteration {i}");
            previous = current;
        }
    }

    [Fact]
    public void ReportsPlausibleWallClockTime()
    {
        DateTime before = DateTime.UtcNow.AddSeconds(-1);
        ulong timestamp = new MonotonicClock().NextTimestampNanoseconds();
        DateTime after = DateTime.UtcNow.AddSeconds(1);

        DateTime observed = MonotonicClock.ToUtc(timestamp);

        Assert.InRange(observed, before, after);
    }

    [Fact]
    public void ConvertsBetweenNanosecondsAndDateTimeWithoutLosingTheHundredNanosecondTick()
    {
        // DateTime ticks are 100 ns, which is the real resolution limit of the wall clock here.
        var original = new DateTime(2026, 7, 29, 14, 3, 12, DateTimeKind.Utc).AddTicks(1234567);

        ulong nanoseconds = MonotonicClock.ToNanoseconds(original);

        Assert.Equal(original, MonotonicClock.ToUtc(nanoseconds));
    }

    [Fact]
    public void NanosecondScaleMatchesTheUnixEpoch()
    {
        Assert.Equal(0UL, MonotonicClock.ToNanoseconds(DateTime.UnixEpoch));
        Assert.Equal(
            1_000_000_000UL,
            MonotonicClock.ToNanoseconds(DateTime.UnixEpoch.AddSeconds(1)));
    }
}
