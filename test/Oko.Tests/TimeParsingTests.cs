using Oko.Http;

namespace Oko.Tests;

public class TimeParsingTests
{
    private static readonly DateTime Now = new(2026, 7, 29, 14, 3, 12, DateTimeKind.Utc);

    [Theory]
    [InlineData("500ms", 0, 0, 0, 500)]
    [InlineData("90s", 0, 0, 90, 0)]
    [InlineData("10m", 0, 10, 0, 0)]
    [InlineData("2h", 2, 0, 0, 0)]
    [InlineData("7d", 168, 0, 0, 0)]
    [InlineData("1d", 24, 0, 0, 0)]
    public void ParsesDurations(string input, int hours, int minutes, int seconds, int milliseconds)
    {
        Assert.True(TimeParsing.TryParseDuration(input, out TimeSpan result));
        Assert.Equal(new TimeSpan(0, hours, minutes, seconds, milliseconds), result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("10")]          // no unit
    [InlineData("m")]           // no count
    [InlineData("10x")]         // unknown unit
    [InlineData("-10m")]        // sign belongs to the instant syntax, not the duration
    [InlineData("10 m")]
    [InlineData("1.5h")]
    [InlineData("0s")]          // a zero-length window is not a useful query
    public void RejectsMalformedDurations(string input) =>
        Assert.False(TimeParsing.TryParseDuration(input, out _));

    [Fact]
    public void ParsesNow()
    {
        Assert.True(TimeParsing.TryParseInstant("now", Now, out DateTime result));
        Assert.Equal(Now, result);
    }

    [Fact]
    public void ParsesRelativeInstantsAsTimeBeforeNow()
    {
        Assert.True(TimeParsing.TryParseInstant("-10m", Now, out DateTime result));
        Assert.Equal(Now.AddMinutes(-10), result);
    }

    [Fact]
    public void ParsesUnixSeconds()
    {
        Assert.True(TimeParsing.TryParseInstant("1769000000", Now, out DateTime result));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1769000000).UtcDateTime, result);
    }

    [Fact]
    public void ParsesUnixMillisecondsByDigitCount()
    {
        // Thirteen digits is milliseconds; ten or fewer is seconds. Guessing wrong would put the result
        // roughly 50,000 years out.
        Assert.True(TimeParsing.TryParseInstant("1769000000123", Now, out DateTime result));
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1769000000123).UtcDateTime, result);
    }

    [Theory]
    [InlineData("2026-07-29T14:03:12Z")]
    [InlineData("2026-07-29T14:03:12")]
    [InlineData("20260729T140312Z")]
    [InlineData("20260729T140312")]
    public void ParsesIsoFormsAsUtc(string input)
    {
        Assert.True(TimeParsing.TryParseInstant(input, Now, out DateTime result));
        Assert.Equal(new DateTime(2026, 7, 29, 14, 3, 12, DateTimeKind.Utc), result);
        Assert.Equal(DateTimeKind.Utc, result.Kind);
    }

    [Fact]
    public void ParsesFractionalSeconds()
    {
        Assert.True(TimeParsing.TryParseInstant("2026-07-29T14:03:12.456Z", Now, out DateTime result));
        Assert.Equal(new DateTime(2026, 7, 29, 14, 3, 12, 456, DateTimeKind.Utc), result);
    }

    [Fact]
    public void ParsesABareDate()
    {
        Assert.True(TimeParsing.TryParseInstant("2026-07-29", Now, out DateTime result));
        Assert.Equal(new DateTime(2026, 7, 29, 0, 0, 0, DateTimeKind.Utc), result);
    }

    [Theory]
    [InlineData("2026-07-29T14:03:12+02:00")]
    [InlineData("2026-07-29T14:03:12-05:00")]
    public void RejectsExplicitOffsetsRatherThanMisinterpretingThem(string input)
    {
        // '+' means space in a query string and is ambiguous unescaped in a path, so an offset is
        // refused outright instead of being silently read as something else.
        Assert.False(TimeParsing.TryParseInstant(input, Now, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("yesterday")]
    [InlineData("14:03:12")]
    [InlineData("-")]
    [InlineData("-nonsense")]
    [InlineData("2026-13-45T99:99:99Z")]
    public void RejectsMalformedInstants(string input) =>
        Assert.False(TimeParsing.TryParseInstant(input, Now, out _));

    [Fact]
    public void AcceptedFormDescriptionsMentionTheFormsActuallySupported()
    {
        // These strings go into 400 responses, so they must not drift from the parser.
        foreach (string sample in new[] { "now", "-10m" })
        {
            Assert.Contains(sample, TimeParsing.AcceptedInstantForms, StringComparison.Ordinal);
            Assert.True(TimeParsing.TryParseInstant(sample, Now, out _));
        }

        foreach (string sample in new[] { "500ms", "90s", "10m", "2h", "7d" })
        {
            Assert.Contains(sample, TimeParsing.AcceptedDurationForms, StringComparison.Ordinal);
            Assert.True(TimeParsing.TryParseDuration(sample, out _));
        }
    }
}
