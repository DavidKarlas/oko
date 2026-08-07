using System.Globalization;

namespace Oko.Http;

/// <summary>
/// Parses the time expressions Oko accepts in URLs.
/// </summary>
/// <remarks>
/// Deliberately generous about input format, because these get typed by hand into a <c>curl</c>
/// command, but strict about time zones: everything is UTC. A <c>+02:00</c> offset inside a URL path
/// segment is an encoding trap (<c>+</c> means space in a query string, and an unescaped one is
/// ambiguous), so it is rejected with a message naming the accepted forms rather than silently
/// misparsed.
/// </remarks>
internal static class TimeParsing
{
    private static readonly string[] InstantFormats =
    [
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'",
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF",
        "yyyy-MM-dd'T'HH:mm:ss",
        "yyyy-MM-dd'T'HH:mm",
        "yyyyMMdd'T'HHmmssfff'Z'",
        "yyyyMMdd'T'HHmmss'Z'",
        "yyyyMMdd'T'HHmmssfff",
        "yyyyMMdd'T'HHmmss",
        "yyyy-MM-dd",
    ];

    public const string AcceptedInstantForms =
        "unix seconds (1769000000), unix milliseconds (1769000000123), " +
        "ISO-8601 UTC (2026-07-29T14:03:12Z or 20260729T140312Z), " +
        "'now', or a negative duration such as -10m";

    public const string AcceptedDurationForms = "a duration such as 500ms, 90s, 10m, 2h or 7d";

    /// <summary>Parses a point in time. Relative forms are resolved against <paramref name="nowUtc"/>.</summary>
    public static bool TryParseInstant(string? value, DateTime nowUtc, out DateTime result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        value = value.Trim();

        if (string.Equals(value, "now", StringComparison.OrdinalIgnoreCase))
        {
            result = nowUtc;
            return true;
        }

        // Relative: "-10m" means ten minutes ago.
        if (value[0] == '-')
        {
            if (!TryParseDuration(value[1..], out TimeSpan back))
            {
                return false;
            }

            result = nowUtc - back;
            return true;
        }

        // A bare integer is a Unix timestamp; the digit count distinguishes seconds from milliseconds.
        if (long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long epoch))
        {
            result = value.Length >= 13
                ? DateTimeOffset.FromUnixTimeMilliseconds(epoch).UtcDateTime
                : DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
            return true;
        }

        if (DateTime.TryParseExact(
            value,
            InstantFormats,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTime parsed))
        {
            result = parsed;
            return true;
        }

        return false;
    }

    /// <summary>Parses <c>500ms</c>, <c>90s</c>, <c>10m</c>, <c>2h</c>, <c>7d</c>.</summary>
    public static bool TryParseDuration(string? value, out TimeSpan result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        value = value.Trim();

        int digits = 0;
        while (digits < value.Length && char.IsAsciiDigit(value[digits]))
        {
            digits++;
        }

        if (digits == 0 || digits == value.Length)
        {
            return false;
        }

        if (!long.TryParse(value.AsSpan(0, digits), NumberStyles.None, CultureInfo.InvariantCulture, out long count))
        {
            return false;
        }

        string unit = value[digits..];
        double multiplierMilliseconds = unit switch
        {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            _ => 0,
        };

        if (multiplierMilliseconds == 0)
        {
            return false;
        }

        double totalMilliseconds = count * multiplierMilliseconds;
        if (totalMilliseconds is <= 0 or > 3_650d * 86_400_000)
        {
            return false;
        }

        result = TimeSpan.FromMilliseconds(totalMilliseconds);
        return true;
    }
}
