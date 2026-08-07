using System.Globalization;

namespace Oko.Capture;

/// <summary>
/// Reads the kernel's UDP drop counter for Oko's listening port from <c>/proc/net/udp</c>.
/// </summary>
/// <remarks>
/// Silent loss is the failure mode that ruins a TZSP capture: the frames simply are not there, and
/// nothing in the file says so. The kernel does know, and this is the cheapest way to surface it.
/// Rising drops almost always mean the socket receive buffer is too small — and note that
/// <c>net.core.rmem_max</c> is a global, non-namespaced sysctl, so inside a container an 8 MB
/// <c>SO_RCVBUF</c> request is silently clamped to roughly 208 KB unless the host was tuned.
/// Linux-only; returns <see langword="null"/> elsewhere.
/// </remarks>
internal sealed class UdpDropReader(int port, ILogger<UdpDropReader> logger)
{
    private static readonly string[] ProcFiles = ["/proc/net/udp", "/proc/net/udp6"];

    private bool _warnedAboutFailure;

    /// <summary>Total dropped datagrams across every socket bound to the port, or null if unavailable.</summary>
    public long? TryReadDrops()
    {
        long total = 0;
        bool found = false;

        foreach (string file in ProcFiles)
        {
            if (!File.Exists(file))
            {
                continue;
            }

            try
            {
                foreach (string line in File.ReadLines(file).Skip(1))
                {
                    if (TryParseLine(line, out long drops))
                    {
                        total += drops;
                        found = true;
                    }
                }
            }
            catch (IOException exception)
            {
                if (!_warnedAboutFailure)
                {
                    _warnedAboutFailure = true;
                    logger.LogWarning(exception, "Could not read {File}; drop counts will be unavailable.", file);
                }

                return null;
            }
        }

        return found ? total : null;
    }

    private bool TryParseLine(string line, out long drops)
    {
        drops = 0;

        // sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ref pointer drops
        string[] fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 5)
        {
            return false;
        }

        int colon = fields[1].LastIndexOf(':');
        if (colon < 0 ||
            !int.TryParse(fields[1].AsSpan(colon + 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int localPort) ||
            localPort != port)
        {
            return false;
        }

        // Take the last column rather than a fixed index: the trailing fields have varied across
        // kernel versions, but drops has always been last.
        return long.TryParse(fields[^1], CultureInfo.InvariantCulture, out drops);
    }
}
