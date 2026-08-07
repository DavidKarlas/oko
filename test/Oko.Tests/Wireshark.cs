using System.Diagnostics;

namespace Oko.Tests;

/// <summary>
/// Runs the real Wireshark command-line tools against files Oko produced. This is the check that
/// actually proves the pcapng writer is correct — golden bytes only prove it is self-consistent.
/// </summary>
internal static class Wireshark
{
    public sealed record ToolResult(int ExitCode, string StandardOutput, string StandardError);

    /// <summary>Returns the tool's path, or <see langword="null"/> when it is not installed.</summary>
    public static string? Locate(string tool)
    {
        foreach (string directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            if (directory.Length == 0)
            {
                continue;
            }

            string candidate = Path.Combine(directory, tool);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    /// <summary>Skips the calling test when <paramref name="tool"/> is unavailable.</summary>
    public static string Require(string tool)
    {
        string? path = Locate(tool);
        if (path is null)
        {
            Assert.Skip($"{tool} is not installed; install Wireshark to run capture-format validation.");
        }

        return path!;
    }

    public static ToolResult Run(string tool, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(Require(tool))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"could not start {tool}");

        string standardOutput = process.StandardOutput.ReadToEnd();
        string standardError = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(30_000), $"{tool} did not exit within 30s");

        return new ToolResult(process.ExitCode, standardOutput, standardError);
    }

    /// <summary>
    /// Asserts the file is valid pcapng as far as Wireshark is concerned: both tools exit cleanly and
    /// neither writes anything to stderr, where file-format complaints appear.
    /// </summary>
    public static void AssertFileIsValid(string path)
    {
        var capinfos = Run("capinfos", path);
        Assert.True(
            capinfos.ExitCode == 0 && capinfos.StandardError.Length == 0,
            $"capinfos rejected the file (exit {capinfos.ExitCode}): {capinfos.StandardError}");

        var tshark = Run("tshark", "-r", path);
        Assert.True(
            tshark.ExitCode == 0 && tshark.StandardError.Length == 0,
            $"tshark rejected the file (exit {tshark.ExitCode}): {tshark.StandardError}");

        // Dissection problems surface on stdout rather than stderr, and would mean the frame bytes or
        // the recorded link type are wrong even though the container blocks parsed.
        Assert.DoesNotContain("Malformed", tshark.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>Reads one field per packet, e.g. <c>frame.interface_name</c> or <c>frame.time_epoch</c>.</summary>
    public static string[] ReadField(string path, string field)
    {
        var result = Run("tshark", "-r", path, "-T", "fields", "-e", field);
        Assert.Equal(0, result.ExitCode);

        return result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
