using System.Diagnostics;

namespace Oko.Tests;

/// <summary>
/// Tests for the <c>oko-tap</c> shell script. Its one safety-critical property is that the
/// self-exclusion filter is always present: without it, tcpdump captures the stream being sent to the
/// collector, which emits another packet, which is captured in turn, until the link saturates.
/// </summary>
public class OkoTapScriptTests
{
    private static string ScriptPath
    {
        get
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Oko.slnx")))
            {
                directory = directory.Parent;
            }

            Assert.NotNull(directory);
            return Path.Combine(directory!.FullName, "tools", "oko-tap", "oko-tap");
        }
    }

    [Fact]
    public void AlwaysIncludesTheSelfExclusionFilter()
    {
        (int exitCode, string output, _) = Run("--collector", "10.0.0.5", "--dry-run");

        Assert.Equal(0, exitCode);
        Assert.Contains("not (host 10.0.0.5 and tcp port 37009)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void KeepsTheExclusionEvenWhenTheUserFilterContradictsIt()
    {
        // Someone explicitly asking to capture the collector's traffic must still not be able to create
        // the loop. The user filter is parenthesised and ANDed, so it cannot widen the result.
        (int exitCode, string output, _) = Run(
            "--collector", "10.0.0.5", "--filter", "host 10.0.0.5", "--dry-run");

        Assert.Equal(0, exitCode);
        Assert.Contains("(host 10.0.0.5) and not (host 10.0.0.5 and tcp port 37009)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void CombinesAUserFilterWithParenthesesSoPrecedenceCannotLeak()
    {
        // Without the parentheses, 'a or b' would bind loosely and defeat the trailing exclusion.
        (_, string output, _) = Run("--collector", "10.0.0.5", "--filter", "tcp or udp", "--dry-run");

        Assert.Contains("(tcp or udp) and not (host 10.0.0.5 and tcp port 37009)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void HonoursThePortWhenBuildingTheExclusion()
    {
        (_, string output, _) = Run("--collector", "oko.example.com", "--port", "40000", "--dry-run");

        Assert.Contains("not (host oko.example.com and tcp port 40000)", output, StringComparison.Ordinal);
        Assert.Contains("40000", output, StringComparison.Ordinal);
    }

    [Fact]
    public void CanAlsoExcludeTheManagementSshSession()
    {
        (_, string output, _) = Run("--collector", "10.0.0.5", "--exclude-ssh", "--dry-run");

        Assert.Contains("not tcp port 22", output, StringComparison.Ordinal);
        Assert.Contains("not (host 10.0.0.5 and tcp port 37009)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void DefaultsToTheAnyInterfaceAndUnbufferedOutput()
    {
        (_, string output, _) = Run("--collector", "10.0.0.5", "--dry-run");

        Assert.Contains("-i any", output, StringComparison.Ordinal);

        // Without -U, tcpdump buffers roughly 4 KB and a live view stalls until it fills.
        Assert.Contains("-U", output, StringComparison.Ordinal);
    }

    [Fact]
    public void RequiresACollector()
    {
        (int exitCode, _, string error) = Run("--dry-run");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("--collector is required", error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsANonNumericPort()
    {
        (int exitCode, _, string error) = Run("--collector", "10.0.0.5", "--port", "banana", "--dry-run");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("must be a number", error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsUnknownOptionsRatherThanIgnoringThem()
    {
        // Silently ignoring a typo'd option could mean silently dropping --filter.
        (int exitCode, _, string error) = Run("--collector", "10.0.0.5", "--fliter", "x", "--dry-run");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("unknown option", error, StringComparison.Ordinal);
    }

    [Fact]
    public void DocumentsThatTheExclusionCannotBeDisabled()
    {
        (int exitCode, string output, _) = Run("--help");

        Assert.Equal(0, exitCode);
        Assert.Contains("cannot be disabled", output, StringComparison.Ordinal);

        // The two gotchas an operator will otherwise hit: SLL2 versus TZSP, and promiscuous mode.
        Assert.Contains("SLL2", output, StringComparison.Ordinal);
        Assert.Contains("promiscuous", output, StringComparison.Ordinal);
    }

    [Fact]
    public void IsExecutable()
    {
        Assert.True(File.Exists(ScriptPath), $"{ScriptPath} is missing");

        if (!OperatingSystem.IsWindows())
        {
            UnixFileMode mode = File.GetUnixFileMode(ScriptPath);
            Assert.True(mode.HasFlag(UnixFileMode.UserExecute), "oko-tap must be executable");
        }
    }

    private static (int ExitCode, string StandardOutput, string StandardError) Run(params string[] arguments)
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("oko-tap is a POSIX shell script.");
        }

        var startInfo = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        startInfo.ArgumentList.Add(ScriptPath);
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("could not run sh");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(15_000), "oko-tap did not exit");

        return (process.ExitCode, output, error);
    }
}
