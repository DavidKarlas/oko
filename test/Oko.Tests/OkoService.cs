using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Oko.Tests;

/// <summary>
/// Runs the real <c>Oko</c> executable and drives it over UDP and HTTP.
/// </summary>
/// <remarks>
/// Launching the published binary rather than hosting it in-process means these tests cover exactly
/// what ships: environment-variable parsing, Kestrel configuration, the socket setup, and shutdown
/// draining. Requires the project to have been built.
/// </remarks>
internal sealed class OkoService : IAsyncDisposable
{
    private readonly Process _process;
    private readonly StringBuilder _output = new();

    private OkoService(
        Process process,
        string dataDirectory,
        int httpPort,
        int udpPort,
        int pcapTcpPort,
        string token)
    {
        _process = process;
        DataDirectory = dataDirectory;
        HttpPort = httpPort;
        UdpPort = udpPort;
        PcapTcpPort = pcapTcpPort;
        Token = token;

        process.OutputDataReceived += Capture;
        process.ErrorDataReceived += Capture;
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    public string DataDirectory { get; }

    public int HttpPort { get; }

    public int UdpPort { get; }

    public int PcapTcpPort { get; }

    public string Token { get; }

    public string BaseAddress => $"http://127.0.0.1:{HttpPort}";

    /// <summary>Everything the service wrote to stdout and stderr, for diagnosing a failed assertion.</summary>
    public string Output
    {
        get
        {
            lock (_output)
            {
                return _output.ToString();
            }
        }
    }

    public static async Task<OkoService> StartAsync(
        string dataDirectory,
        params (string Name, string Value)[] environment)
    {
        string executable = LocateExecutable();
        int httpPort = FindFreePort();
        int udpPort = FindFreePort();
        int pcapTcpPort = FindFreePort();
        const string token = "test-token";

        var startInfo = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(executable),
        };

        startInfo.Environment["OKO_DATA_DIR"] = dataDirectory;
        startInfo.Environment["OKO_TOKENS"] = token;
        startInfo.Environment["OKO_UDP_PORT"] = udpPort.ToString(System.Globalization.CultureInfo.InvariantCulture);
        startInfo.Environment["OKO_PCAP_TCP_PORT"] =
            pcapTcpPort.ToString(System.Globalization.CultureInfo.InvariantCulture);
        startInfo.Environment["OKO_UDP_BIND"] = "127.0.0.1";
        startInfo.Environment["ASPNETCORE_URLS"] = $"http://127.0.0.1:{httpPort}";
        startInfo.Environment["Logging__LogLevel__Default"] = "Warning";

        foreach ((string name, string value) in environment)
        {
            startInfo.Environment[name] = value;
        }

        Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"could not start {executable}");

        var service = new OkoService(process, dataDirectory, httpPort, udpPort, pcapTcpPort, token);
        await service.WaitUntilHealthyAsync();
        return service;
    }

    /// <summary>
    /// Pushes a classic pcap stream to the TCP ingest, the way <c>tcpdump -w - | socat</c> does.
    /// </summary>
    public async Task PushPcapStreamAsync(byte[] stream, bool closeAfter = true)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, PcapTcpPort);

        await using NetworkStream network = client.GetStream();
        await network.WriteAsync(stream);
        await network.FlushAsync();

        if (closeAfter)
        {
            // A clean half-close is how the sender signals end-of-capture.
            client.Client.Shutdown(SocketShutdown.Send);
        }
    }

    private async Task WaitUntilHealthyAsync()
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        while (true)
        {
            if (_process.HasExited)
            {
                throw new InvalidOperationException(
                    $"Oko exited with code {_process.ExitCode} during startup. Output:\n{Output}");
            }

            try
            {
                using HttpResponseMessage response =
                    await client.GetAsync(new Uri($"{BaseAddress}/healthz"), timeout.Token);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                if (timeout.IsCancellationRequested)
                {
                    throw new TimeoutException($"Oko did not become healthy. Output:\n{Output}");
                }
            }

            await Task.Delay(100, timeout.Token);
        }
    }

    /// <summary>Sends TZSP datagrams carrying Ethernet/IPv4/UDP frames with distinguishable ip.id values.</summary>
    public void SendFrames(int count, int firstIdentification = 0, int frameLength = 200)
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        var target = new IPEndPoint(IPAddress.Loopback, UdpPort);

        for (int i = 0; i < count; i++)
        {
            byte[] frame = TestFrames.Udp(frameLength, (ushort)(firstIdentification + i));
            byte[] datagram = TzspDatagram.Create().Padding().End(frame);
            client.Send(datagram, datagram.Length, target);
        }
    }

    public void SendKeepalive()
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        byte[] datagram = TzspDatagram.Create(Tzsp.TzspPacketType.Keepalive).End();
        client.Send(datagram, datagram.Length, new IPEndPoint(IPAddress.Loopback, UdpPort));
    }

    public async Task<HttpResponseMessage> GetAsync(string path, CancellationToken cancellationToken = default)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        return await client.GetAsync(new Uri($"{BaseAddress}/{path.TrimStart('/')}"), cancellationToken);
    }

    /// <summary>Downloads a capture to a file and returns its path.</summary>
    public async Task<string> DownloadCaptureAsync(string path, string fileName)
    {
        using HttpResponseMessage response = await GetAsync(path);
        response.EnsureSuccessStatusCode();

        string target = Path.Combine(DataDirectory, fileName);
        await using (FileStream file = File.Create(target))
        {
            await response.Content.CopyToAsync(file);
        }

        return target;
    }

    /// <summary>
    /// Polls <c>/status</c> until <paramref name="condition"/> holds, so tests wait on the service's own
    /// reported state instead of guessing at a sleep duration.
    /// </summary>
    public async Task<StatusView> WaitForStatusAsync(
        Func<StatusView, bool> condition,
        TimeSpan? timeout = null)
    {
        using var expiry = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(30));

        StatusView status = await ReadStatusAsync();
        while (!condition(status))
        {
            if (expiry.IsCancellationRequested)
            {
                throw new TimeoutException($"status condition not met. Last status: {status}\nOutput:\n{Output}");
            }

            await Task.Delay(100, expiry.Token);
            status = await ReadStatusAsync();
        }

        return status;
    }

    /// <summary>
    /// Waits until the stored-frame count stops moving, so a following query has a stable expectation.
    /// </summary>
    /// <remarks>
    /// Tests assert that a capture contains exactly what ingest recorded rather than exactly what was
    /// sent. UDP is allowed to lose datagrams even on loopback, and "the HTTP response matches the
    /// counters" is the property that actually matters — it would catch a dropped or duplicated packet
    /// in the read path, which comparing against the send count would not.
    /// </remarks>
    public async Task<StatusView> WaitForQuietAsync(TimeSpan? timeout = null)
    {
        using var expiry = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(30));

        long previous = -1;
        while (true)
        {
            StatusView status = await ReadStatusAsync();
            if (status.FramesStored == previous)
            {
                return status;
            }

            previous = status.FramesStored;
            await Task.Delay(300, expiry.Token);
        }
    }

    /// <summary>
    /// Sends SIGTERM and waits for exit, which is how the shutdown drain gets exercised. .NET has no
    /// portable API for this, hence the subprocess.
    /// </summary>
    public async Task StopGracefullyAsync()
    {
        if (_process.HasExited)
        {
            return;
        }

        using Process? kill = Process.Start(
            new ProcessStartInfo("/bin/kill", ["-TERM", _process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)])
            {
                UseShellExecute = false,
            });

        if (kill is not null)
        {
            await kill.WaitForExitAsync();
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await _process.WaitForExitAsync(timeout.Token);
    }

    public async Task<StatusView> ReadStatusAsync()
    {
        using HttpResponseMessage response = await GetAsync($"{Token}/status");
        response.EnsureSuccessStatusCode();
        return StatusView.Parse(await response.Content.ReadAsStringAsync());
    }

    private void Capture(object sender, DataReceivedEventArgs e)
    {
        if (e.Data is null)
        {
            return;
        }

        lock (_output)
        {
            _output.AppendLine(e.Data);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_process.HasExited)
        {
            // SIGKILL rather than a graceful stop: individual tests that need the shutdown drain trigger
            // it explicitly, and killing keeps teardown fast and predictable.
            _process.Kill(entireProcessTree: true);
        }

        await _process.WaitForExitAsync();
        _process.Dispose();
    }

    private static int FindFreePort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    private static string LocateExecutable()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Oko.slnx")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new InvalidOperationException("could not locate the repository root from the test assembly");
        }

        string configuration = Path.GetFileName(Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(
            Path.DirectorySeparatorChar)))!;
        string executable = Path.Combine(
            directory.FullName,
            "src",
            "Oko",
            "bin",
            configuration,
            "net10.0",
            OperatingSystem.IsWindows() ? "Oko.exe" : "Oko");

        return File.Exists(executable)
            ? executable
            : throw new InvalidOperationException(
                $"'{executable}' not found. Build the solution before running the service tests.");
    }
}
