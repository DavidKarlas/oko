using System.Globalization;
using System.Net;

namespace Oko.Tests;

/// <summary>
/// Drives the real service over UDP and HTTP: TZSP in, pcapng out, verified with tshark.
/// </summary>
[Collection(nameof(ServiceEndToEndTests))]
public class ServiceEndToEndTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-e2e-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A killed service may still hold a handle; the temp directory is disposable either way.
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task ReturnsEveryFrameExactlyOnceWhenTheWindowSpansDiskAndMemoryAsync()
    {
        // The invariant that matters most: CompleteFlush publishes a segment and releases its blocks under
        // one lock, so a query overlapping the handoff must see each packet exactly once — no gaps from a
        // premature release, no duplicates from a late one.
        await using OkoService oko = await OkoService.StartAsync(
            _directory,
            ("OKO_FLUSH_BYTES", "65536"),
            ("OKO_FLUSH_INTERVAL", "00:00:01"));

        oko.SendFrames(3_000, firstIdentification: 0);
        await oko.WaitForStatusAsync(status => status.Segments >= 1);

        oko.SendFrames(500, firstIdentification: 3_000);
        StatusView status = await oko.WaitForQuietAsync();

        // Confirm the data really is split, or the test would not be exercising the boundary at all.
        Assert.True(status.Segments >= 1, "expected at least one segment on disk");
        Assert.True(status.ActiveBytes + status.SealedBytes > 0, "expected some data still in memory");

        string capture = await oko.DownloadCaptureAsync($"{oko.Token}/last/1h", "spanning.pcapng");

        Wireshark.AssertFileIsValid(capture);
        int[] identifications = ReadIdentifications(capture);

        Assert.Equal(status.FramesStored, identifications.Length);
        Assert.Equal(identifications.Length, identifications.Distinct().Count());
        Assert.Equal(identifications.Order(), identifications);
    }

    [Fact]
    public async Task NarrowsTheResultToTheRequestedWindowAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(
            _directory,
            ("OKO_FLUSH_BYTES", "65536"),
            ("OKO_FLUSH_INTERVAL", "00:00:01"));

        oko.SendFrames(400, firstIdentification: 0);
        await oko.WaitForStatusAsync(status => status.FramesStored >= 400);

        // Everything before this instant must be excluded from the narrowed query.
        await Task.Delay(1_200, TestContext.Current.CancellationToken);
        DateTime boundary = DateTime.UtcNow;
        await Task.Delay(1_200, TestContext.Current.CancellationToken);

        oko.SendFrames(400, firstIdentification: 400);
        StatusView status = await oko.WaitForQuietAsync();

        string boundaryText = boundary.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        string narrowed = await oko.DownloadCaptureAsync(
            $"{oko.Token}/from/{boundaryText}/to/now",
            "narrowed.pcapng");
        string everything = await oko.DownloadCaptureAsync($"{oko.Token}/last/1h", "everything.pcapng");

        Wireshark.AssertFileIsValid(narrowed);
        int[] inWindow = ReadIdentifications(narrowed);

        Assert.Equal(status.FramesStored, ReadIdentifications(everything).Length);

        // Only the second batch is inside the window, and the edge segment must have been trimmed
        // per-packet rather than copied whole.
        Assert.NotEmpty(inWindow);
        Assert.All(inWindow, identification => Assert.True(identification >= 400));
        Assert.True(inWindow.Length < status.FramesStored, "the narrowed window must exclude the first batch");
    }

    [Fact]
    public async Task StreamsHistoryThenLivePacketsWithoutDuplicatingTheHandoffAsync()
    {
        // The flagship endpoint: Wireshark opens already showing recent history and keeps updating.
        await using OkoService oko = await OkoService.StartAsync(
            _directory,
            ("OKO_FLUSH_BYTES", "65536"),
            ("OKO_FLUSH_INTERVAL", "00:00:01"),
            ("OKO_LIVE_FLUSH_MS", "100"));

        oko.SendFrames(800, firstIdentification: 0);
        StatusView beforeFollowing = await oko.WaitForQuietAsync();

        string path = Path.Combine(_directory, "follow.pcapng");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(60));

        Task streaming = StreamToFileAsync(oko, $"{oko.Token}/last/1h/live", path, stop.Token);

        await oko.WaitForStatusAsync(status => status.LiveSubscribers >= 1);
        oko.SendFrames(150, firstIdentification: 800);
        StatusView afterFollowing = await oko.WaitForQuietAsync();

        // Give the coalescing buffer time to flush the tail, then end the stream as a client would.
        await Task.Delay(1_000, TestContext.Current.CancellationToken);
        await stop.CancelAsync();
        await streaming;

        int[] identifications = ReadIdentifications(path);

        // History and live must both be complete, and the sequence-based dedupe must not double-send the
        // packets that arrived between subscribing and finishing the history read.
        Assert.Equal(afterFollowing.FramesStored, identifications.Length);
        Assert.Equal(identifications.Length, identifications.Distinct().Count());
        Assert.True(
            identifications.Count(identification => identification < 800) >= beforeFollowing.FramesStored,
            "the historical portion is incomplete");
        Assert.Contains(949, identifications);
    }

    [Fact]
    public async Task ReportsIngestCountersAndNormalisedSensorAddressesAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        oko.SendFrames(50);
        oko.SendKeepalive();
        StatusView status = await oko.WaitForStatusAsync(s => s.FramesStored >= 50 && s.Keepalives >= 1);

        Assert.Equal(51, status.PacketsReceived);
        Assert.Equal(50, status.FramesStored);
        Assert.Equal(1, status.Keepalives);
        Assert.Equal(0, status.ParseErrors);
        Assert.True(status.UptimeSeconds > 0, "uptime must be measured from process start, not first request");

        // Not ::ffff:127.0.0.1: the address must match the name recorded in the IDB.
        Assert.Equal(["127.0.0.1"], status.SensorAddresses);
    }

    [Fact]
    public async Task FlushesEverythingStillInMemoryOnACleanShutdownAsync()
    {
        // Both thresholds are set far out of reach, so these frames can only reach disk via the shutdown
        // drain. Without it, stopping the container would silently discard up to a segment of capture.
        await using OkoService oko = await OkoService.StartAsync(
            _directory,
            ("OKO_FLUSH_INTERVAL", "01:00:00"),
            ("OKO_FLUSH_BYTES", "1073741824"));

        oko.SendFrames(120);
        StatusView status = await oko.WaitForQuietAsync();

        Assert.True(status.FramesStored > 0);
        Assert.Equal(0, status.Segments);
        Assert.True(status.ActiveBytes > 0, "the frames should still be in memory at this point");

        await oko.StopGracefullyAsync();

        string segments = Path.Combine(_directory, "segments");
        string[] written = Directory.Exists(segments)
            ? [.. Directory.EnumerateFiles(segments, "*.pcapng", SearchOption.AllDirectories)]
            : [];

        string capture = Assert.Single(written);
        Wireshark.AssertFileIsValid(capture);
        Assert.Equal(status.FramesStored, ReadIdentifications(capture).Length);
    }

    [Theory]
    // Malformed expressions: the response must name the forms that would have worked, because these get
    // typed by hand into a curl command.
    [InlineData("last/banana", "Expected")]
    [InlineData("last/0s", "Expected")]
    [InlineData("last/10", "Expected")]
    [InlineData("from/yesterday/to/now", "Expected")]
    // Well-formed but nonsensical: a different, specific explanation.
    [InlineData("from/now/to/-10m", "before its start")]
    public async Task RejectsUnusableTimeExpressionsWithAnExplanationAsync(string path, string expectedDetail)
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        using HttpResponseMessage response = await oko.GetAsync($"{oko.Token}/{path}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains(expectedDetail, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HidesCaptureEndpointsBehindTheTokenAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);

        // 404 rather than 401, so a wrong token is indistinguishable from a wrong path.
        using (HttpResponseMessage wrong = await oko.GetAsync("not-the-token/last/10m", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.NotFound, wrong.StatusCode);
        }

        using (HttpResponseMessage right = await oko.GetAsync($"{oko.Token}/last/10m", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, right.StatusCode);
        }

        // healthz must stay open so a container health check does not need a capture token.
        using (HttpResponseMessage health = await oko.GetAsync("healthz", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        }
    }

    [Fact]
    public async Task AcceptsTheTokenViaBearerHeaderAndQueryStringAsync()
    {
        // Every route carries a {token} segment, so these two forms are only reachable if all three
        // sources are treated as alternatives rather than the path taking precedence.
        await using OkoService oko = await OkoService.StartAsync(_directory);

        using var client = new HttpClient { BaseAddress = new Uri(oko.BaseAddress) };
        using var request = new HttpRequestMessage(HttpMethod.Get, "placeholder/status");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", oko.Token);

        using HttpResponseMessage viaHeader = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, viaHeader.StatusCode);

        using HttpResponseMessage viaQuery = await client.GetAsync($"placeholder/status?token={oko.Token}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, viaQuery.StatusCode);
    }

    [Fact]
    public async Task RefusesToServeCapturesWhenNoTokenIsConfiguredAsync()
    {
        // Failing closed matters: a collector reachable without a token would hand a network capture to
        // anyone who found the port.
        await using OkoService oko = await OkoService.StartAsync(_directory, ("OKO_TOKENS", ""));

        using HttpResponseMessage response = await oko.GetAsync("anything/last/10m", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task ServesCapturesWithHeadersThatMakeBrowsersAndWiresharkBehaveAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory);
        oko.SendFrames(20);
        await oko.WaitForStatusAsync(status => status.FramesStored >= 20);

        using HttpResponseMessage response = await oko.GetAsync($"{oko.Token}/last/10m", TestContext.Current.CancellationToken);

        Assert.Equal("application/x-pcapng", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("attachment", response.Content.Headers.ContentDisposition?.DispositionType);
        Assert.EndsWith(
            ".pcapng\"",
            response.Content.Headers.ContentDisposition?.ToString() ?? "",
            StringComparison.Ordinal);

        // A capture must never be cached: the same URL means something different a second later.
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task RefusesToStartOnAnUnparseableConfigurationValueAsync()
    {
        // Running with a silently defaulted port or retention would be worse than not starting.
        await Assert.ThrowsAnyAsync<Exception>(() =>
            OkoService.StartAsync(_directory, ("OKO_UDP_PORT", "not-a-port")));
    }

    private static async Task StreamToFileAsync(
        OkoService oko,
        string path,
        string destination,
        CancellationToken cancellationToken)
    {
        using var client = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

        try
        {
            using HttpResponseMessage response = await client.GetAsync(
                new Uri($"{oko.BaseAddress}/{path}"),
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            response.EnsureSuccessStatusCode();

            await using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using FileStream file = File.Create(destination);
            await body.CopyToAsync(file, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Ending the stream is how a live client normally finishes.
        }
    }

    private static int[] ReadIdentifications(string capture) =>
    [
        .. Wireshark.ReadField(capture, "ip.id")
            .Select(value => Convert.ToInt32(value, 16)),
    ];
}
