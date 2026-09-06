using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using Oko.Http;

namespace Oko.Tests;

public sealed class MetricsTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("oko-metrics-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData(false, "", HttpStatusCode.ServiceUnavailable)]
    [InlineData(false, "test-token", HttpStatusCode.NotFound)]
    [InlineData(true, "", HttpStatusCode.OK)]
    public async Task MetricsUsesExistingAuthenticationAsync(bool anonymous, string token, HttpStatusCode expected)
    {
        await using OkoService oko = await OkoService.StartAsync(_directory,
            ("OKO_TOKENS", token), ("OKO_ALLOW_ANONYMOUS", anonymous.ToString()));
        using HttpResponseMessage response = await oko.GetAsync("metrics", TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task ScrapesTrackIngestFailedWritesAndRecoveryAsync()
    {
        await using OkoService oko = await OkoService.StartAsync(_directory,
            ("OKO_FLUSH_INTERVAL", "00:00:01"));
        using var client = new HttpClient { BaseAddress = new Uri(oko.BaseAddress) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "wrong");
        using (HttpResponseMessage rejected = await client.GetAsync("/metrics", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.NotFound, rejected.StatusCode);
        }
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", oko.Token);
        using (HttpResponseMessage initial = await client.GetAsync("/metrics", TestContext.Current.CancellationToken))
        {
            initial.EnsureSuccessStatusCode();
            Assert.Contains("version=0.0.4", initial.Content.Headers.ContentType!.ToString());
            string text = await initial.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(0, Value(text, "oko_stored_frames_total"));
            Assert.Equal(0, Value(text, "oko_writer_last_success_timestamp_seconds"));
            Assert.EndsWith("\n", text);
            if (!OperatingSystem.IsLinux()) { Assert.DoesNotContain("oko_udp_socket_drops_total", text); }
        }

        // Make storage unwritable without relying on permissions (which root could bypass).
        string segments = Path.Combine(_directory, "segments");
        Directory.Delete(segments);
        await File.WriteAllTextAsync(segments, "blocked", TestContext.Current.CancellationToken);
        oko.SendFrames(3);
        await oko.WaitForStatusAsync(s => s.FramesStored == 3);
        string failed = await WaitForMetricAsync(client, "oko_writer_failures_total", v => v >= 1);
        Assert.Equal(0, Value(failed, "oko_writer_flushes_total"));
        Assert.True(Value(failed, "oko_memory_pending_flush_bytes") > 0);
        Assert.True(Value(failed, "oko_writer_consecutive_failures") >= 1);

        File.Delete(segments);
        Directory.CreateDirectory(segments);
        string recovered = await WaitForMetricAsync(client, "oko_writer_flushes_total", v => v == 1);
        Assert.Equal(3, Value(recovered, "oko_stored_frames_total"));
        Assert.Equal(0, Value(recovered, "oko_memory_pending_flush_bytes"));
        Assert.Equal(0, Value(recovered, "oko_writer_consecutive_failures"));
        Assert.True(Value(recovered, "oko_writer_last_success_timestamp_seconds") > 0);
        Assert.True(Value(recovered, "oko_writer_bytes_total") > 0);
        Assert.True(Value(recovered, "oko_writer_flush_duration_seconds_total") > 0);
        Assert.Contains("oko_sensor_frames_total{sensor=\"127.0.0.1\",link_type=\"1\"} 3\n", recovered);
        string again = await client.GetStringAsync("/metrics", TestContext.Current.CancellationToken);
        Assert.Equal(Value(recovered, "oko_writer_failures_total"), Value(again, "oko_writer_failures_total"));
        Assert.Equal(3, Value(again, "oko_stored_frames_total"));
    }

    [Fact]
    public void EscapesPrometheusLabelValues()
    {
        Assert.Equal("a\\\\b\\\"c\\nd", MetricsReporter.EscapeLabel("a\\b\"c\nd"));
    }

    private static double Value(string text, string name) => double.Parse(
        text.Split('\n').Single(line => line.StartsWith(name + " ", StringComparison.Ordinal))[(name.Length + 1)..],
        CultureInfo.InvariantCulture);

    private static async Task<string> WaitForMetricAsync(HttpClient client, string name, Func<double, bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (true)
        {
            string text = await client.GetStringAsync("/metrics", timeout.Token);
            if (condition(Value(text, name))) { return text; }
            await Task.Delay(100, timeout.Token);
        }
    }
}
