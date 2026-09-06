using System.Globalization;
using System.Text;
using Oko.Capture;

namespace Oko.Http;

/// <summary>Prometheus text 0.0.4 projection of existing counters. Scraping never resets them.</summary>
internal sealed class MetricsReporter(StatusReporter status, WriterMetrics writer)
{
    public string Build()
    {
        StatusResponse s = status.Build();
        WriterSnapshot w = writer.Snapshot();
        var text = new StringBuilder();
        Metric(text, "oko_ingest_packets_total", "counter", "Received TZSP datagrams and TCP pcap records.", s.Ingest.PacketsReceived);
        Metric(text, "oko_ingest_bytes_total", "counter", "Received bytes as counted by each ingest transport.", s.Ingest.BytesReceived);
        Metric(text, "oko_stored_frames_total", "counter", "Frames accepted into the capture store, including memory-only data.", s.Ingest.FramesStored);
        Metric(text, "oko_stored_bytes_total", "counter", "Frame bytes accepted into the capture store.", s.Ingest.BytesStored);
        Metric(text, "oko_tzsp_parse_errors_total", "counter", "Malformed TZSP datagrams.", s.Ingest.TzspParseErrors);
        Metric(text, "oko_tzsp_keepalives_total", "counter", "TZSP keepalive datagrams.", s.Ingest.Keepalives);
        Metric(text, "oko_ingest_empty_payloads_total", "counter", "Empty ingest payloads.", s.Ingest.EmptyPayloads);
        Metric(text, "oko_ingest_unsupported_encapsulation_total", "counter", "Unsupported encapsulations.", s.Ingest.UnsupportedEncapsulation);
        Metric(text, "oko_ingest_receive_errors_total", "counter", "Receive errors.", s.Ingest.ReceiveErrors);
        Metric(text, "oko_ingest_truncated_frames_total", "counter", "Frames truncated to the configured snap length.", s.Ingest.TruncatedFrames);
        Metric(text, "oko_pcap_stream_errors_total", "counter", "Rejected or failed TCP pcap streams.", s.Ingest.PcapStreamErrors);
        Metric(text, "oko_capture_loop_suspects_total", "counter", "Frames suspected of capturing the ingest connection.", s.Ingest.CaptureLoopSuspects);
        Metric(text, "oko_clock_skew_events_total", "counter", "Sender clock skew observations; not a count of unique sensors.", s.Ingest.ClockSkewedSenders);
        Metric(text, "oko_uptime_seconds", "gauge", "Process uptime.", s.UptimeSeconds);
        Metric(text, "oko_memory_active_bytes", "gauge", "Bytes in the active capture block.", s.Memory.ActiveBytes);
        Metric(text, "oko_memory_pending_flush_bytes", "gauge", "Sealed capture bytes awaiting disk commit; excludes the active block.", s.Memory.PendingFlushBytes);
        Metric(text, "oko_storage_bytes", "gauge", "Indexed segment bytes, not filesystem usage.", s.Storage.Bytes);
        Metric(text, "oko_storage_segments", "gauge", "Indexed capture segments.", s.Storage.Segments);
        Metric(text, "oko_storage_retention_bytes", "gauge", "Configured retention byte limit.", s.Storage.RetentionBytes);
        Metric(text, "oko_live_subscribers", "gauge", "Currently attached live readers.", s.Live.Subscribers);
        Metric(text, "oko_live_overflow_disconnects_total", "counter", "Live readers disconnected when their queue overflowed.", s.Live.DroppedBatches);
        Metric(text, "oko_writer_flushes_total", "counter", "Successfully committed segments.", w.Flushes);
        Metric(text, "oko_writer_failures_total", "counter", "Failed segment write attempts, including retries.", w.Failures);
        Metric(text, "oko_writer_bytes_total", "counter", "Committed segment bytes including headers.", w.Bytes);
        Metric(text, "oko_writer_flush_duration_seconds_total", "counter", "Cumulative duration of successful segment writes and commits.", w.DurationSeconds);
        Metric(text, "oko_writer_last_success_timestamp_seconds", "gauge", "Unix time of last successful flush; zero before any success.", w.LastSuccessTimestampSeconds);
        Metric(text, "oko_writer_consecutive_failures", "gauge", "Failed write attempts since the last successful flush.", w.ConsecutiveFailures);
        if (s.Ingest.SocketDrops is long drops)
        {
            Metric(text, "oko_udp_socket_drops_total", "counter", "Kernel UDP drops; omitted when unavailable.", drops);
        }
        if (s.Storage.OldestUtc is DateTime oldest)
        {
            Metric(text, "oko_storage_oldest_timestamp_seconds", "gauge", "Earliest indexed capture timestamp.", UnixSeconds(oldest));
        }
        Header(text, "oko_sensor_frames_total", "counter", "Stored frames per sensor.");
        foreach (SensorStatus sensor in s.Sensors)
        {
            Sample(text, "oko_sensor_frames_total", sensor.Packets, Labels(sensor));
        }
        Header(text, "oko_sensor_bytes_total", "counter", "Stored frame bytes per sensor.");
        foreach (SensorStatus sensor in s.Sensors)
        {
            Sample(text, "oko_sensor_bytes_total", sensor.Bytes, Labels(sensor));
        }
        Header(text, "oko_sensor_last_seen_timestamp_seconds", "gauge", "Last stored frame timestamp per sensor; TCP uses sender time.");
        foreach (SensorStatus sensor in s.Sensors)
        {
            Sample(text, "oko_sensor_last_seen_timestamp_seconds", UnixSeconds(sensor.LastSeenUtc), Labels(sensor));
        }
        return text.ToString();
    }

    private static double UnixSeconds(DateTime utc) => new DateTimeOffset(utc).ToUnixTimeMilliseconds() / 1000d;

    private static string Labels(SensorStatus sensor) =>
        "{sensor=\"" + EscapeLabel(sensor.Address) + "\",link_type=\"" + sensor.LinkType.ToString(CultureInfo.InvariantCulture) + "\"}";

    internal static string EscapeLabel(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);

    private static void Metric(StringBuilder text, string name, string type, string help, double value)
    {
        Header(text, name, type, help);
        Sample(text, name, value);
    }

    private static void Header(StringBuilder text, string name, string type, string help) =>
        text.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n')
            .Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');

    private static void Sample(StringBuilder text, string name, double value, string labels = "") =>
        text.Append(name).Append(labels).Append(' ').Append(value.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
}
