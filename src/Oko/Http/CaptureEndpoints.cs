using System.Buffers;
using System.Globalization;
using System.IO.Pipelines;
using Microsoft.AspNetCore.Http.Features;
using Oko.Capture;

namespace Oko.Http;

/// <summary>
/// The capture routes.
/// </summary>
/// <remarks>
/// Shapes chosen so the primary use case stays a single command:
/// <c>curl -N https://oko/$TOKEN/last/10m/live | wireshark -k -i -</c>. The token is the first path
/// segment for the same reason.
/// </remarks>
internal static class CaptureEndpoints
{
    /// <summary>Registered pcapng media type, which makes browsers and Wireshark do the right thing.</summary>
    private const string PcapngContentType = "application/x-pcapng";

    public static void MapCaptureEndpoints(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // History, then follow. The recommended default: Wireshark opens already showing what happened.
        app.MapGet("/{token}/last/{duration}/live", (
                HttpContext context,
                CaptureService captures,
                string duration,
                CancellationToken cancellationToken) =>
            captures.ServeAsync(context, ParseLast(duration), follow: true, cancellationToken))
            .AddEndpointFilter<TokenAuthFilter>();

        app.MapGet("/{token}/last/{duration}", (
                HttpContext context,
                CaptureService captures,
                string duration,
                CancellationToken cancellationToken) =>
            captures.ServeAsync(context, ParseLast(duration), follow: false, cancellationToken))
            .AddEndpointFilter<TokenAuthFilter>();

        app.MapGet("/{token}/live", (
                HttpContext context,
                CaptureService captures,
                CancellationToken cancellationToken) =>
            captures.ServeAsync(context, LiveOnly, follow: true, cancellationToken))
            .AddEndpointFilter<TokenAuthFilter>();

        app.MapGet("/{token}/from/{start}/to/{end}", (
                HttpContext context,
                CaptureService captures,
                string start,
                string end,
                CancellationToken cancellationToken) =>
            captures.ServeAsync(context, ParseRange(start, end), follow: false, cancellationToken))
            .AddEndpointFilter<TokenAuthFilter>();

        app.MapGet("/{token}/from/{start}", (
                HttpContext context,
                CaptureService captures,
                string start,
                CancellationToken cancellationToken) =>
            captures.ServeAsync(context, ParseRange(start, "now"), follow: false, cancellationToken))
            .AddEndpointFilter<TokenAuthFilter>();

        app.MapGet("/{token}/status", (StatusReporter reporter) =>
                Results.Json(reporter.Build(), OkoJson.Default.StatusResponse))
            .AddEndpointFilter<TokenAuthFilter>();
    }

    /// <summary>An empty window: /live sends nothing historical, only what arrives from now on.</summary>
    private static Func<DateTime, TimeWindow> LiveOnly => now => new TimeWindow(now, now, null, IncludeHistory: false);

    private static Func<DateTime, TimeWindow> ParseLast(string duration) => now =>
        TimeParsing.TryParseDuration(duration, out TimeSpan window)
            ? new TimeWindow(now - window, now, null)
            : new TimeWindow(
                default,
                default,
                $"'{duration}' is not a valid duration. Expected {TimeParsing.AcceptedDurationForms}.");

    private static Func<DateTime, TimeWindow> ParseRange(string start, string end) => now =>
    {
        if (!TimeParsing.TryParseInstant(start, now, out DateTime fromUtc))
        {
            return new TimeWindow(
                default,
                default,
                $"'{start}' is not a valid time. Expected {TimeParsing.AcceptedInstantForms}. Times must be UTC.");
        }

        if (!TimeParsing.TryParseInstant(end, now, out DateTime toUtc))
        {
            return new TimeWindow(
                default,
                default,
                $"'{end}' is not a valid time. Expected {TimeParsing.AcceptedInstantForms}. Times must be UTC.");
        }

        return toUtc < fromUtc
            ? new TimeWindow(default, default, "The end of the range is before its start.")
            : new TimeWindow(fromUtc, toUtc, null);
    };

    internal sealed record TimeWindow(DateTime FromUtc, DateTime ToUtc, string? Error, bool IncludeHistory = true);

    /// <summary>Serves a capture response: history from the store, then optionally live packets.</summary>
    internal sealed class CaptureService(
        CaptureStore store,
        PcapngResponseWriter writer,
        LiveHub live,
        ILogger<CaptureService> logger)
    {
        public async Task<IResult> ServeAsync(
            HttpContext context,
            Func<DateTime, TimeWindow> parse,
            bool follow,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(parse);

            DateTime now = DateTime.UtcNow;
            TimeWindow window = parse(now);

            if (window.Error is not null)
            {
                return Results.Problem(detail: window.Error, statusCode: StatusCodes.Status400BadRequest);
            }

            // Subscribe before reading history so nothing arriving during the read is missed. Anything
            // already covered by the snapshot is filtered out afterwards by sequence number.
            LiveSubscription? subscription = null;
            if (follow)
            {
                subscription = live.TrySubscribe();
                if (subscription is null)
                {
                    return Results.Problem(
                        detail: "Too many live subscribers; raise OKO_LIVE_MAX_SUBSCRIBERS.",
                        statusCode: StatusCodes.Status503ServiceUnavailable);
                }
            }

            using (subscription)
            {
                CaptureSnapshot snapshot = store.Snapshot(window.FromUtc, window.ToUtc);

                PrepareResponse(context, window, follow);
                PipeWriter output = context.Response.BodyWriter;

                long bytes = 0;
                if (window.IncludeHistory)
                {
                    writer.WritePreamble(output, PcapngResponseWriter.DescribeQuery(window.FromUtc, window.ToUtc, follow));
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    bytes = await writer
                        .WriteSnapshotAsync(output, snapshot, window.FromUtc, window.ToUtc, cancellationToken)
                        .ConfigureAwait(false);
                }

                logger.LogInformation(
                    "Served {Bytes} bytes of history for {From:o}..{To:o} ({Segments} segment(s)){Follow}.",
                    bytes,
                    window.FromUtc,
                    window.ToUtc,
                    snapshot.Segments.Length,
                    follow ? ", following" : "");

                if (subscription is not null)
                {
                    await FollowAsync(context, output, subscription, snapshot.LastSequence, window, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            return Results.Empty;
        }

        /// <summary>
        /// Streams live batches until the client disconnects, skipping anything already emitted as
        /// history.
        /// </summary>
        internal async Task FollowAsync(
            HttpContext context,
            PipeWriter output,
            LiveSubscription subscription,
            ulong lastHistorySequence,
            TimeWindow window,
            CancellationToken cancellationToken)
        {
            try
            {
                // Live has its own pcapng section and the exact table captured when subscribing.
                // History may already know newer interfaces; mixing those tables in one section would
                // duplicate inline announcements and shift interface IDs.
                output.Write(subscription.Preamble);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);

                ulong fromNanoseconds = MonotonicClock.ToNanoseconds(window.FromUtc);
                ulong toNanoseconds = MonotonicClock.ToNanoseconds(window.ToUtc);
                await foreach (LiveBatch batch in subscription.Batches.ReadAllAsync(cancellationToken)
                    .ConfigureAwait(false))
                {
                    batch.WriteExcludingHistory(output, window.IncludeHistory ? lastHistorySequence : 0,
                        fromNanoseconds, toNanoseconds);
                    FlushResult result = await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (result.IsCompleted || result.IsCanceled)
                    {
                        break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // The client hung up, which is the normal way a live stream ends.
            }
            catch (LiveStreamOverflowException)
            {
                logger.LogWarning(
                    "Aborting incomplete live capture because its queue overflowed. Download history to recover.");
                // The response already started; a clean EOF would falsely claim a successful download.
                context.Abort();
            }
        }

        private static void PrepareResponse(HttpContext context, TimeWindow window, bool follow)
        {
            HttpResponse response = context.Response;
            response.StatusCode = StatusCodes.Status200OK;
            response.ContentType = PcapngContentType;

            // So a browser hit downloads a file that opens by double-click.
            string name = string.Create(
                CultureInfo.InvariantCulture,
                $"oko-{window.FromUtc:yyyyMMdd'T'HHmmss}{(follow ? "-live" : $"-{window.ToUtc:yyyyMMdd'T'HHmmss}")}.pcapng");
            response.Headers.ContentDisposition = $"attachment; filename=\"{name}\"";

            // A capture must never be served from a cache: the same URL means something different a
            // second later, and /last/10m is relative to now.
            response.Headers.CacheControl = "no-store";

            if (follow)
            {
                // Without this the response would sit in Kestrel's buffer and Wireshark would show
                // nothing until enough accumulated, which defeats the point of a live view.
                context.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();
            }
        }
    }
}
