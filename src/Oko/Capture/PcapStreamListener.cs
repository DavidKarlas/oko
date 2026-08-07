using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Oko.Pcapng;

namespace Oko.Capture;

/// <summary>
/// Accepts inbound classic-pcap streams over TCP, so an ordinary host can feed Oko with nothing more
/// than <c>tcpdump</c> and <c>socat</c>.
/// </summary>
/// <remarks>
/// <para>
/// This is the path for a Linux VM, and it is better than TZSP for that job in three ways. TCP does not
/// lose packets under burst, where UDP does. The pcap header declares its own link type, so
/// <c>tcpdump -i any</c> works — TZSP has no encapsulation code for Linux cooked capture and cannot
/// carry it at all. And nothing needs to be installed on the sending host.
/// </para>
/// <para>
/// Timestamps come from the stream rather than from arrival time, because the capturing kernel stamps
/// packets before any queuing delay. The cost is that a sender with a wrong clock produces
/// wrongly-dated captures, so skew is measured and reported rather than silently corrected — a query
/// for the last ten minutes not finding a skewed sender's packets is otherwise baffling.
/// </para>
/// <para>
/// Like the UDP ingest, this port is unauthenticated: anyone who can reach it can inject frames and
/// consume retention. Firewall it to the hosts that should be sending.
/// </para>
/// </remarks>
internal sealed class PcapStreamListener(
    OkoOptions options,
    CaptureStore store,
    InterfaceTable interfaces,
    IngestStats stats,
    LiveHub live,
    ILogger<PcapStreamListener> logger) : BackgroundService
{
    /// <summary>Clock difference beyond which a sender's timestamps are worth complaining about.</summary>
    private static readonly TimeSpan ClockSkewWarningThreshold = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.PcapTcpPort == 0)
        {
            logger.LogInformation("pcap TCP ingest is disabled (OKO_PCAP_TCP_PORT=0).");
            return;
        }

        using var listener = new Socket(options.BindAddressFamily, SocketType.Stream, ProtocolType.Tcp);

        if (options.BindAddressFamily == AddressFamily.InterNetworkV6)
        {
            listener.DualMode = options.UseDualStack;
        }

        listener.Bind(new IPEndPoint(options.BindAddress, options.PcapTcpPort));
        listener.Listen(backlog: 16);

        logger.LogInformation(
            "Accepting pcap streams on {Endpoint} (TCP). Send with: {Example}",
            listener.LocalEndPoint,
            $"tcpdump -i any -U -w - 'not (host <oko> and tcp port {options.PcapTcpPort})' " +
            $"| socat - TCP:<oko>:{options.PcapTcpPort}");

        var connections = new List<Task>();

        while (!stoppingToken.IsCancellationRequested)
        {
            Socket connection;
            try
            {
                connection = await listener.AcceptAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException exception)
            {
                logger.LogDebug(exception, "Recoverable error accepting a pcap stream.");
                continue;
            }

            connections.RemoveAll(task => task.IsCompleted);
            connections.Add(ServeAsync(connection, stoppingToken));
        }

        await Task.WhenAll(connections).ConfigureAwait(false);
        logger.LogInformation("pcap TCP listener stopped.");
    }

    private async Task ServeAsync(Socket connection, CancellationToken stoppingToken)
    {
        IPAddress peer = connection.RemoteEndPoint is IPEndPoint endpoint
            ? endpoint.Address
            : IPAddress.None;

        long framesFromThisPeer = 0;

        try
        {
            using (connection)
            await using (var stream = new NetworkStream(connection, ownsSocket: false))
            {
                framesFromThisPeer = await ReadStreamAsync(stream, peer, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (UnsupportedCaptureStreamException exception)
        {
            // Almost always a misconfigured sender, so say exactly what is wrong at a visible level.
            stats.RecordPcapStreamError();
            logger.LogError("Rejected pcap stream from {Peer}: {Reason}", peer, exception.Message);
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
        catch (Exception exception) when (exception is IOException or SocketException)
        {
            // The sender went away, which is how these connections normally end.
            logger.LogInformation(
                "pcap stream from {Peer} ended after {Frames} frame(s): {Reason}",
                peer,
                framesFromThisPeer,
                exception.Message);
            return;
        }

        logger.LogInformation("pcap stream from {Peer} closed after {Frames} frame(s).", peer, framesFromThisPeer);
    }

    private async Task<long> ReadStreamAsync(Stream stream, IPAddress peer, CancellationToken stoppingToken)
    {
        var globalHeader = new byte[PcapStreamReader.GlobalHeaderLength];
        await stream.ReadExactlyAsync(globalHeader, stoppingToken).ConfigureAwait(false);

        PcapStreamHeader header = PcapStreamReader.ParseGlobalHeader(globalHeader);
        SensorInterface sensor = interfaces.Resolve(peer, header.LinkType);

        logger.LogInformation(
            "pcap stream from {Peer}: {LinkType}, snaplen {SnapshotLength}, {Resolution} timestamps -> interface {Id}.",
            peer,
            LinkTypeMapDescription(header.LinkType),
            header.SnapshotLength,
            header.NanosecondTimestamps ? "nanosecond" : "microsecond",
            sensor.Id);

        var packetHeader = new byte[PcapStreamReader.PacketHeaderLength];
        byte[] frame = ArrayPool<byte>.Shared.Rent(64 * 1024);
        long frames = 0;
        bool warnedAboutSkew = false;

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                int read = await stream
                    .ReadAtLeastAsync(packetHeader, packetHeader.Length, throwOnEndOfStream: false, stoppingToken)
                    .ConfigureAwait(false);

                if (read == 0)
                {
                    break; // clean end of stream
                }

                if (read < packetHeader.Length)
                {
                    throw new UnsupportedCaptureStreamException(
                        "stream ended part-way through a packet header");
                }

                PcapPacketHeader packet = PcapStreamReader.ParsePacketHeader(packetHeader, header);

                if (frame.Length < packet.CapturedLength)
                {
                    ArrayPool<byte>.Shared.Return(frame);
                    frame = ArrayPool<byte>.Shared.Rent(packet.CapturedLength);
                }

                await stream
                    .ReadExactlyAsync(frame.AsMemory(0, packet.CapturedLength), stoppingToken)
                    .ConfigureAwait(false);

                stats.RecordDatagram(PcapStreamReader.PacketHeaderLength + packet.CapturedLength);

                if (packet.CapturedLength == 0)
                {
                    stats.RecordEmptyPayload();
                    continue;
                }

                warnedAboutSkew = Store(sensor, header.LinkType, packet, frame, peer, warnedAboutSkew);
                frames++;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(frame);
        }

        return frames;
    }

    private bool Store(
        SensorInterface sensor,
        ushort linkType,
        PcapPacketHeader packet,
        byte[] buffer,
        IPAddress peer,
        bool warnedAboutSkew)
    {
        ReadOnlySpan<byte> payload = buffer.AsSpan(0, packet.CapturedLength);
        uint originalLength = packet.OriginalLength;

        if (options.SnapshotLength > 0 && payload.Length > options.SnapshotLength)
        {
            payload = payload[..options.SnapshotLength];
            stats.RecordTruncatedFrame();
        }

        // Backstop for a sender whose filter fails to exclude its own stream. oko-tap makes this
        // impossible by construction, but a hand-written pipeline can still create a runaway loop.
        if (FrameInspector.TryGetDestinationPort(payload, linkType, out ushort destinationPort) &&
            (destinationPort == options.PcapTcpPort || destinationPort == options.UdpPort))
        {
            stats.RecordCaptureLoopSuspect();
        }

        ulong timestamp = packet.TimestampNanoseconds;
        DateTime captured = MonotonicClock.ToUtc(timestamp);

        if (!warnedAboutSkew && (DateTime.UtcNow - captured).Duration() > ClockSkewWarningThreshold)
        {
            warnedAboutSkew = true;
            stats.RecordClockSkew();
            logger.LogWarning(
                "Timestamps from {Peer} are {Skew} away from this host's clock (first packet stamped {Captured:o}). " +
                "Oko keeps the sender's timestamps, so time-range queries will look wrong until its clock is fixed.",
                peer,
                (DateTime.UtcNow - captured).Duration(),
                captured);
        }

        ulong sequence = store.Append(sensor.Id, timestamp, payload, originalLength);
        live.Publish(sensor.Id, timestamp, payload, originalLength, sequence);
        stats.RecordStoredFrame(sensor.Id, sensor.Name, linkType, payload.Length, captured);

        return warnedAboutSkew;
    }

    private static string LinkTypeMapDescription(ushort linkType) => Tzsp.LinkTypeMap.DescribeLinkType(linkType);
}
