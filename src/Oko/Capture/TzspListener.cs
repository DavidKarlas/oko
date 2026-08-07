using System.Net;
using System.Net.Sockets;
using Oko.Tzsp;

namespace Oko.Capture;

/// <summary>
/// Receives TZSP datagrams and turns them into pcapng packet blocks.
/// </summary>
/// <remarks>
/// A single receive loop on a dedicated task. At Oko's design target of 50k pps the bottleneck is the
/// kernel, not this code, so there is no need for multiple <c>SO_REUSEPORT</c> sockets; the loop is
/// kept allocation-free anyway so that headroom is not spent on garbage.
/// </remarks>
internal sealed class TzspListener(
    OkoOptions options,
    CaptureStore store,
    InterfaceTable interfaces,
    MonotonicClock clock,
    IngestStats stats,
    LiveHub live,
    ILogger<TzspListener> logger) : BackgroundService
{
    /// <summary>Resolving the sender's address allocates, and a sensor's address never changes.</summary>
    private SocketAddress? _cachedSocketAddress;
    private ushort _cachedLinkType;
    private uint _cachedInterfaceId;
    private string _cachedAddressText = string.Empty;

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.Factory.StartNew(
            () => ReceiveLoopAsync(stoppingToken),
            stoppingToken,
            TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
            TaskScheduler.Default).Unwrap();

    private async Task ReceiveLoopAsync(CancellationToken stoppingToken)
    {
        using Socket socket = CreateSocket();

        var buffer = new byte[OkoOptions.MaxDatagramSize];
        var senderAddress = new SocketAddress(socket.AddressFamily);

        logger.LogInformation(
            "Listening for TZSP on {Endpoint} (UDP), receive buffer {ReceiveBuffer} bytes.",
            socket.LocalEndPoint,
            socket.ReceiveBufferSize);

        while (!stoppingToken.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await socket
                    .ReceiveFromAsync(buffer, SocketFlags.None, senderAddress, stoppingToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException exception)
            {
                // A datagram larger than the buffer, an ICMP error, or a transient interface problem.
                // None of these are worth stopping the collector for.
                stats.RecordReceiveError();
                logger.LogDebug(exception, "Recoverable socket error while receiving.");
                continue;
            }

            stats.RecordDatagram(received);
            Process(buffer.AsSpan(0, received), senderAddress);
        }

        logger.LogInformation("TZSP listener stopped.");
    }

    private void Process(ReadOnlySpan<byte> datagram, SocketAddress senderAddress)
    {
        TzspParseResult result = TzspParser.TryParse(datagram, out TzspFrame frame);
        if (result != TzspParseResult.Ok)
        {
            stats.RecordParseError(result);
            return;
        }

        // Types 3/4/5 are configuration and NAT-keepalive frames. Keepalives are a useful liveness
        // signal, so they are counted rather than lumped in with errors.
        if (!frame.CarriesFrame)
        {
            stats.RecordKeepalive();
            return;
        }

        if (frame.PayloadLength == 0)
        {
            stats.RecordEmptyPayload();
            return;
        }

        if (!LinkTypeMap.TryResolve(frame.Encapsulation, out ushort linkType))
        {
            stats.RecordUnsupportedEncapsulation();
            return;
        }

        ReadOnlySpan<byte> payload = datagram.Slice(frame.PayloadOffset, frame.PayloadLength);
        uint originalLength = frame.OriginalLength;

        if (options.SnapshotLength > 0 && payload.Length > options.SnapshotLength)
        {
            payload = payload[..options.SnapshotLength];
            stats.RecordTruncatedFrame();
        }

        (uint interfaceId, string addressText) = ResolveInterface(frame, senderAddress, linkType);
        ulong timestamp = clock.NextTimestampNanoseconds();

        ulong sequence = store.Append(interfaceId, timestamp, payload, originalLength);
        live.Publish(interfaceId, timestamp, payload, originalLength, sequence);

        stats.RecordStoredFrame(interfaceId, addressText, linkType, payload.Length, MonotonicClock.ToUtc(timestamp));
    }

    /// <summary>
    /// Maps this datagram to a pcapng interface, using a one-entry cache because in the overwhelmingly
    /// common case every datagram comes from the same sensor with the same link type.
    /// </summary>
    private (uint InterfaceId, string AddressText) ResolveInterface(
        TzspFrame frame,
        SocketAddress senderAddress,
        ushort linkType)
    {
        if (linkType == _cachedLinkType &&
            _cachedSocketAddress is not null &&
            _cachedSocketAddress.Equals(senderAddress) &&
            !frame.HasSensorAddress)
        {
            return (_cachedInterfaceId, _cachedAddressText);
        }

        // TAG_SENSOR wins when present: with a NAT in the path the datagram's source address is the
        // NAT's, but the sensor knows its own identity.
        IPAddress address = frame.HasSensorAddress
            ? frame.GetSensorAddress()
            : ResolveSenderAddress(senderAddress);

        // Use the table's canonical name, not the raw address: a dual-mode socket reports IPv4 senders
        // as ::ffff:a.b.c.d, and reporting that while the IDB says a.b.c.d is just confusing.
        SensorInterface resolved = interfaces.Resolve(address, linkType);

        if (!frame.HasSensorAddress)
        {
            _cachedSocketAddress = CloneSocketAddress(senderAddress);
            _cachedLinkType = linkType;
            _cachedInterfaceId = resolved.Id;
            _cachedAddressText = resolved.Name;
        }

        return (resolved.Id, resolved.Name);
    }

    private static IPAddress ResolveSenderAddress(SocketAddress senderAddress)
    {
        EndPoint template = senderAddress.Family == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

        return ((IPEndPoint)template.Create(senderAddress)).Address;
    }

    private static SocketAddress CloneSocketAddress(SocketAddress source)
    {
        var clone = new SocketAddress(source.Family, source.Size);
        source.Buffer.Span[..source.Size].CopyTo(clone.Buffer.Span);
        return clone;
    }

    private Socket CreateSocket()
    {
        // Binding IPv6Any in dual mode accepts both stacks on one socket. IPv4 senders then arrive as
        // ::ffff:a.b.c.d, which InterfaceTable normalises so a router does not get two interface IDs
        // depending on how Oko happened to be bound. The family and address come from OkoOptions so this
        // listener and the pcap TCP listener cannot disagree about them.
        var socket = new Socket(options.BindAddressFamily, SocketType.Dgram, ProtocolType.Udp);

        try
        {
            if (socket.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = options.UseDualStack;
            }

            socket.ReceiveBufferSize = options.SocketReceiveBuffer;
            socket.Bind(new IPEndPoint(options.BindAddress, options.UdpPort));

            if (socket.ReceiveBufferSize < options.SocketReceiveBuffer)
            {
                logger.LogWarning(
                    "Asked for a {Requested}-byte socket receive buffer but the kernel granted {Granted}. " +
                    "net.core.rmem_max is a global sysctl and is not namespaced, so raise it on the host " +
                    "(sysctl -w net.core.rmem_max={Requested}) or bursts will be dropped before Oko sees them.",
                    options.SocketReceiveBuffer,
                    socket.ReceiveBufferSize,
                    options.SocketReceiveBuffer);
            }

            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
