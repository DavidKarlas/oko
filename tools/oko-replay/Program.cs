using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

// oko-replay — reads a capture file and re-sends its frames as TZSP, standing in for a MikroTik router.
//
// Useful for two things: checking an Oko deployment end to end without touching real hardware, and
// demonstrating the curl | wireshark workflow with traffic you already have.
//
//   oko-replay <capture.pcap|.pcapng> <host> [port] [--rate <pps>] [--loop] [--sensor <a.b.c.d>]

return Replay.Run(args);

internal static class Replay
{
    private const int DefaultPort = 37008;

    /// <summary>Leaves room for the TZSP header inside a typical 1500-byte path MTU.</summary>
    private const int MaxFrameLength = 1400;

    public static int Run(string[] args)
    {
        if (args.Length < 2 || args.Contains("--help") || args.Contains("-h"))
        {
            Console.Error.WriteLine("""
                usage: oko-replay <capture> <host> [port] [options]

                  <capture>          a .pcap or .pcapng file to replay
                  <host>             the Oko collector's address
                  [port]             UDP port (default 37008)

                options:
                  --rate <pps>       packets per second (default 1000, 0 = as fast as possible)
                  --loop             replay forever
                  --sensor <ip>      add TAG_SENSOR so Oko attributes frames to this address
                                     instead of the sending host
                """);
            return 64; // EX_USAGE
        }

        string capturePath = args[0];
        string host = args[1];
        int port = args.Length > 2 && int.TryParse(args[2], CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : DefaultPort;

        int rate = ReadIntOption(args, "--rate", 1000);
        bool loop = args.Contains("--loop");
        IPAddress? sensor = ReadOption(args, "--sensor") is { } text && IPAddress.TryParse(text, out IPAddress? parsedSensor)
            ? parsedSensor
            : null;

        if (!File.Exists(capturePath))
        {
            Console.Error.WriteLine($"oko-replay: '{capturePath}' not found");
            return 66; // EX_NOINPUT
        }

        List<byte[]> frames;
        try
        {
            frames = CaptureFile.ReadFrames(capturePath, MaxFrameLength);
        }
        catch (InvalidDataException exception)
        {
            Console.Error.WriteLine($"oko-replay: {exception.Message}");
            return 65; // EX_DATAERR
        }

        if (frames.Count == 0)
        {
            Console.Error.WriteLine("oko-replay: the capture contains no Ethernet frames to replay");
            return 65;
        }

        Console.WriteLine(
            $"Replaying {frames.Count} frame(s) from {Path.GetFileName(capturePath)} " +
            $"to {host}:{port} at {(rate == 0 ? "full speed" : $"{rate} pps")}{(loop ? ", looping" : "")}.");

        using var client = new UdpClient();
        client.Connect(host, port);

        long sent = 0;
        var stopwatch = Stopwatch.StartNew();
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancellation.Cancel();
        };

        do
        {
            foreach (byte[] frame in frames)
            {
                if (cancellation.IsCancellationRequested)
                {
                    break;
                }

                byte[] datagram = Tzsp.Wrap(frame, sensor);
                client.Send(datagram, datagram.Length);
                sent++;

                if (rate > 0)
                {
                    Pace(stopwatch, sent, rate);
                }
            }
        }
        while (loop && !cancellation.IsCancellationRequested);

        Console.WriteLine(
            $"Sent {sent} frame(s) in {stopwatch.Elapsed.TotalSeconds:F1}s " +
            $"({sent / Math.Max(stopwatch.Elapsed.TotalSeconds, 0.001):F0} pps).");

        return 0;
    }

    /// <summary>Sleeps only when ahead of schedule, so the average rate holds without busy-waiting.</summary>
    private static void Pace(Stopwatch stopwatch, long sent, int rate)
    {
        TimeSpan due = TimeSpan.FromSeconds((double)sent / rate);
        TimeSpan ahead = due - stopwatch.Elapsed;

        if (ahead > TimeSpan.FromMilliseconds(1))
        {
            Thread.Sleep(ahead);
        }
    }

    private static string? ReadOption(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static int ReadIntOption(string[] args, string name, int fallback) =>
        ReadOption(args, name) is { } text && int.TryParse(text, CultureInfo.InvariantCulture, out int value)
            ? value
            : fallback;
}

/// <summary>Builds TZSP datagrams the way a sensor would.</summary>
internal static class Tzsp
{
    private const byte Version = 1;
    private const byte TypeReceived = 0;
    private const ushort EncapsulationEthernet = 1;
    private const byte TagEnd = 1;
    private const byte TagSensor = 60;
    private const byte TagOriginalLength = 41;

    public static byte[] Wrap(byte[] frame, IPAddress? sensor, int originalLength = 0)
    {
        int headerLength = 4
            + (sensor is null ? 0 : 6)
            + (originalLength > 0 ? 4 : 0)
            + 1;

        var datagram = new byte[headerLength + frame.Length];
        var cursor = datagram.AsSpan();

        cursor[0] = Version;
        cursor[1] = TypeReceived;
        BinaryPrimitives.WriteUInt16BigEndian(cursor[2..], EncapsulationEthernet);
        int offset = 4;

        if (sensor is not null)
        {
            datagram[offset++] = TagSensor;
            datagram[offset++] = 4;
            sensor.GetAddressBytes().CopyTo(datagram, offset);
            offset += 4;
        }

        if (originalLength > 0)
        {
            datagram[offset++] = TagOriginalLength;
            datagram[offset++] = 2;
            BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(offset), (ushort)originalLength);
            offset += 2;
        }

        datagram[offset++] = TagEnd;
        frame.CopyTo(datagram, offset);
        return datagram;
    }
}

/// <summary>Reads Ethernet frames out of a pcap or pcapng file.</summary>
internal static class CaptureFile
{
    private const uint PcapMagicMicroseconds = 0xA1B2C3D4;
    private const uint PcapMagicNanoseconds = 0xA1B23C4D;
    private const uint PcapMagicSwappedMicroseconds = 0xD4C3B2A1;
    private const uint PcapMagicSwappedNanoseconds = 0x4D3CB2A1;
    private const uint PcapngSectionHeader = 0x0A0D0D0A;
    private const uint PcapngEnhancedPacket = 0x00000006;
    private const uint PcapngSimplePacket = 0x00000003;

    public static List<byte[]> ReadFrames(string path, int maxFrameLength)
    {
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length < 4)
        {
            throw new InvalidDataException($"'{path}' is too short to be a capture file");
        }

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(bytes);

        return magic switch
        {
            PcapngSectionHeader => ReadPcapng(bytes, maxFrameLength),
            PcapMagicMicroseconds or PcapMagicNanoseconds => ReadPcap(bytes, maxFrameLength, swapped: false),
            PcapMagicSwappedMicroseconds or PcapMagicSwappedNanoseconds =>
                ReadPcap(bytes, maxFrameLength, swapped: true),
            _ => throw new InvalidDataException(
                $"'{path}' is neither pcap nor pcapng (leading bytes 0x{magic:X8})"),
        };
    }

    private static List<byte[]> ReadPcap(byte[] bytes, int maxFrameLength, bool swapped)
    {
        var frames = new List<byte[]>();
        int offset = 24; // global header

        while (offset + 16 <= bytes.Length)
        {
            uint capturedLength = ReadUInt32(bytes, offset + 8, swapped);
            offset += 16;

            if (capturedLength == 0 || offset + capturedLength > bytes.Length)
            {
                break;
            }

            Add(frames, bytes.AsSpan(offset, (int)capturedLength), maxFrameLength);
            offset += (int)capturedLength;
        }

        return frames;
    }

    private static List<byte[]> ReadPcapng(byte[] bytes, int maxFrameLength)
    {
        var frames = new List<byte[]>();
        int offset = 0;

        while (offset + 12 <= bytes.Length)
        {
            uint blockType = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
            uint totalLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4));

            if (totalLength < 12 || offset + totalLength > bytes.Length)
            {
                break;
            }

            if (blockType == PcapngEnhancedPacket && totalLength >= 32)
            {
                uint capturedLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 20));
                if (capturedLength > 0 && offset + 28 + capturedLength <= bytes.Length)
                {
                    Add(frames, bytes.AsSpan(offset + 28, (int)capturedLength), maxFrameLength);
                }
            }
            else if (blockType == PcapngSimplePacket && totalLength >= 16)
            {
                int capturedLength = (int)totalLength - 16;
                if (capturedLength > 0)
                {
                    Add(frames, bytes.AsSpan(offset + 12, capturedLength), maxFrameLength);
                }
            }

            offset += (int)totalLength;
        }

        return frames;
    }

    /// <summary>
    /// Truncates over-long frames rather than skipping them: a real sensor does the same when the frame
    /// exceeds the path MTU, so this keeps the replay representative.
    /// </summary>
    private static void Add(List<byte[]> frames, ReadOnlySpan<byte> frame, int maxFrameLength) =>
        frames.Add(frame[..Math.Min(frame.Length, maxFrameLength)].ToArray());

    private static uint ReadUInt32(byte[] bytes, int offset, bool swapped) =>
        swapped
            ? BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset))
            : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
}
