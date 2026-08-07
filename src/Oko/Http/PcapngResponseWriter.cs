using System.Buffers;
using System.Globalization;
using System.IO.Pipelines;
using Oko.Capture;
using Oko.Pcapng;

namespace Oko.Http;

/// <summary>
/// Streams a pcapng capture assembled from segment files plus whatever is still in memory.
/// </summary>
/// <remarks>
/// <para>
/// The output is a single pcapng section: one SHB, then the whole interface table as IDBs, then packet
/// blocks in chronological order. Because interface IDs are globally stable and every segment stores
/// the table in the same order, an ID means the same sensor in every source, so nothing has to be
/// remapped.
/// </para>
/// <para>
/// A segment wholly inside the requested window is copied verbatim; only the segments straddling an
/// edge are walked block by block to trim packets outside it. That keeps the bulk of a large query at
/// copy speed while still answering the exact question that was asked.
/// </para>
/// </remarks>
internal sealed class PcapngResponseWriter(
    OkoOptions options,
    InterfaceTable interfaces,
    ILogger<PcapngResponseWriter> logger)
{
    private const int CopyBufferSize = 128 * 1024;

    /// <summary>
    /// Writes the SHB and interface table. Must precede any packet bytes: it is what tells a reader
    /// which sensor each interface ID refers to.
    /// </summary>
    public void WritePreamble(IBufferWriter<byte> output, string description)
    {
        PcapngWriter.WriteSectionHeader(output, OkoVersion.UserApplication, description);

        foreach (SensorInterface entry in interfaces.Snapshot())
        {
            PcapngWriter.WriteInterfaceDescription(
                output,
                entry.LinkType,
                (uint)options.SnapshotLength,
                entry.Name,
                entry.Description);
        }
    }

    /// <summary>Writes every packet in <paramref name="snapshot"/> within the window, oldest first.</summary>
    /// <returns>Bytes of packet data written.</returns>
    public async Task<long> WriteSnapshotAsync(
        PipeWriter output,
        CaptureSnapshot snapshot,
        DateTime fromUtc,
        DateTime toUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(snapshot);

        ulong fromNanoseconds = MonotonicClock.ToNanoseconds(fromUtc);
        ulong toNanoseconds = MonotonicClock.ToNanoseconds(toUtc);
        long written = 0;

        // Segments, then sealed blocks, then the active block. That is chronological: sequence numbers
        // increase monotonically, and a segment always holds older data than anything still in memory.
        foreach (SegmentRef segment in snapshot.Segments)
        {
            written += await WriteSegmentAsync(
                output,
                segment,
                fromUtc,
                toUtc,
                fromNanoseconds,
                toNanoseconds,
                cancellationToken).ConfigureAwait(false);
        }

        foreach (CaptureBlock block in snapshot.SealedBlocks)
        {
            written += WriteFilteredBlocks(output, block.WrittenSpan, fromNanoseconds, toNanoseconds);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        if (!snapshot.ActiveBlock.IsEmpty)
        {
            written += WriteFilteredBlocks(output, snapshot.ActiveBlock.Bytes, fromNanoseconds, toNanoseconds);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        return written;
    }

    private async Task<long> WriteSegmentAsync(
        PipeWriter output,
        SegmentRef segment,
        DateTime fromUtc,
        DateTime toUtc,
        ulong fromNanoseconds,
        ulong toNanoseconds,
        CancellationToken cancellationToken)
    {
        FileStream stream;
        try
        {
            // FileShare.Delete so retention removing this file mid-read cannot fail the request.
            stream = new FileStream(
                segment.Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                CopyBufferSize,
                FileOptions.SequentialScan | FileOptions.Asynchronous);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            // Retention evicted it between the snapshot and this read. That can only happen at the very
            // oldest edge of the window, where the data was being dropped anyway.
            logger.LogWarning("Segment {Path} disappeared while streaming; skipping it.", segment.Path);
            return 0;
        }

        await using (stream.ConfigureAwait(false))
        {
            long start;
            try
            {
                start = PcapngReader.FindFirstPacketBlockOffset(stream);
            }
            catch (Exception exception) when (exception is InvalidDataException or IOException)
            {
                // One unreadable segment must not abort a query spanning many.
                logger.LogError(exception, "Segment {Path} is unreadable; skipping it.", segment.Path);
                return 0;
            }

            if (start >= stream.Length)
            {
                return 0;
            }

            stream.Position = start;

            bool entirelyInsideWindow = segment.StartUtc >= fromUtc && segment.EndUtc <= toUtc;
            return entirelyInsideWindow
                ? await CopyVerbatimAsync(output, stream, cancellationToken).ConfigureAwait(false)
                : await CopyFilteredAsync(output, stream, fromNanoseconds, toNanoseconds, cancellationToken)
                    .ConfigureAwait(false);
        }
    }

    /// <summary>Bulk path: every packet in this segment is wanted, so the bytes go straight through.</summary>
    private static async Task<long> CopyVerbatimAsync(
        PipeWriter output,
        Stream source,
        CancellationToken cancellationToken)
    {
        long copied = 0;
        long remaining = source.Length - source.Position;

        while (remaining > 0)
        {
            Memory<byte> buffer = output.GetMemory(CopyBufferSize);
            int wanted = (int)Math.Min(buffer.Length, remaining);
            int read = await source.ReadAsync(buffer[..wanted], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            output.Advance(read);
            copied += read;
            remaining -= read;
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        return copied;
    }

    /// <summary>
    /// Edge path: read the segment and emit only the blocks inside the window. A segment is bounded by
    /// the flush threshold (8 MB by default) and at most two segments per query straddle an edge, so
    /// buffering one is cheaper than the bookkeeping a streaming block walk would need.
    /// </summary>
    private static async Task<long> CopyFilteredAsync(
        PipeWriter output,
        Stream source,
        ulong fromNanoseconds,
        ulong toNanoseconds,
        CancellationToken cancellationToken)
    {
        int length = (int)(source.Length - source.Position);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);

        try
        {
            await source.ReadExactlyAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            long written = WriteFilteredBlocks(output, buffer.AsSpan(0, length), fromNanoseconds, toNanoseconds);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            return written;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Copies the blocks in <paramref name="source"/> whose timestamps fall inside the window. Blocks
    /// that are not packet blocks pass through untouched, so an inline IDB is never dropped.
    /// </summary>
    /// <returns>Bytes written.</returns>
    private static long WriteFilteredBlocks(
        PipeWriter output,
        ReadOnlySpan<byte> source,
        ulong fromNanoseconds,
        ulong toNanoseconds)
    {
        long written = 0;
        int offset = 0;

        while (offset + PcapngReader.MinimumBlockLength <= source.Length)
        {
            ReadOnlySpan<byte> remainder = source[offset..];
            uint blockType = PcapngReader.ReadBlockType(remainder);
            uint totalLength = PcapngReader.ReadBlockTotalLength(remainder);

            if (totalLength < PcapngReader.MinimumBlockLength || offset + totalLength > source.Length)
            {
                break;
            }

            ReadOnlySpan<byte> block = remainder[..(int)totalLength];
            bool include = true;

            if (blockType == BlockType.EnhancedPacket && totalLength >= PcapngReader.EnhancedPacketFieldsLength)
            {
                ulong timestamp = PcapngReader.ReadEnhancedPacketTimestamp(block);
                include = timestamp >= fromNanoseconds && timestamp <= toNanoseconds;
            }

            if (include)
            {
                block.CopyTo(output.GetSpan(block.Length));
                output.Advance(block.Length);
                written += block.Length;
            }

            offset += (int)totalLength;
        }

        return written;
    }

    /// <summary>Human-readable description recorded in the response's SHB comment.</summary>
    public static string DescribeQuery(DateTime fromUtc, DateTime toUtc, bool follow) => string.Create(
        CultureInfo.InvariantCulture,
        $"Oko query {fromUtc:yyyy-MM-dd'T'HH:mm:ss.fff'Z'} .. {toUtc:yyyy-MM-dd'T'HH:mm:ss.fff'Z'}{(follow ? " then live" : "")}");
}
