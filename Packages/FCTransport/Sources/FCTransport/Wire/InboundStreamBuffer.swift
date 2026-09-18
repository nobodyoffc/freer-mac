import Foundation

/// Reassembly buffer for one inbound FUDP stream. Chunks arrive as
/// (offset, data) pairs, possibly out of order, duplicated, or
/// overlapping; `fin` on a chunk fixes the total length. Coverage is
/// tracked as merged [start, end) intervals, so completion is known
/// without sorting chunks on every append.
///
/// Small messages assemble in RAM. Once buffered bytes cross
/// `spillThreshold`, everything moves to a temp file written at chunk
/// offsets, and the assembled result is returned as **file-mapped**
/// `Data` — a multi-hundred-MB download never sits in anonymous
/// memory. The temp file is unlinked immediately after mapping (the
/// pages stay valid until the `Data` is released).
final class InboundStreamBuffer {

    enum Failure: Error, CustomStringConvertible {
        case spillIo(Error)
        case offsetOverflow(offset: UInt64, length: Int)
        case tooLarge(limit: UInt64)
        case tooFragmented(intervals: Int)
        case beyondFinalSize(offset: UInt64, length: Int, finalSize: UInt64)
        case conflictingFinalSize(had: UInt64, got: UInt64)

        var description: String {
            switch self {
            case .spillIo(let e): return "InboundStreamBuffer: spill file I/O — \(e)"
            case let .offsetOverflow(offset, length):
                return "InboundStreamBuffer: offset \(offset) + \(length) does not fit a 64-bit offset"
            case .tooLarge(let limit):
                return "InboundStreamBuffer: stream exceeds the \(limit)-byte ceiling"
            case .tooFragmented(let intervals):
                return "InboundStreamBuffer: \(intervals) disjoint ranges is more fragmentation than a stream may ask us to track"
            case let .beyondFinalSize(offset, length, finalSize):
                return "InboundStreamBuffer: \(offset)+\(length) is past the final size \(finalSize) a FIN already fixed"
            case let .conflictingFinalSize(had, got):
                return "InboundStreamBuffer: a second FIN declares final size \(got), contradicting \(had)"
            }
        }
    }

    /// Ceiling on a single stream's length.
    ///
    /// FUDP2V1 gives a stream an initial 100 MB limit that the receiver
    /// raises with MAX_STREAM_DATA as the application consumes; this
    /// client implements no flow-control frames, and its whole point is
    /// that a large download never sits in anonymous memory, so a
    /// literal 100 MB would refuse transfers the design exists to
    /// serve. This is therefore not flow control — it is the ceiling
    /// past which a declared length is an attack rather than a file.
    static let defaultMaxStreamBytes: UInt64 = 8 << 30   // 8 GiB

    /// Ceiling on how many *disjoint* ranges one stream may leave
    /// outstanding. Every arriving chunk is merged into this list, so an
    /// unbounded one is both the memory and the CPU cost of a peer that
    /// sends every other byte.
    static let defaultMaxIntervals = 4096

    /// Buffered bytes above which the stream spills to disk.
    static let defaultSpillThreshold = 8 * 1024 * 1024

    private let spillThreshold: Int
    private let maxStreamBytes: UInt64
    private let maxIntervals: Int
    private var ramChunks: [(offset: UInt64, data: Data)] = []
    private var ramBytes = 0
    private var spillHandle: FileHandle?
    private var spillURL: URL?

    /// Merged, sorted coverage intervals [start, end).
    private var covered: [(start: UInt64, end: UInt64)] = []
    private var finReceived = false
    private var totalLength: UInt64?

    init(
        spillThreshold: Int = InboundStreamBuffer.defaultSpillThreshold,
        maxStreamBytes: UInt64 = InboundStreamBuffer.defaultMaxStreamBytes,
        maxIntervals: Int = InboundStreamBuffer.defaultMaxIntervals
    ) {
        self.spillThreshold = spillThreshold
        self.maxStreamBytes = maxStreamBytes
        self.maxIntervals = maxIntervals
    }

    deinit {
        cleanup()
    }

    /// Append one chunk. Returns the count of NEW bytes (excluding
    /// overlap with already-received ranges) for progress reporting.
    @discardableResult
    func append(offset: UInt64, data: Data, fin: Bool) throws -> Int {
        // `offset` is a 64-bit field straight off the wire. Adding a
        // length to it wraps, and Swift traps on the wrap rather than
        // producing a wrong answer, so a peer could end the process by
        // naming an offset near the top of the range.
        let (end, overflowed) = offset.addingReportingOverflow(UInt64(data.count))
        guard !overflowed else {
            throw Failure.offsetOverflow(offset: offset, length: data.count)
        }
        guard end <= maxStreamBytes else { throw Failure.tooLarge(limit: maxStreamBytes) }

        // A FIN fixes the stream's length. Data past it, or a second
        // FIN naming a different length, is a peer contradicting
        // itself: taking the newer figure let a late frame redefine how
        // much of the message counted as "all of it".
        if let established = totalLength {
            if fin, end != established {
                throw Failure.conflictingFinalSize(had: established, got: end)
            }
            if end > established {
                throw Failure.beyondFinalSize(
                    offset: offset, length: data.count, finalSize: established
                )
            }
        }
        if fin {
            finReceived = true
            totalLength = end
        }

        let newRanges = newRanges(start: offset, end: end)
        let newBytes = newRanges.reduce(0) { $0 + Int($1.end - $1.start) }
        mergeInterval(start: offset, end: end)
        guard covered.count <= maxIntervals else {
            throw Failure.tooFragmented(intervals: covered.count)
        }

        if let handle = spillHandle {
            // **Only the bytes we did not already have.** Seeking to
            // the chunk's offset and writing all of it let a later
            // overlapping chunk rewrite bytes already received, so two
            // frames could each claim a different content for the same
            // range and the last one on the wire won. FUDP2V1 is
            // explicit that an overlapping portion MUST be discarded.
            for range in newRanges {
                let from = Int(range.start - offset)
                let to = Int(range.end - offset)
                try write(
                    chunk: data.subdata(in: (data.startIndex + from)..<(data.startIndex + to)),
                    at: range.start, to: handle
                )
            }
        } else {
            ramChunks.append((offset, data))
            ramBytes += data.count
            if ramBytes > spillThreshold {
                try spillToDisk()
            }
        }
        return newBytes
    }

    /// The sub-ranges of `[start, end)` not already covered, in order.
    private func newRanges(start: UInt64, end: UInt64) -> [(start: UInt64, end: UInt64)] {
        guard end > start else { return [] }
        var gaps: [(start: UInt64, end: UInt64)] = []
        var cursor = start
        for interval in covered where interval.end > start && interval.start < end {
            if interval.start > cursor { gaps.append((cursor, min(interval.start, end))) }
            cursor = max(cursor, interval.end)
            if cursor >= end { break }
        }
        if cursor < end { gaps.append((cursor, end)) }
        return gaps
    }

    /// Cumulative distinct bytes received so far.
    var receivedBytes: UInt64 {
        covered.reduce(0) { $0 + ($1.end - $1.start) }
    }

    /// The complete message once every byte of [0, totalLength) has
    /// arrived and `fin` was seen; nil while chunks are still missing.
    /// For spilled streams the returned `Data` is file-mapped.
    func assembleIfComplete() throws -> Data? {
        guard finReceived, let total = totalLength else { return nil }
        guard isFullyCovered(upTo: total) else { return nil }

        if let handle = spillHandle, let url = spillURL {
            do {
                try handle.close()
            } catch {
                throw Failure.spillIo(error)
            }
            spillHandle = nil
            let mapped: Data
            do {
                mapped = try Data(contentsOf: url, options: .alwaysMapped)
            } catch {
                throw Failure.spillIo(error)
            }
            // Unlink now — the mapping keeps the pages alive, and the
            // file must not outlive the transfer on failure paths.
            try? FileManager.default.removeItem(at: url)
            spillURL = nil
            return mapped.count == Int(total) ? mapped : nil
        }

        // RAM path: tile the sorted chunks, skipping overlap.
        let sorted = ramChunks.sorted { $0.offset < $1.offset }
        var assembled = Data(capacity: Int(total))
        for chunk in sorted {
            let pos = UInt64(assembled.count)
            if chunk.offset == pos {
                assembled.append(chunk.data)
            } else if chunk.offset < pos {
                let overlap = Int(pos - chunk.offset)
                if overlap < chunk.data.count {
                    assembled.append(chunk.data.dropFirst(overlap))
                }
            } else {
                return nil // gap — interval math said covered; defensive
            }
        }
        return assembled.count == Int(total) ? assembled : nil
    }

    /// Release the spill file if the stream is torn down incomplete.
    func cleanup() {
        try? spillHandle?.close()
        spillHandle = nil
        if let url = spillURL {
            try? FileManager.default.removeItem(at: url)
            spillURL = nil
        }
        ramChunks.removeAll()
        ramBytes = 0
    }

    // MARK: - private

    private func spillToDisk() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fudp-rx-\(UUID().uuidString).tmp")
        do {
            FileManager.default.createFile(atPath: url.path, contents: nil)
            let handle = try FileHandle(forWritingTo: url)
            for chunk in ramChunks {
                try write(chunk: chunk.data, at: chunk.offset, to: handle)
            }
            spillHandle = handle
            spillURL = url
            ramChunks.removeAll()
            ramBytes = 0
        } catch {
            try? FileManager.default.removeItem(at: url)
            throw Failure.spillIo(error)
        }
    }

    private func write(chunk: Data, at offset: UInt64, to handle: FileHandle) throws {
        do {
            try handle.seek(toOffset: offset)
            try handle.write(contentsOf: chunk)
        } catch {
            throw Failure.spillIo(error)
        }
    }

    /// Insert [start, end) into the merged interval list.
    private func mergeInterval(start: UInt64, end: UInt64) {
        guard end > start else { return }

        var merged: [(start: UInt64, end: UInt64)] = []
        var s = start
        var e = end

        for interval in covered {
            if interval.end < s || interval.start > e {
                merged.append(interval)
            } else {
                s = min(s, interval.start)
                e = max(e, interval.end)
            }
        }
        merged.append((s, e))
        merged.sort { $0.start < $1.start }
        covered = merged
    }

    private func isFullyCovered(upTo total: UInt64) -> Bool {
        guard let first = covered.first else { return total == 0 }
        return first.start == 0 && first.end >= total && covered.count == 1
    }
}
