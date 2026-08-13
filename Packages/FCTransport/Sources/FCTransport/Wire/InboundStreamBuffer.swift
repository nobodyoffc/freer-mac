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

        var description: String {
            switch self {
            case .spillIo(let e): return "InboundStreamBuffer: spill file I/O — \(e)"
            }
        }
    }

    /// Buffered bytes above which the stream spills to disk.
    static let defaultSpillThreshold = 8 * 1024 * 1024

    private let spillThreshold: Int
    private var ramChunks: [(offset: UInt64, data: Data)] = []
    private var ramBytes = 0
    private var spillHandle: FileHandle?
    private var spillURL: URL?

    /// Merged, sorted coverage intervals [start, end).
    private var covered: [(start: UInt64, end: UInt64)] = []
    private var finReceived = false
    private var totalLength: UInt64?

    init(spillThreshold: Int = InboundStreamBuffer.defaultSpillThreshold) {
        self.spillThreshold = spillThreshold
    }

    deinit {
        cleanup()
    }

    /// Append one chunk. Returns the count of NEW bytes (excluding
    /// overlap with already-received ranges) for progress reporting.
    @discardableResult
    func append(offset: UInt64, data: Data, fin: Bool) throws -> Int {
        if fin {
            finReceived = true
            totalLength = offset + UInt64(data.count)
        }
        let newBytes = mergeInterval(start: offset, end: offset + UInt64(data.count))

        if let handle = spillHandle {
            try write(chunk: data, at: offset, to: handle)
        } else {
            ramChunks.append((offset, data))
            ramBytes += data.count
            if ramBytes > spillThreshold {
                try spillToDisk()
            }
        }
        return newBytes
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

    /// Insert [start, end) into the merged interval list. Returns how
    /// many bytes were not already covered.
    private func mergeInterval(start: UInt64, end: UInt64) -> Int {
        guard end > start else { return 0 }

        var newBytes = Int(end - start)
        var merged: [(start: UInt64, end: UInt64)] = []
        var s = start
        var e = end

        for interval in covered {
            if interval.end < s || interval.start > e {
                merged.append(interval)
            } else {
                // Overlapping/adjacent: subtract the overlap from newBytes.
                let overlapStart = max(interval.start, start)
                let overlapEnd = min(interval.end, end)
                if overlapEnd > overlapStart {
                    newBytes -= Int(overlapEnd - overlapStart)
                }
                s = min(s, interval.start)
                e = max(e, interval.end)
            }
        }
        merged.append((s, e))
        merged.sort { $0.start < $1.start }
        covered = merged
        return max(0, newBytes)
    }

    private func isFullyCovered(upTo total: UInt64) -> Bool {
        guard let first = covered.first else { return total == 0 }
        return first.start == 0 && first.end >= total && covered.count == 1
    }
}
