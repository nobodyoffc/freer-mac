#if os(macOS)
import AppKit
#else
import UIKit
#endif
import AVFoundation
import CoreMedia
import SwiftUI
import Vision

/// Live camera QR scanning. macOS has no `.qr` metadata type on
/// `AVCaptureMetadataOutput` (that detector is iOS-only), so frames
/// come in through `AVCaptureVideoDataOutput` and are scanned with
/// Vision's `VNDetectBarcodesRequest` — the same detector
/// ``QrCoder/decode(cgImage:)`` uses for image files.
///
/// Same rhythm as the Android `QrCodeActivity` camera path: one
/// successful read fires ``onCode`` once and pauses the session, so
/// multi-part payloads are collected one deliberate scan at a time
/// (the caller re-arms with ``start()``).
public final class QrCameraController: NSObject, ObservableObject,
                                        AVCaptureVideoDataOutputSampleBufferDelegate {

    public let session: AVCaptureSession

    /// The one preview layer for this controller. Created eagerly —
    /// before the session ever runs — because attaching a preview
    /// layer mutates the running session's connection graph while the
    /// capture thread enumerates it (NSException: "Collection
    /// __NSArrayM was mutated while being enumerated"). SwiftUI
    /// recreates the preview *view* on every appearance, so the view
    /// only re-parents this layer and never touches the session.
    public let previewLayer: AVCaptureVideoPreviewLayer

    /// True between a successful `start()` and `stop()` / a read.
    @Published public private(set) var isRunning = false
    /// Camera permission was denied or restricted — the UI should
    /// point at System Settings › Privacy & Security › Camera.
    @Published public private(set) var permissionDenied = false
    /// Non-permission setup problem (no camera, config failure).
    @Published public private(set) var setupError: String?

    /// Fired on the main queue with the decoded string, once per
    /// armed scan.
    public var onCode: ((String) -> Void)?

    private var configured = false
    /// Guards `armed`: written from the main queue, read/taken from
    /// the frame queue.
    private let armedLock = NSLock()
    private var armed = false
    /// `startRunning()` / `stopRunning()` block, so they run here.
    private let workQueue = DispatchQueue(label: "fcui.qr.camera")
    /// Frame delivery + Vision detection.
    private let frameQueue = DispatchQueue(label: "fcui.qr.camera.frames")
    /// Detection throttle — only touched on `frameQueue`.
    private var lastDetection = Date.distantPast

    override public init() {
        let session = AVCaptureSession()
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        self.session = session
        self.previewLayer = layer
        super.init()
    }

    /// Ask for permission if needed, configure once, start the
    /// session, and arm the next read.
    public func start() {
        setupError = nil
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            beginSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    if granted {
                        self.beginSession()
                    } else {
                        self.permissionDenied = true
                    }
                }
            }
        default:
            permissionDenied = true
        }
    }

    public func stop() {
        setArmed(false)
        isRunning = false
        workQueue.async { [session] in
            if session.isRunning { session.stopRunning() }
        }
    }

    private func beginSession() {
        if !configured {
            guard configure() else { return }
            configured = true
        }
        setArmed(true)
        isRunning = true
        workQueue.async { [session] in
            if !session.isRunning { session.startRunning() }
        }
    }

    private func configure() -> Bool {
        session.beginConfiguration()
        defer { session.commitConfiguration() }

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else {
            setupError = String(localized: "No usable camera found.")
            return false
        }
        session.addInput(input)

        let output = AVCaptureVideoDataOutput()
        output.alwaysDiscardsLateVideoFrames = true
        output.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA
        ]
        output.setSampleBufferDelegate(self, queue: frameQueue)
        guard session.canAddOutput(output) else {
            setupError = String(localized: "Camera does not support video capture.")
            return false
        }
        session.addOutput(output)
        return true
    }

    // MARK: - armed flag

    private func setArmed(_ value: Bool) {
        armedLock.lock()
        armed = value
        armedLock.unlock()
    }

    /// Atomically consume the armed flag — exactly one frame wins.
    private func takeArmed() -> Bool {
        armedLock.lock()
        defer { armedLock.unlock() }
        guard armed else { return false }
        armed = false
        return true
    }

    private var isArmed: Bool {
        armedLock.lock()
        defer { armedLock.unlock() }
        return armed
    }

    // MARK: - AVCaptureVideoDataOutputSampleBufferDelegate (frameQueue)

    public func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        guard isArmed else { return }

        // ~6 detections/sec is plenty for a hand-held code and keeps
        // Vision off the other frames.
        let now = Date()
        guard now.timeIntervalSince(lastDetection) >= 0.15 else { return }
        lastDetection = now

        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try? VNImageRequestHandler(cvPixelBuffer: pixelBuffer, options: [:])
            .perform([request])

        guard let payload = request.results?
                  .compactMap(\.payloadStringValue)
                  .first,
              takeArmed()
        else { return }

        DispatchQueue.main.async {
            self.stop()
            self.onCode?(payload)
        }
    }
}

/// AppKit-backed live preview hosting a ``QrCameraController``'s
/// persistent ``QrCameraController/previewLayer``. Only re-parents
/// the layer — it must never construct a preview layer of its own,
/// because attaching a new layer to a running session crashes the
/// capture thread (see the controller's `previewLayer` doc).
#if os(macOS)
public struct QrCameraPreview: NSViewRepresentable {
    private let layer: AVCaptureVideoPreviewLayer

    public init(layer: AVCaptureVideoPreviewLayer) {
        self.layer = layer
    }

    public func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.wantsLayer = true
        layer.removeFromSuperlayer()
        layer.frame = view.bounds
        layer.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        view.layer?.addSublayer(layer)
        return view
    }

    public func updateNSView(_ nsView: NSView, context: Context) {}

    public static func dismantleNSView(_ nsView: NSView, coordinator: ()) {
        nsView.layer?.sublayers?
            .compactMap { $0 as? AVCaptureVideoPreviewLayer }
            .forEach { $0.removeFromSuperlayer() }
    }
}
#else
public struct QrCameraPreview: UIViewRepresentable {
    private let layer: AVCaptureVideoPreviewLayer

    public init(layer: AVCaptureVideoPreviewLayer) {
        self.layer = layer
    }

    public func makeUIView(context: Context) -> UIView {
        let view = PreviewHost()
        layer.removeFromSuperlayer()
        view.layer.addSublayer(layer)
        return view
    }

    public func updateUIView(_ uiView: UIView, context: Context) {}

    public static func dismantleUIView(_ uiView: UIView, coordinator: ()) {
        uiView.layer.sublayers?
            .compactMap { $0 as? AVCaptureVideoPreviewLayer }
            .forEach { $0.removeFromSuperlayer() }
    }

    /// A CALayer has no autoresizing on iOS, so the host lays the
    /// preview out itself — and turns the picture upright, since the
    /// sensor delivers landscape frames whichever way the phone is held.
    private final class PreviewHost: UIView {
        override func layoutSubviews() {
            super.layoutSubviews()
            for case let preview as AVCaptureVideoPreviewLayer in layer.sublayers ?? [] {
                preview.frame = bounds
                guard let connection = preview.connection else { continue }
                let angle = Self.rotation(for: window?.windowScene?.interfaceOrientation ?? .portrait)
                if connection.isVideoRotationAngleSupported(angle) {
                    connection.videoRotationAngle = angle
                }
            }
        }

        private static func rotation(for orientation: UIInterfaceOrientation) -> CGFloat {
            switch orientation {
            case .landscapeRight: return 0
            case .landscapeLeft: return 180
            case .portraitUpsideDown: return 270
            default: return 90
            }
        }
    }
}
#endif
