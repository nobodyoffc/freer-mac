import Foundation

extension Bundle {
    /// FCUI's resource bundle, wherever the current build put it.
    ///
    /// SwiftPM's generated `Bundle.module` looks in
    /// `Bundle.main.bundleURL/FCUI_FCUI.bundle` — for an `.app` that is the
    /// bundle *root*, the one place `codesign` will not seal anything
    /// ("unsealed contents present in the bundle root"). Packaging therefore
    /// puts the resource bundle in `Contents/Resources` and this looks there
    /// first; `Bundle.module` still answers for `swift run`, `swift test` and
    /// previews, where there is no app bundle at all.
    ///
    /// Everything in FCUI that reads a bundled asset goes through here, so the
    /// packaging layout is decided in one place rather than at each call site.
    static let fcuiResources: Bundle = {
        if let url = Bundle.main.resourceURL?.appendingPathComponent("FCUI_FCUI.bundle"),
           let bundle = Bundle(url: url) {
            return bundle
        }
        return .module
    }()
}
