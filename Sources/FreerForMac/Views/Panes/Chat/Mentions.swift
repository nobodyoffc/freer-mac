import SwiftUI
import FCDomain

/// What the chat pane draws of a mention. The rules — what counts as an
/// `@`, whom it names — are ``Mentions`` in FCDomain, shared with the
/// Mac and matched case for case by Android.
extension Mentions {

    /// What to write after the `@` for `fid`: the CID the chain shows
    /// for it, else the FID itself.
    @MainActor static func handle(for fid: String, names: ChatNameBook) -> String {
        names.cid(of: fid) ?? fid
    }

    /// `text` with each `@name` that `isKnown` drawn in `tint`, bold.
    static func highlighted(_ text: String, tint: Color, isKnown: (String) -> Bool) -> AttributedString {
        var out = AttributedString(text)
        for token in tokens(in: text) where isKnown(token.name) {
            guard let lower = AttributedString.Index(token.range.lowerBound, within: out),
                  let upper = AttributedString.Index(token.range.upperBound, within: out)
            else { continue }
            out[lower..<upper].foregroundColor = tint
            out[lower..<upper].inlinePresentationIntent = .stronglyEmphasized
        }
        return out
    }
}
