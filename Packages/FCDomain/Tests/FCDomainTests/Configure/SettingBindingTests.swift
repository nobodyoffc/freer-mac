import XCTest
import FCCore
import FCStorage
@testable import FCDomain

/// A setting file belongs to one main FID, and the ciphertext has to
/// say so.
///
/// Every main under one Configure keeps its setting in a file of the
/// same name, under the same Configure symkey. While the AAD was that
/// shared filename the files were interchangeable: moving one into
/// another main's directory left it perfectly valid, and the session
/// that opened it force-unwrapped `keyInfoMap[mainFid]` for a FID the
/// file had never heard of.
final class SettingBindingTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SettingBindingTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func settingUrl(_ manager: ConfigureManager, _ passwordName: String, _ fid: String) -> URL {
        manager.settingDirectory(passwordName: passwordName, mainFid: fid)
            .appendingPathComponent("setting.encrypted.dat")
    }

    func testASettingFileFromAnotherMainIsRefused() throws {
        let manager = try ConfigureManager(baseDirectory: baseDir)
        let configure = try manager.createConfigure(
            password: Data("swap".utf8), kdfKind: .legacySha256
        )
        let a = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        let b = try configure.addMain(privkey: Data(repeating: 0xB2, count: 32), label: "B")

        // Materialise both settings.
        _ = try configure.unlockMain(fid: a.fid, fapi: MockFapiClient())
        _ = try configure.unlockMain(fid: b.fid, fapi: MockFapiClient())

        let aUrl = settingUrl(manager, configure.record.passwordName, a.fid)
        let bUrl = settingUrl(manager, configure.record.passwordName, b.fid)

        // Swap B's file into A's directory: same name, same symkey.
        try FileManager.default.removeItem(at: aUrl)
        try FileManager.default.copyItem(at: bUrl, to: aUrl)

        // The AAD names B's FID, so opening it as A fails the AEAD
        // outright — the swap is refused by the cryptography, not by a
        // field comparison.
        XCTAssertThrowsError(try configure.unlockMain(fid: a.fid, fapi: MockFapiClient()))
    }

    /// The second line of defence, for a file old enough to still
    /// authenticate under its filename.
    ///
    /// The migration path has to accept those or every existing vault
    /// is locked out — and a legacy file is exactly as interchangeable
    /// as it always was, so the AEAD cannot be what rejects the swap.
    /// The contents have to be read and disagreed with.
    func testALegacySettingFileFromAnotherMainIsRefusedByItsContents() throws {
        let manager = try ConfigureManager(baseDirectory: baseDir)
        let configure = try manager.createConfigure(
            password: Data("legacy-swap".utf8), kdfKind: .legacySha256
        )
        let a = try configure.addMain(privkey: Data(repeating: 0xD4, count: 32), label: "A")
        let b = try configure.addMain(privkey: Data(repeating: 0xE5, count: 32), label: "B")
        _ = try configure.unlockMain(fid: a.fid, fapi: MockFapiClient())
        _ = try configure.unlockMain(fid: b.fid, fapi: MockFapiClient())

        let aUrl = settingUrl(manager, configure.record.passwordName, a.fid)
        let bUrl = settingUrl(manager, configure.record.passwordName, b.fid)
        let symkey = try configure.symkey()

        // B's setting, written the old way, dropped into A's directory.
        let bSetting = try XCTUnwrap(
            try EncryptedFile.read(
                Setting.self, from: bUrl, key: symkey,
                aad: ConfigureSession.settingAad(fid: b.fid)
            )
        )
        try EncryptedFile.write(bSetting, to: aUrl, key: symkey)

        XCTAssertThrowsError(try configure.unlockMain(fid: a.fid, fapi: MockFapiClient())) { e in
            guard case let ConfigureSession.Failure.settingBelongsToAnotherMain(expected, found) = e else {
                return XCTFail("wrong error: \(e)")
            }
            XCTAssertEqual(expected, a.fid)
            XCTAssertEqual(found, b.fid)
        }
    }

    /// Files written before the binding existed authenticate under the
    /// filename alone. Refusing them would lock every current vault out
    /// of its own settings, so they are read once and re-sealed.
    func testALegacySettingFileIsReadAndRewrittenBound() throws {
        let manager = try ConfigureManager(baseDirectory: baseDir)
        let configure = try manager.createConfigure(
            password: Data("legacy".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: Data(repeating: 0xC3, count: 32), label: "L")
        let session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
        let url = settingUrl(manager, configure.record.passwordName, info.fid)

        // Rewrite it the old way: AAD defaulted to the filename.
        let symkey = try configure.symkey()
        let stored = try XCTUnwrap(
            try EncryptedFile.read(
                Setting.self, from: url, key: symkey,
                aad: ConfigureSession.settingAad(fid: info.fid)
            )
        )
        try EncryptedFile.write(stored, to: url, key: symkey)
        XCTAssertNil(
            try? EncryptedFile.read(
                Setting.self, from: url, key: symkey,
                aad: ConfigureSession.settingAad(fid: info.fid)
            ),
            "precondition: the file is now in the legacy form"
        )

        // It still opens...
        let reopened = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
        XCTAssertEqual(reopened.mainFid, session.mainFid)

        // ...and has been re-sealed under the FID-bound AAD.
        XCTAssertNotNil(
            try EncryptedFile.read(
                Setting.self, from: url, key: symkey,
                aad: ConfigureSession.settingAad(fid: info.fid)
            ),
            "the migration should happen on the read that accepted it"
        )
    }
}
