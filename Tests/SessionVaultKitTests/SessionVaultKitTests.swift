import XCTest
@testable import SessionVaultKit

final class SessionVaultKitTests: XCTestCase {

    func testSessionCodableRoundtrip() throws {
        let s = Session(name: "vps-nl", host: "1.2.3.4", port: 22044, username: "root", authMethod: .privateKey, privateKeyPath: "~/.ssh/id_ed25519")
        let data = try JSONEncoder.vaultEncoder.encode(s)
        let decoded = try JSONDecoder.vaultDecoder.decode(Session.self, from: data)
        XCTAssertEqual(s, decoded)
    }

    // VaultCrypto / SessionStore tests are intentionally NOT here: they need
    // a real Secure Enclave (physical Mac with T2/Apple Silicon) and a Touch
    // ID prompt, so they don't run headless in CI. Test those manually from
    // the app target first, wrap in a manual QA checklist later.
}
