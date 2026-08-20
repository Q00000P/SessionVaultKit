import Foundation
import CryptoKit

/// Ties VaultCrypto (MK wrap/unwrap + vault encrypt/decrypt) to on-disk
/// storage. This is the type the app actually talks to.
public final class SessionStore {
    private let crypto: VaultCrypto
    private let directory: URL
    private var cachedMK: SymmetricKey?
    private var vaultPath: URL { directory.appendingPathComponent("vault.dat") }
    private var wrappedMKPath: URL { directory.appendingPathComponent("vault.mk.wrap") }

    public init(crypto: VaultCrypto = VaultCrypto(), directoryOverride: URL? = nil) {
        self.crypto = crypto
        if let directoryOverride {
            self.directory = directoryOverride
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.directory = appSupport.appendingPathComponent("SessionVaultKit", isDirectory: true)
        }
    }

    private func ensureDirectory() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    public var isInitialized: Bool {
        FileManager.default.fileExists(atPath: vaultPath.path) &&
        FileManager.default.fileExists(atPath: wrappedMKPath.path)
    }

    private func masterKey(reason: String) throws -> SymmetricKey {
        if let mk = cachedMK { return mk }
        let wrapped = try Data(contentsOf: wrappedMKPath)
        let mk = try crypto.unwrapMasterKey(wrapped, reason: reason)
        cachedMK = mk
        return mk
    }

    /// Сбросить разблокировку (на будущее — авто-лок по таймауту).
    public func lock() { cachedMK = nil }

    @discardableResult
    public func initializeIfNeeded(deviceID: UUID = UUID()) throws -> SessionVault {
        try ensureDirectory()
        if isInitialized {
            return try load()
        }
        let mk = SymmetricKey(size: .bits256)
        let wrapped = try crypto.wrapMasterKey(mk, reason: "Создать хранилище сессий")
        try wrapped.write(to: wrappedMKPath, options: .atomic)
        cachedMK = mk

        let empty = SessionVault(deviceID: deviceID, sessions: [])
        let encrypted = try crypto.encryptVault(empty, mk: mk)
        try encrypted.write(to: vaultPath, options: .atomic)
        return empty
    }

    public func load() throws -> SessionVault {
        let mk = try masterKey(reason: "Разблокировать хранилище сессий")
        let encrypted = try Data(contentsOf: vaultPath)
        return try crypto.decryptVault(encrypted, mk: mk)
    }

    /// Сохранить изменившиеся части вейлта. nil-параметр = оставить как было.
    public func save(
        sessions: [Session]? = nil,
        snippets: [Snippet]? = nil,
        secrets: [String: String]? = nil,
        sshKeys: [SSHKey]? = nil,
        cmdHistory: [String: CmdStat]? = nil
    ) throws {
        let mk = try masterKey(reason: "Сохранить хранилище сессий")

        var vault = try load()
        if let sessions { vault.sessions = sessions }
        if let snippets { vault.snippets = snippets }
        if let secrets { vault.secrets = secrets }
        if let sshKeys { vault.sshKeys = sshKeys }
        if let cmdHistory { vault.cmdHistory = cmdHistory }
        vault.updatedAt = Date()

        let encrypted = try crypto.encryptVault(vault, mk: mk)
        try encrypted.write(to: vaultPath, options: .atomic)
    }
}
