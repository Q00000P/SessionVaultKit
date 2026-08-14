import Foundation

/// Auth method for a session. The actual secret (password / key passphrase)
/// never lives in this struct or in the vault JSON — only a reference to a
/// Keychain item does. Keeps the vault blob "safe-ish" even if MK ever leaks,
/// and keeps secret rotation independent from vault sync.
public enum AuthMethod: String, Codable, Sendable {
    case password
    case privateKey
    case agent
}

/// Non-secret connection metadata. This is what gets serialized into the
/// encrypted vault blob (vault.dat).
public struct Session: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public var name: String
    public var host: String
    public var port: Int
    public var username: String
    public var authMethod: AuthMethod

    /// Path to a private key file, when authMethod == .privateKey.
    /// The key's passphrase (if any) lives in Keychain, referenced by `id`.
    public var privateKeyPath: String?

    /// Free-form notes / jump-host / proxy-command / hostkey (TOFU) etc.
    public var extra: [String: String]

    public init(
        id: UUID = UUID(),
        name: String,
        host: String,
        port: Int = 22,
        username: String,
        authMethod: AuthMethod,
        privateKeyPath: String? = nil,
        extra: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.username = username
        self.authMethod = authMethod
        self.privateKeyPath = privateKeyPath
        self.extra = extra
    }
}

/// Избранная команда. Живёт в вейлте — синкается вместе с сессиями.
public struct Snippet: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public var title: String
    public var command: String

    public init(id: UUID = UUID(), title: String, command: String) {
        self.id = id
        self.title = title
        self.command = command
    }
}

/// Top-level vault payload. Versioned so that future devices (Windows/Android
/// ports) and future sync logic can detect schema drift before decoding.
public struct SessionVault: Codable, Sendable {
    public var schemaVersion: Int
    public var deviceID: UUID
    public var updatedAt: Date
    public var sessions: [Session]
    /// Optional: старые вейлты без этого поля читаются как раньше.
    public var snippets: [Snippet]?
    /// Секреты сессий (пароль/passphrase), ключ — "<sessionID>.<kind>".
    /// Внутри шифрованного вейлта — ребилды приложения их не трогают,
    /// синкаются вместе с сессиями. Optional для обратной совместимости.
    public var secrets: [String: String]?

    public init(
        schemaVersion: Int = 1,
        deviceID: UUID,
        updatedAt: Date = Date(),
        sessions: [Session] = [],
        snippets: [Snippet]? = nil,
        secrets: [String: String]? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.deviceID = deviceID
        self.updatedAt = updatedAt
        self.sessions = sessions
        self.snippets = snippets
        self.secrets = secrets
    }
}
