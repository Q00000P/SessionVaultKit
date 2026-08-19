import Foundation

/// Auth method for a session. The actual secret (password / key passphrase)
/// never lives in this struct — only inside the encrypted vault blob.
public enum AuthMethod: String, Codable, Sendable {
    case password
    case privateKey
    case agent
}

/// Приватный ключ, живущий ВНУТРИ вейлта. Файл на диске после импорта не
/// нужен: содержимое скопировано в шифрованный blob, синкается вместе со всем.
public struct SSHKey: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public var name: String
    /// PEM/OpenSSH-текст приватного ключа (может быть зашифрован passphrase).
    public var privateKey: String
    public var createdAt: Date

    public init(id: UUID = UUID(), name: String, privateKey: String, createdAt: Date = Date()) {
        self.id = id
        self.name = name
        self.privateKey = privateKey
        self.createdAt = createdAt
    }
}

/// Non-secret connection metadata (host/port/user + ссылки на ключ).
public struct Session: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public var name: String
    public var host: String
    public var port: Int
    public var username: String
    public var authMethod: AuthMethod

    /// Ключ из хранилища вейлта (приоритетный способ).
    public var keyID: UUID?
    /// Либо путь к файлу ключа на диске (легаси/по желанию).
    public var privateKeyPath: String?

    /// Free-form: hostkey (TOFU), подсказки импорта и т.п.
    public var extra: [String: String]

    public init(
        id: UUID = UUID(),
        name: String,
        host: String,
        port: Int = 22,
        username: String,
        authMethod: AuthMethod,
        keyID: UUID? = nil,
        privateKeyPath: String? = nil,
        extra: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.username = username
        self.authMethod = authMethod
        self.keyID = keyID
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

/// Top-level vault payload. Все новые поля — optional: старые вейлты
/// читаются без пересоздания.
public struct SessionVault: Codable, Sendable {
    public var schemaVersion: Int
    public var deviceID: UUID
    public var updatedAt: Date
    public var sessions: [Session]
    public var snippets: [Snippet]?
    /// Секреты: пароли сессий и passphrases ключей. Ключи словаря:
    ///   "<sessionID>.password"            — пароль сессии
    ///   "key:<keyID>.passphrase"          — passphrase ключа из хранилища
    ///   "path:<путь>.passphrase"          — passphrase файлового ключа
    ///   "<sessionID>.privateKeyPassphrase" — легаси (мигрируется)
    public var secrets: [String: String]?
    /// Приватные ключи в вейлте.
    public var sshKeys: [SSHKey]?

    public init(
        schemaVersion: Int = 1,
        deviceID: UUID,
        updatedAt: Date = Date(),
        sessions: [Session] = [],
        snippets: [Snippet]? = nil,
        secrets: [String: String]? = nil,
        sshKeys: [SSHKey]? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.deviceID = deviceID
        self.updatedAt = updatedAt
        self.sessions = sessions
        self.snippets = snippets
        self.secrets = secrets
        self.sshKeys = sshKeys
    }
}
