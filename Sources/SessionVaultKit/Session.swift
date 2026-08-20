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
    /// Синк: время последнего изменения (ISO8601, сравнимо лексикографически).
    public var updatedAt: String?
    /// Синк: tombstone — запись удалена, но живёт для распространения удаления.
    public var deleted: Bool?

    public init(
        id: UUID = UUID(), name: String, privateKey: String,
        createdAt: Date = Date(), updatedAt: String? = nil, deleted: Bool? = nil
    ) {
        self.id = id
        self.name = name
        self.privateKey = privateKey
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.deleted = deleted
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
    /// Синк: время последнего изменения (ISO8601, сравнимо лексикографически).
    public var updatedAt: String?
    /// Синк: tombstone.
    public var deleted: Bool?

    public init(
        id: UUID = UUID(),
        name: String,
        host: String,
        port: Int = 22,
        username: String,
        authMethod: AuthMethod,
        keyID: UUID? = nil,
        privateKeyPath: String? = nil,
        extra: [String: String] = [:],
        updatedAt: String? = nil,
        deleted: Bool? = nil
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
        self.updatedAt = updatedAt
        self.deleted = deleted
    }
}

/// Избранная команда. Живёт в вейлте — синкается вместе с сессиями.
public struct Snippet: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public var title: String
    public var command: String
    /// Синк: время последнего изменения (ISO8601) и tombstone.
    public var updatedAt: String?
    public var deleted: Bool?

    public init(
        id: UUID = UUID(), title: String, command: String,
        updatedAt: String? = nil, deleted: Bool? = nil
    ) {
        self.id = id
        self.title = title
        self.command = command
        self.updatedAt = updatedAt
        self.deleted = deleted
    }
}

/// Статистика команды для подсказок (журнал набора). Merge между
/// устройствами идемпотентен: count = max, lastUsed = max (ISO8601-строка).
public struct CmdStat: Codable, Sendable, Equatable {
    public var count: Int
    public var lastUsed: String?
    /// Tombstone: команда удалена из журнала. Побеждает более свежий
    /// lastUsed — повторный ввод после удаления воскрешает запись.
    public var deleted: Bool?

    public init(count: Int = 0, lastUsed: String? = nil, deleted: Bool? = nil) {
        self.count = count
        self.lastUsed = lastUsed
        self.deleted = deleted
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
    /// Журнал команд для подсказок (синкается, кап ~500).
    public var cmdHistory: [String: CmdStat]?

    public init(
        schemaVersion: Int = 1,
        deviceID: UUID,
        updatedAt: Date = Date(),
        sessions: [Session] = [],
        snippets: [Snippet]? = nil,
        secrets: [String: String]? = nil,
        sshKeys: [SSHKey]? = nil,
        cmdHistory: [String: CmdStat]? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.deviceID = deviceID
        self.updatedAt = updatedAt
        self.sessions = sessions
        self.snippets = snippets
        self.secrets = secrets
        self.sshKeys = sshKeys
        self.cmdHistory = cmdHistory
    }
}
