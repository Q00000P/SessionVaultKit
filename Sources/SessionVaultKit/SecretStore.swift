import Foundation
import Security

/// Kind of secret associated with a Session.
public enum SecretKind: String {
    case password
    case privateKeyPassphrase
}

/// Секреты. Живут внутри шифрованного вейлта (vault.secrets).
///
/// Passphrase ключа привязывается к КЛЮЧУ, а не к сессии: один RSA-ключ на
/// пятнадцати нодах = одна фраза, введённая один раз.
///   "key:<keyID>.passphrase"   — ключ из хранилища вейлта
///   "path:<путь>.passphrase"   — файловый ключ (путь развёрнут, без ~)
/// Легаси "<sessionID>.privateKeyPassphrase" мигрируется при первом чтении.
public final class SecretStore {
    private let legacyService: String
    private let store: SessionStore

    public init(store: SessionStore, legacyService: String = "com.q00000p.sessionvaultkit.secrets") {
        self.store = store
        self.legacyService = legacyService
    }

    // MARK: - Низкоуровневый доступ к словарю секретов

    private func allSecrets() -> [String: String] {
        (try? store.load().secrets) ?? [:]
    }

    private func put(_ value: String?, forKey key: String) throws {
        var secrets = allSecrets()
        secrets[key] = value
        try store.save(secrets: secrets)
    }

    // MARK: - Пароли сессий (как раньше)

    public func set(_ secret: String, for sessionID: UUID, kind: SecretKind) throws {
        try put(secret, forKey: "\(sessionID.uuidString).\(kind.rawValue)")
        deleteLegacy(for: sessionID, kind: kind)
    }

    public func get(for sessionID: UUID, kind: SecretKind) throws -> String? {
        let k = "\(sessionID.uuidString).\(kind.rawValue)"
        if let v = allSecrets()[k] { return v }
        if let legacy = readLegacy(for: sessionID, kind: kind) {
            try? put(legacy, forKey: k)
            deleteLegacy(for: sessionID, kind: kind)
            return legacy
        }
        return nil
    }

    public func delete(for sessionID: UUID, kind: SecretKind) throws {
        try put(nil, forKey: "\(sessionID.uuidString).\(kind.rawValue)")
        deleteLegacy(for: sessionID, kind: kind)
    }

    public func deleteAll(for sessionID: UUID) {
        try? delete(for: sessionID, kind: .password)
        try? delete(for: sessionID, kind: .privateKeyPassphrase)
    }

    // MARK: - Passphrase ключей (по ключу, не по сессии)

    public func setPassphrase(_ phrase: String, forKeyID keyID: UUID) throws {
        try put(phrase, forKey: "key:\(keyID.uuidString).passphrase")
    }

    public func passphrase(forKeyID keyID: UUID) -> String? {
        allSecrets()["key:\(keyID.uuidString).passphrase"]
    }

    public func deletePassphrase(forKeyID keyID: UUID) {
        try? put(nil, forKey: "key:\(keyID.uuidString).passphrase")
    }

    public func setPassphrase(_ phrase: String, forPath path: String) throws {
        try put(phrase, forKey: "path:\(Self.norm(path)).passphrase")
    }

    /// Passphrase файлового ключа. Если по пути не нашлось — пробуем легаси
    /// (по сессии) и мигрируем на путь, чтобы остальные ноды с этим ключом
    /// больше не спрашивали.
    public func passphrase(forPath path: String, legacySession sessionID: UUID? = nil) -> String? {
        let k = "path:\(Self.norm(path)).passphrase"
        if let v = allSecrets()[k] { return v }
        if let sessionID,
           let phrase = (try? get(for: sessionID, kind: .privateKeyPassphrase)) ?? nil {
            try? put(phrase, forKey: k)
            return phrase
        }
        return nil
    }

    private static func norm(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    // MARK: - Legacy Keychain (только чтение для миграции + удаление)

    private func legacyAccount(_ sessionID: UUID, _ kind: SecretKind) -> String {
        "\(sessionID.uuidString).\(kind.rawValue)"
    }

    private func readLegacy(for sessionID: UUID, kind: SecretKind) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyService,
            kSecAttrAccount as String: legacyAccount(sessionID, kind),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteLegacy(for sessionID: UUID, kind: SecretKind) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyService,
            kSecAttrAccount as String: legacyAccount(sessionID, kind)
        ]
        SecItemDelete(query as CFDictionary)
    }
}
