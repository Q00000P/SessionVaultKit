import Foundation
import Security

/// Kind of secret associated with a Session.
public enum SecretKind: String {
    case password
    case privateKeyPassphrase
}

/// Секреты сессий. Хранятся ВНУТРИ шифрованного вейлта (поле secrets) — а не
/// отдельными Keychain-элементами: элементы связки привязаны к подписи
/// приложения, и каждый ребилд заставлял переподтверждать паролем каждый
/// секрет. Вейлт защищён одним SE-ключом (Touch ID) — один палец на запуск,
/// ребилды секреты не трогают, и они синкаются вместе с сессиями.
///
/// Старые секреты из связки мигрируются лениво: при первом чтении секрет
/// ищется в вейлте, не найден — читается из старого Keychain-элемента,
/// перекладывается в вейлт и удаляется из связки.
public final class SecretStore {
    private let legacyService: String
    private let store: SessionStore

    public init(store: SessionStore, legacyService: String = "com.q00000p.sessionvaultkit.secrets") {
        self.store = store
        self.legacyService = legacyService
    }

    private func key(for sessionID: UUID, kind: SecretKind) -> String {
        "\(sessionID.uuidString).\(kind.rawValue)"
    }

    public func set(_ secret: String, for sessionID: UUID, kind: SecretKind) throws {
        var secrets = (try? store.load().secrets) ?? [:]
        secrets[key(for: sessionID, kind: kind)] = secret
        try store.save(secrets: secrets)
        // Старый элемент связки, если был — больше не нужен.
        deleteLegacy(for: sessionID, kind: kind)
    }

    public func get(for sessionID: UUID, kind: SecretKind) throws -> String? {
        let k = key(for: sessionID, kind: kind)
        let vaultSecrets = (try? store.load().secrets) ?? [:]
        if let v = vaultSecrets[k] { return v }

        // Миграция из связки: нашли по-старому — переложили в вейлт, удалили.
        if let legacy = readLegacy(for: sessionID, kind: kind) {
            var secrets = vaultSecrets
            secrets[k] = legacy
            try? store.save(secrets: secrets)
            deleteLegacy(for: sessionID, kind: kind)
            return legacy
        }
        return nil
    }

    public func delete(for sessionID: UUID, kind: SecretKind) throws {
        var secrets = (try? store.load().secrets) ?? [:]
        secrets.removeValue(forKey: key(for: sessionID, kind: kind))
        try store.save(secrets: secrets)
        deleteLegacy(for: sessionID, kind: kind)
    }

    /// Call when a Session is deleted, so orphaned secrets don't pile up.
    public func deleteAll(for sessionID: UUID) {
        try? delete(for: sessionID, kind: .password)
        try? delete(for: sessionID, kind: .privateKeyPassphrase)
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
