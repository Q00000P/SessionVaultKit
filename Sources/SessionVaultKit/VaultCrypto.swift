import Foundation
import CryptoKit
import Security
import LocalAuthentication

/// Errors surfaced by the crypto layer.
public enum VaultCryptoError: Error {
    case secureEnclaveUnavailable
    case keychainWrite(OSStatus)
    case keychainRead(OSStatus)
    case keychainDelete(OSStatus)
    case corruptWrappedKey
    case sealFailed
    case openFailed
}

/// Wraps/unwraps the vault Master Key (MK) using a Secure-Enclave-resident
/// P-256 key. Приватный ключ SE не покидает чип; в связке лежит только его
/// непереносимое представление.
///
/// ВАЖНО: элемент хранится в data-protection keychain
/// (kSecUseDataProtectionKeychain), а не в старой файловой связке. В старой
/// доступ регулировался ACL со списком доверенных приложений, и каждая
/// пересборка QTerm считалась «новым приложением» — отсюда парольный промпт
/// после каждого ребилда. В data-protection доступ определяется самим
/// SE-ключом и биометрией, содержимое бандла роли не играет.
public final class VaultCrypto {

    private let service: String
    private let seKeyAccount = "sessionvaultkit.se-private-key"

    public init(service: String = "com.q00000p.sessionvaultkit") {
        self.service = service
    }

    // MARK: - SE key lifecycle

    private func loadOrCreateSEKey(reason: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw VaultCryptoError.secureEnclaveUnavailable
        }

        if let existing = try? readKeychainData(account: seKeyAccount) {
            let context = LAContext()
            context.localizedReason = reason
            // Только биометрия: без парольного фолбэка и без переспрашивания
            // пальца в пределах 10 минут.
            context.localizedFallbackTitle = ""
            context.touchIDAuthenticationAllowableReuseDuration = 600
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: existing,
                authenticationContext: context
            )
        }

        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            nil
        )!

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        try writeKeychainData(key.dataRepresentation, account: seKeyAccount)
        return key
    }

    /// Wraps a 32-byte Master Key: ephemeral-static ECDH + HKDF + AES-GCM.
    /// Формат: ephemeral pubkey (64 байта raw) + nonce + ciphertext + tag.
    public func wrapMasterKey(_ mk: SymmetricKey, reason: String = "Разблокировать хранилище сессий") throws -> Data {
        let seKey = try loadOrCreateSEKey(reason: reason)
        let ephemeral = P256.KeyAgreement.PrivateKey()

        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let symmetric = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("SessionVaultKit.MK.wrap.v1".utf8),
            sharedInfo: Data(),
            outputByteCount: 32
        )

        guard let sealed = try? AES.GCM.seal(mk.withUnsafeBytes { Data($0) }, using: symmetric) else {
            throw VaultCryptoError.sealFailed
        }

        var out = Data()
        out.append(ephemeral.publicKey.rawRepresentation)   // 64 байта
        out.append(sealed.combined!)
        return out
    }

    public func unwrapMasterKey(_ wrapped: Data, reason: String = "Разблокировать хранилище сессий") throws -> SymmetricKey {
        guard wrapped.count > 64 else { throw VaultCryptoError.corruptWrappedKey }
        let seKey = try loadOrCreateSEKey(reason: reason)

        let ephemeralPubData = wrapped.prefix(64)
        let sealedData = wrapped.suffix(from: wrapped.startIndex + 64)

        guard let ephemeralPub = try? P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubData) else {
            throw VaultCryptoError.corruptWrappedKey
        }

        let shared = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPub)
        let symmetric = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("SessionVaultKit.MK.wrap.v1".utf8),
            sharedInfo: Data(),
            outputByteCount: 32
        )

        guard let box = try? AES.GCM.SealedBox(combined: sealedData),
              let opened = try? AES.GCM.open(box, using: symmetric) else {
            throw VaultCryptoError.openFailed
        }
        return SymmetricKey(data: opened)
    }

    // MARK: - Vault blob encryption (MK -> vault.dat)

    public func encryptVault(_ vault: SessionVault, mk: SymmetricKey) throws -> Data {
        let plaintext = try JSONEncoder.vaultEncoder.encode(vault)
        guard let sealed = try? AES.GCM.seal(plaintext, using: mk), let combined = sealed.combined else {
            throw VaultCryptoError.sealFailed
        }
        return combined
    }

    public func decryptVault(_ data: Data, mk: SymmetricKey) throws -> SessionVault {
        guard let box = try? AES.GCM.SealedBox(combined: data),
              let plaintext = try? AES.GCM.open(box, using: mk) else {
            throw VaultCryptoError.openFailed
        }
        return try JSONDecoder.vaultDecoder.decode(SessionVault.self, from: plaintext)
    }

    // MARK: - Keychain (data protection)

    private func writeKeychainData(_ data: Data, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultCryptoError.keychainWrite(status) }
    }

    private func readKeychainData(account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultCryptoError.keychainRead(status)
        }
        return data
    }
}

extension JSONEncoder {
    static var vaultEncoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }
}
extension JSONDecoder {
    static var vaultDecoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
