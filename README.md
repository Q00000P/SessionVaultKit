# SessionVaultKit

Стартовый пакет для будущего мак-терминала (MobaXterm alternative).
Не проверялся компиляцией — тут нет macOS/Xcode. Ревью перед вставкой в проект обязателен.

## Что уже есть

- `Session` / `SessionVault` — модель сессии и версионированный вейлт (Sources/SessionVaultKit/Session.swift)
- `VaultCrypto` — обёртка Master Key (MK) через Secure Enclave (P-256, Touch ID gate), AES-GCM шифрование самого вейлта (Sources/SessionVaultKit/VaultCrypto.swift)
- `SecretStore` — пароли/passphrase отдельно в Keychain, по одному item на сессию+вид секрета (Sources/SessionVaultKit/SecretStore.swift)
- `SessionStore` — склеивает всё вместе, читает/пишет `vault.dat` + `vault.mk.wrap` в Application Support (Sources/SessionVaultKit/SessionStore.swift)

Ноль внешних зависимостей — только CryptoKit/Security/LocalAuthentication (системные фреймворки), как и QSwitcher.

## Модель угроз / зачем два файла

- `vault.dat` — зашифрован AES-256-GCM на MK. Без MK бесполезен, можно хоть в облако класть.
- `vault.mk.wrap` — MK, зашифрованный ECIES-схемой на Secure Enclave ключе ЭТОГО устройства. Без чипа, на котором создан — бесполезен. Это и есть "привязка к чипу", как в логе QSwitcher.

## Синк между устройствами (не реализовано, дизайн на будущее)

Проблема: если MK физически не покидает Secure Enclave — синк невозможен в принципе, никаким сервером. Значит модель должна быть:

1. MK — один на все устройства аккаунта.
2. На каждом устройстве отдельно хранится СВОЯ обёртка MK (SE на маке, TPM/Hello на винде, Keystore на андроиде) — это и есть привязка к чипу, но она про *локальный анлок*, а не про синк.
3. Добавление нового устройства = прямая передача MK на него (QR-код / локальная сеть, как device-linking в Signal/1Password), НЕ через сервер.
4. Сервер (тот же паттерн, что update-сервер qsw.05.gs) — просто relay зашифрованного `vault.dat` + номер версии, zero-knowledge, MK не видит и не хранит никогда.

Когда дойдём до синка — добавить `DeviceLinkKit` рядом, не трогая `SessionVaultKit`.

## Дальше (не в этом пакете)

- App target (SwiftUI/AppKit) со списком сессий из `SessionStore.load()`
- `SwiftTerm` — терминальный view, подключается на shell-канал SSH-соединения
- `Citadel` (SwiftNIO SSH) — SSH-транспорт + SFTP-клиент (list/get/put/rm/mkdir/rename) на том же соединении, что и shell
- Файловый браузер: SFTP listDirectory → дерево, двойной клик → download во временный файл → открыть → следить за mtime → upload обратно при изменении
