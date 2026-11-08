# TGram Native — 100% Pure Rust Native Messenger (`Zero Web Core`)

Кроссплатформенный нативный мессенджер реального времени (**Desktop + iOS + Android**), спроектированный и реализованный с нуля на **100% нативном Rust (AOT)** по архитектуре и дизайн-системе **Telegram (`Night Blue`)**.

## Жёсткие архитектурные гарантии
- **Zero Web Core:** Никаких Electron, Tauri, WebView, CEF, React Native, Flutter, HTML/CSS/JS, QML, JVM-рендеринга или .NET.
- **Единое общее ядро `tgram-client-core` (`staticlib` / `cdylib` / `rlib`):**
  - Вся сетевая логика (`MTWire v1`, `Tokio`, 10-секундный `Ping/Pong` watchdog, бесшовное переключение `Wi-Fi <-> 5G/LTE`, `EnterBackground`/`EnterForeground` lifecycle), локальная зашифрованная БД (`SQLite3 WAL` + `ChaCha20-Poly1305` `LocalVaultCipher`) и доменные модели вынесены в переиспользуемый крейт `client-core`, экспортирующий C-ABI (`tgram_mobile_*` + `tgram_client_core.h`), Android JNI (`Java_org_tgram_mobile_bridge_TgramNativeBridge_*`) и декларации `UniFFI` (`tgram_mobile.udl`).
- **Нативные UI-оболочки под каждую целевую ОС:**
  - **Desktop (Windows, macOS, Linux):** Аппаратный GPU-рендеринг (`Iced 0.13` + `wgpu` + `cosmic-text`) через Direct3D 12, Metal и Vulkan с `O(1)` виртуализацией чатов и `O(log N)` виртуализацией истории сообщений.
  - **Android (API 26+):** 100% **Kotlin + Jetpack Compose (Material 3)** поверх `libtgram_client_core.so` (`arm64-v8a`, `armeabi-v7a`, `x86_64`), интеграция с **Android Keystore (`AES-256-GCM`) + `BiometricPrompt`**, `FLAG_SECURE`, анти-Frida/root защита (`SecurityGuard`), `ConnectivityManager.NetworkCallback`, `ProcessLifecycleOwner` и **Firebase Cloud Messaging (`TgramFirebaseMessagingService`)** с фоновым пробуждением ядра.
  - **iOS (iOS 16+):** 100% **Swift + SwiftUI (120Hz ProMotion)** поверх `tgram_core.xcframework` (`aarch64-apple-ios`, `aarch64-apple-ios-sim`), **iOS Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) + LocalAuthentication (`FaceID / TouchID`)**, `ptrace(PT_DENY_ATTACH)` anti-dump защита, `NWPathMonitor`, `URLSessionConfiguration.background` для фоновой докачки медиа и **`UNNotificationServiceExtension` (`NotificationService.swift`)** для фоновой расшифровки пушей `mutable-content: 1` в пределах лимита 24 МБ ОЗУ.
- **Серверный Push-шлюз (APNs / FCM):**
  - Опкоды `0x0014 RegisterPushTokenReq` и `0x0015 RegisterPushTokenRes`, хранение привязок токенов устройств в PostgreSQL (`push_devices`) с автоматической очисткой при отзыве сессий и мгновенная отправка wake-уведомлений (`mutable-content: 1` для APNs и `priority: HIGH` для FCM), когда получатель находится оффлайн.
- **Собственный бинарный криптопротокол `MTWire v1`:**
  - `X25519` (эфемерный ECDH, Perfect Forward Secrecy) + `Ed25519` (строгий пиннинг внешнего серверного ключа `TGRAM_SERVER_KEY_HEX` / `TGRAM_SERVER_PUBKEY_HEX`, `Zeroize` ключевого материала) + `HKDF-SHA256` + `ChaCha20-Poly1305` (атомарное in-place шифрование фреймов без десинхронизации sequence-счётчика) + `Protobuf v3` (`prost`).
- **Защита медиа-хранилища (Zero IDOR & Anti-DoS):**
  - Загрузка файлов требует полного подтверждения владения байтами (`Proof-of-Possession` SHA-256 без уязвимой CAS-дедупликации по хэшу), строгой проверки членства пользователя в чате (`user_has_access_to_media`) при скачивании и прикреплении `media_id`, квотирования активных сессий на пользователя (`RAII UploadSlotGuard`) и фонового сборщика заброшенных `.part`-файлов по монотонному TTL.
- **Максимальная AOT-оптимизация бинарника:** `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`, `panic = "abort"`, `strip = "symbols"`.

---

## Структура монорепозитория

```text
tgram-native/
├── Cargo.toml                  # Workspace + агрессивный AOT release-профиль (LTO, strip, panic=abort)
├── proto/                      # Крейт `tgram-proto`: MTWire v1, крипто-рукопожатие, AEAD-фрейминг, Push opcodes
│   ├── mtwire.proto            # Каноническая схема Protobuf v3 (включая RegisterPushToken 0x0014/0x0015)
│   ├── WIRE_SPEC.md            # Спецификация байтового протокола и криптографии
│   └── src/
├── server/                     # Крейт `tgram-server`: асинхронный TCP-сервер реального времени + PushGateway
│   ├── migrations/001_init.sql # Схема PostgreSQL (users, sessions, push_devices, chats, messages, media)
│   ├── src/                    # Hub (64-шардовый DashMap), Auth (Argon2id), Push (APNs/FCM), Media ACL + TTL GC
│   └── tests/realtime_e2e.rs   # Интеграционные E2E-тесты протокола, пушей, изоляции Media IDOR и DoS-защиты
├── client-core/                # Крейт `tgram-client-core`: общее ядро для Desktop, iOS и Android
│   ├── include/                # C-ABI заголовок `tgram_client_core.h` и `module.modulemap` для Swift/Clang
│   └── src/
│       ├── domain.rs           # Доменные модели, форматирование времени и каналы команд/событий
│       ├── net/mod.rs          # Сетевой движок MTWire v1, Mobile Lifecycle (Background/Foreground/NetworkChanged)
│       ├── storage/            # SQLite3 WAL + LocalVaultCipher + инъекция мастер-ключа из Hardware Keystore
│       ├── ffi.rs              # Экспорт C-ABI (`tgram_mobile_*`) для iOS и JNI для Android
│       └── tgram_mobile.udl    # Схема UniFFI интерфейса для мобильных платформ
├── client/                     # Крейт `tgram-client` (десктопный бинарь `tgram-desktop` поверх `tgram-client-core`)
│   └── src/ui/                 # Тема Telegram Night Blue, кастомные GPU Canvas-виджеты и 2/3-колоночный UI
├── mobile/
│   ├── android/                # Нативный Android-клиент (Kotlin + Jetpack Compose + Hardware Keystore + FCM)
│   └── ios/                    # Нативный iOS-клиент (Swift + SwiftUI + Keychain/FaceID + NotificationServiceExtension)
└── scripts/
    ├── build-android.ps1       # Сборка `.so` (`arm64-v8a`, `armeabi-v7a`, `x86_64`) через `cargo-ndk` (Windows)
    ├── build-android.sh        # Сборка `.so` через `cargo-ndk` (Linux/macOS)
    └── build-ios-xcframework.sh # Сборка `tgram_core.xcframework` (`aarch64-apple-ios`, симулятор)
```

---

## Быстрый запуск и тестирование

### 1. Прогон модульных, property/fuzz и E2E-тестов безопасности
Проверяет криптографическое рукопожатие `X25519 + Ed25519`, защиту от MITM и подмены AAD, атомарность счётчика nonce на фрагментированных потоках, изоляцию доступа к медиафайлам (анти-IDOR / отказ CAS-пробинга), защиту от исчерпания файловых дескрипторов и доставку сообщений (`✓` -> `✓✓`):
```powershell
cargo test --workspace
```

### 2. Сборка нативных AOT release-бинарников
```powershell
cargo build --release --workspace
```

### 3. Генерация ключа сервера и запуск (`In-Memory` или `PostgreSQL + Redis`)
Сервер **не содержит зашитых приватных ключей** и требует явного задания 32-байтного сида `TGRAM_SERVER_KEY_HEX` (64 HEX-символа). При старте сервер выведет в лог соответствующий публичный ключ `ed25519_pubkey` для клиентов:

```powershell
# Сгенерировать криптостойкий 32-байтный ключ (PowerShell):
$bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:TGRAM_SERVER_KEY_HEX = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""

# Запуск в быстром In-Memory режиме (слушает 0.0.0.0:4430):
cargo run --release -p tgram-server
```
Для production-режима с **PostgreSQL + Redis** дополнительно задайте:
```powershell
$env:DATABASE_URL = "postgres://postgres:postgres@127.0.0.1:5432/tgram"
$env:REDIS_URL = "redis://127.0.0.1:6379"
cargo run --release -p tgram-server
```

### 4. Запуск двух независимых клиентов на одной машине
Скопируйте `ed25519_pubkey` из первой строки лога `tgram-server` и передайте его через `TGRAM_SERVER_PUBKEY_HEX`, флаг `--server-pubkey` либо вставьте прямо в поле **«Публичный ключ сервера Ed25519 (64 HEX)»** на экране входа (после успешного входа ключ сохраняется в зашифрованном хранилище `SQLite3 WAL` для автоматического `TokenResume`):

**Терминал 1 (Алиса):**
```powershell
$env:TGRAM_SERVER_PUBKEY_HEX = "<ed25519_pubkey_из_лога_сервера>"
cargo run --release -p tgram-client -- --profile alice
```

**Терминал 2 (Боб):**
```powershell
$env:TGRAM_SERVER_PUBKEY_HEX = "<ed25519_pubkey_из_лога_сервера>"
cargo run --release -p tgram-client -- --profile bob
```

### Что протестировать в UI:
1. Нажмите **«Нет аккаунта? Создать новый»** в обоих окнах и зарегистрируйте пользователей `alice` и `bob`.
2. Оба пользователя сразу попадут в общий чат, либо найдите `@bob` через строку **Поиск** в левой панели Алисы для открытия личного диалога.
3. Проверьте живой статус **«печатает...»** в шапке чата и превью диалога, мгновенную смену одной галочки `✓` на две голубые `✓✓` при прочтении, отправку и скачивание файлов (скрепка `📎`) с прогресс-баром, перетаскивание сплиттера колонок и 3-ю инфо-панель (`◧`).
4. Откройте бургер-меню (`☰`) или правую инфо-панель и нажмите **«⚡ Стресс-тест: +20 000 сообщ.»** — `StorageThread` запишет 20 000 зашифрованных сообщений одной транзакцией `SQLite WAL`, а виртуализированная лента `wgpu` позволит скроллить их на 60/120 FPS без задержек.

---

## Мобильная сборка (iOS / Android)

### 1. Android (`cargo-ndk` + Jetpack Compose)
Скрипт компилирует `tgram-client-core` (`libtgram_client_core.so`) под `arm64-v8a`, `armeabi-v7a` и `x86_64`, автоматически укладывая бинарники в `mobile/android/app/src/main/jniLibs/`:
```powershell
# Windows (PowerShell):
.\scripts\build-android.ps1

# Linux / macOS:
./scripts/build-android.sh
```
Затем откройте директорию `mobile/android` в **Android Studio** или соберите APK/AAB через Gradle (`./gradlew assembleRelease`).

### 2. iOS (`XCFramework` + SwiftUI + `NotificationServiceExtension`)
На macOS с установленным Xcode запустите скрипт сборки универсального `tgram_core.xcframework` (`aarch64-apple-ios` для физических устройств и `aarch64-apple-ios-sim` + `x86_64-apple-ios` для симулятора):
```bash
./scripts/build-ios-xcframework.sh
cd mobile/ios && xcodegen generate
open TGramMobile.xcodeproj
```
