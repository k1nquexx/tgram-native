# TGram Native — 100% Pure Rust Native Messenger (`Zero Web Core`)

Кроссплатформенный десктопный мессенджер реального времени, спроектированный и реализованный с нуля на **100% нативном Rust (AOT)** по архитектуре и дизайн-системе **Telegram Desktop (`Night Blue`)**.

## Жёсткие архитектурные гарантии
- **Zero Web Core:** Никаких Electron, Tauri, WebView, CEF, HTML/CSS/JS, QML, JVM или .NET.
- **Аппаратный GPU-рендеринг (`Iced 0.13` + `wgpu` + `cosmic-text`):** Прямая векторная отрисовка через Direct3D 12 (Windows), Metal (macOS) и Vulkan (Linux) с попиксельно точным замером и переносом глифов системных шрифтов через `cosmic-text` (`HarfRust`) и кэшированием раскладок.
- **Двойная виртуализация списков:**
  - `O(1)` виртуализация списка чатов (`72px` фиксированные строки `DialogRowCanvas`).
  - `O(log N)` виртуализация ленты сообщений разновысотных пузырей через префиксные суммы (`HistoryLayoutCache` + бинарный поиск `partition_point`) — плавные 60/120 FPS на десятках тысяч сообщений.
- **Строгая неблокирующая 3-поточная модель клиента:**
  1. `UI Thread (Main)` — исключительно отрисовка `wgpu`, шейпинг текста и события ввода (таймстампы в локальном часовом поясе ОС через `time`).
  2. `Network Thread` (`tgram-network`) — изолированный цикл событий `Tokio` (`TCP_NODELAY`), 1-RTT рукопожатие, мультиплексирование RPC, `Ping/Pong` keep-alive и авто-реконнект с `TokenResume`.
  3. `Storage Thread` (`tgram-storage`) — локальная БД **SQLite3** в режиме **`WAL`** (`mmap_size = 64 MB`) с AEAD-шифрованием всех записей и токенов на диске (`ChaCha20-Poly1305`). Мастер-ключ хранится в системном хранилище ОС через `keyring` (Windows Credential Manager / macOS Keychain / Linux Secret Service) или выводится через **Argon2id** из мастер-пароля `TGRAM_DB_KEY` (Passcode Lock).
- **Собственный бинарный криптопротокол `MTWire v1`:**
  - `X25519` (эфемерный ECDH, Perfect Forward Secrecy) + `Ed25519` (строгий пиннинг внешнего серверного ключа `TGRAM_SERVER_KEY_HEX` / `TGRAM_SERVER_PUBKEY_HEX` без зашитых дефолтных сидов, `Zeroize` ключевого материала) + `HKDF-SHA256` + `ChaCha20-Poly1305` (атомарное in-place шифрование фреймов без десинхронизации sequence-счётчика) + `Protobuf v3` (`prost`).
- **Защита медиа-хранилища (Zero IDOR & Anti-DoS):**
  - Загрузка файлов требует полного подтверждения владения байтами (`Proof-of-Possession` SHA-256 без уязвимой CAS-дедупликации по хэшу), строгой проверки членства пользователя в чате (`user_has_access_to_media`) при скачивании и прикреплении `media_id`, квотирования активных сессий на пользователя (`RAII UploadSlotGuard`) и фонового сборщика заброшенных `.part`-файлов по монотонному TTL.
- **Максимальная AOT-оптимизация бинарника:** `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`, `panic = "abort"`, `strip = "symbols"`.

---

## Структура монорепозитория

```text
tgram-native/
├── Cargo.toml                  # Workspace + агрессивный AOT release-профиль (LTO, strip, panic=abort)
├── proto/                      # Крейт `tgram-proto`: MTWire v1, крипто-рукопожатие, AEAD-фрейминг
│   ├── mtwire.proto            # Каноническая схема Protobuf v3
│   ├── WIRE_SPEC.md            # Спецификация байтового протокола и криптографии
│   └── src/
├── server/                     # Крейт `tgram-server`: асинхронный TCP-сервер реального времени
│   ├── migrations/001_init.sql # Схема PostgreSQL
│   ├── src/                    # Hub (64-шардовый DashMap), Auth (Argon2id), Media ACL + TTL GC, Store (RAM / PG+Redis)
│   └── tests/realtime_e2e.rs   # Интеграционные E2E-тесты протокола, изоляции Media IDOR и DoS-защиты
└── client/                     # Крейт `tgram-client` (бинарь `tgram-desktop`)
    └── src/
        ├── domain.rs           # Модели UI и каналы межпоточного взаимодействия
        ├── net/mod.rs          # Фоновый сетевой поток (MTWire v1, авто-реконнект, чанковая передача файлов)
        ├── storage/            # Фоновый поток SQLite3 WAL + LocalVaultCipher (ChaCha20-Poly1305)
        └── ui/                 # Тема Telegram Night Blue, кастомные GPU Canvas-виджеты и 2/3-колоночный UI
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
