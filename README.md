# TGram Native — 100% Pure Rust Native Messenger (`Zero Web Core`)

Кроссплатформенный десктопный мессенджер реального времени, спроектированный и реализованный с нуля на **100% нативном Rust (AOT)** по архитектуре и дизайн-системе **Telegram Desktop (`Night Blue`)**.

## Жёсткие архитектурные гарантии
- **Zero Web Core:** Никаких Electron, Tauri, WebView, CEF, HTML/CSS/JS, QML, JVM или .NET.
- **Аппаратный GPU-рендеринг (`Iced 0.13` + `wgpu`):** Прямая векторная отрисовка через Direct3D 12 (Windows), Metal (macOS) и Vulkan (Linux).
- **Двойная виртуализация списков:**
  - `O(1)` виртуализация списка чатов (`72px` фиксированные строки `DialogRowCanvas`).
  - `O(log N)` виртуализация ленты сообщений разновысотных пузырей через префиксные суммы (`HistoryLayoutCache` + бинарный поиск `partition_point`) — плавные 60/120 FPS на десятках тысяч сообщений.
- **Строгая неблокирующая 3-поточная модель клиента:**
  1. `UI Thread (Main)` — исключительно отрисовка `wgpu` и события ввода.
  2. `Network Thread` (`tgram-network`) — изолированный цикл событий `Tokio` (`TCP_NODELAY`), 1-RTT рукопожатие, мультиплексирование RPC, `Ping/Pong` keep-alive и авто-реконнект с `TokenResume`.
  3. `Storage Thread` (`tgram-storage`) — локальная БД **SQLite3** в режиме **`WAL`** (`mmap_size = 64 MB`) с AEAD-шифрованием всех записей и токенов на диске (`ChaCha20-Poly1305`).
- **Собственный бинарный криптопротокол `MTWire v1`:**
  - `X25519` (эфемерный ECDH, Perfect Forward Secrecy) + `Ed25519` (подпись транскрипта против MITM) + `HKDF-SHA256` + `ChaCha20-Poly1305` (in-place шифрование фреймов без лишних аллокаций) + `Protobuf v3` (`prost`, без внешней зависимости от `protoc`).

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
│   ├── src/                    # Hub (64-шардовый DashMap), Auth (Argon2id), Media CAS, Store (RAM / PG+Redis)
│   └── tests/realtime_e2e.rs   # Интеграционный E2E-тест протокола и маршрутизации
└── client/                     # Крейт `tgram-client` (бинарь `tgram-desktop`)
    └── src/
        ├── domain.rs           # Модели UI и каналы межпоточного взаимодействия
        ├── net/mod.rs          # Фоновый сетевой поток (MTWire v1, авто-реконнект, чанковая передача файлов)
        ├── storage/            # Фоновый поток SQLite3 WAL + LocalVaultCipher (ChaCha20-Poly1305)
        └── ui/                 # Тема Telegram Night Blue, кастомные GPU Canvas-виджеты и 2/3-колоночный UI
```

---

## Быстрый запуск и тестирование

### 1. Прогон модульных и E2E-тестов
Проверяет криптографическое рукопожатие `X25519 + Ed25519`, защиту от подмены заголовков AAD/MITM, регистрацию, мгновенную доставку сообщений, индикаторы `печатает...` и двойные галочки прочтения (`✓` -> `✓✓`):
```powershell
cargo test --workspace
```

### 2. Сборка нативных AOT release-бинарников
```powershell
cargo build --release --workspace
```

### 3. Запуск сервера (Zero-Setup режим в памяти или PostgreSQL + Redis)
По умолчанию сервер слушает `0.0.0.0:4430` в быстром конкурентном In-Memory режиме с предсозданным демо-чатом (не требует поднятия внешних СУБД для локального теста):
```powershell
cargo run --release -p tgram-server
```
Для production-режима с **PostgreSQL + Redis** достаточно задать переменные окружения:
```powershell
$env:DATABASE_URL = "postgres://postgres:postgres@127.0.0.1:5432/tgram"
$env:REDIS_URL = "redis://127.0.0.1:6379"
cargo run --release -p tgram-server
```

### 4. Запуск двух независимых клиентов на одной машине
Каждый профиль хранит собственную зашифрованную БД `SQLite3 WAL` (`./data/client_<profile>.sqlite3`) и папку загрузок:

**Терминал 1 (Алиса):**
```powershell
cargo run --release -p tgram-client -- --profile alice
```

**Терминал 2 (Боб):**
```powershell
cargo run --release -p tgram-client -- --profile bob
```

### Что протестировать в UI:
1. Нажмите **«Нет аккаунта? Создать новый»** в обоих окнах и зарегистрируйте пользователей `alice` и `bob`.
2. Оба пользователя сразу попадут в общий чат, либо найдите `@bob` через строку **Поиск** в левой панели Алисы для открытия личного диалога.
3. Проверьте живой статус **«печатает...»** в шапке чата и превью диалога, мгновенную смену одной галочки `✓` на две голубые `✓✓` при прочтении, отправку и скачивание файлов (скрепка `📎`) с прогресс-баром, перетаскивание сплиттера колонок и 3-ю инфо-панель (`◧`).
4. Откройте бургер-меню (`☰`) или правую инфо-панель и нажмите **«⚡ Стресс-тест: +20 000 сообщ.»** — `StorageThread` запишет 20 000 зашифрованных сообщений одной транзакцией `SQLite WAL`, а виртуализированная лента `wgpu` позволит скроллить их на 60/120 FPS без задержек.
