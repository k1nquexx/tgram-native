-- TGram Native Server — PostgreSQL Production Schema (MTWire v1)

CREATE TABLE IF NOT EXISTS users (
    user_id          BIGSERIAL PRIMARY KEY,
    username         VARCHAR(32) NOT NULL UNIQUE,
    display_name     VARCHAR(80) NOT NULL,
    password_phc     TEXT NOT NULL,
    avatar_color_rgb BIGINT NOT NULL,
    avatar_media_id  TEXT NOT NULL DEFAULT '',
    last_seen_ms     BIGINT NOT NULL DEFAULT 0,
    current_pts      BIGINT NOT NULL DEFAULT 1,
    created_at_ms    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users (LOWER(username));

CREATE TABLE IF NOT EXISTS user_sessions (
    token_sha256   BYTEA PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_name    VARCHAR(128) NOT NULL DEFAULT '',
    created_at_ms  BIGINT NOT NULL,
    last_active_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_uid ON user_sessions (user_id);

CREATE TABLE IF NOT EXISTS chats (
    chat_id           BIGSERIAL PRIMARY KEY,
    peer_type         INTEGER NOT NULL, -- 1 = Direct, 2 = Group
    title             VARCHAR(128) NOT NULL DEFAULT '',
    avatar_color_rgb  BIGINT NOT NULL DEFAULT 6662877,
    direct_pair_key   VARCHAR(64) UNIQUE, -- "min_uid:max_uid" for 1-on-1 chats
    created_at_ms     BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_members (
    chat_id                 BIGINT NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    user_id                 BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    read_inbox_max_msg_id   BIGINT NOT NULL DEFAULT 0,
    read_outbox_max_msg_id  BIGINT NOT NULL DEFAULT 0,
    is_pinned               BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at_ms            BIGINT NOT NULL,
    PRIMARY KEY (chat_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id);

CREATE TABLE IF NOT EXISTS media_objects (
    media_id         VARCHAR(64) PRIMARY KEY,
    uploader_user_id BIGINT REFERENCES users(user_id) ON DELETE CASCADE,
    file_name        VARCHAR(255) NOT NULL,
    mime_type        VARCHAR(127) NOT NULL,
    size_bytes       BIGINT NOT NULL,
    sha256_hash      BYTEA NOT NULL,
    width            INTEGER NOT NULL DEFAULT 0,
    height           INTEGER NOT NULL DEFAULT 0,
    created_at_ms    BIGINT NOT NULL
);

ALTER TABLE media_objects ADD COLUMN IF NOT EXISTS uploader_user_id BIGINT REFERENCES users(user_id) ON DELETE CASCADE;
ALTER TABLE media_objects DROP CONSTRAINT IF EXISTS media_objects_sha256_hash_key;
CREATE INDEX IF NOT EXISTS idx_media_objects_uploader ON media_objects (uploader_user_id);

CREATE TABLE IF NOT EXISTS messages (
    msg_id           BIGSERIAL PRIMARY KEY,
    chat_id          BIGINT NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    sender_id        BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    client_random_id BIGINT NOT NULL,
    timestamp_ms     BIGINT NOT NULL,
    body_text        TEXT NOT NULL DEFAULT '',
    reply_to_msg_id  BIGINT NOT NULL DEFAULT 0,
    media_id         VARCHAR(64) REFERENCES media_objects(media_id),
    CONSTRAINT uq_chat_sender_random_id UNIQUE (chat_id, sender_id, client_random_id)
);

ALTER TABLE messages DROP CONSTRAINT IF EXISTS uq_sender_random_id;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_chat_sender_random_id'
    ) THEN
        ALTER TABLE messages
            ADD CONSTRAINT uq_chat_sender_random_id UNIQUE (chat_id, sender_id, client_random_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_messages_chat_history ON messages (chat_id, msg_id DESC);
CREATE INDEX IF NOT EXISTS idx_messages_media_id ON messages (media_id) WHERE media_id IS NOT NULL;
