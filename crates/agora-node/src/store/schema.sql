CREATE TABLE IF NOT EXISTS channel_agent_sessions (
    channel_name       TEXT    NOT NULL,
    channel_session_id TEXT    NOT NULL,
    agent_name         TEXT    NOT NULL,
    agent_session_id   TEXT    NOT NULL CHECK (length(agent_session_id) > 0),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,

    UNIQUE (channel_name, channel_session_id, agent_name),
    UNIQUE (agent_name, agent_session_id)
);
