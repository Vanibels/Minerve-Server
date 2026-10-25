-- À exécuter une fois dans l'éditeur SQL de Neon.

CREATE TABLE IF NOT EXISTS users (
    id            bigserial PRIMARY KEY,
    email         text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Un compte = un foyer ; ses agents sont les appareils du foyer.
CREATE TABLE IF NOT EXISTS agents (
    uid        text PRIMARY KEY,
    user_id    bigint REFERENCES users(id) ON DELETE SET NULL,
    token_hash text NOT NULL,
    claim_hash text,
    hostname   text,
    os         text,
    interface  text,
    kind       text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz
);
CREATE INDEX IF NOT EXISTS agents_user_idx  ON agents (user_id);
CREATE INDEX IF NOT EXISTS agents_claim_idx ON agents (claim_hash);

CREATE TABLE IF NOT EXISTS measures (
    id             bigserial PRIMARY KEY,
    agent_uid      text NOT NULL REFERENCES agents(uid) ON DELETE CASCADE,
    ts             timestamptz NOT NULL,
    status         text NOT NULL,
    latency_ms     real,
    bandwidth_mbps real,
    public_ip      text,
    fai            text,
    asn            text,
    interface      text,
    UNIQUE (agent_uid, ts)
);
CREATE INDEX IF NOT EXISTS measures_asn_ts_idx ON measures (asn, ts);

CREATE TABLE IF NOT EXISTS incidents (
    id         bigserial PRIMARY KEY,
    agent_uid  text NOT NULL REFERENCES agents(uid) ON DELETE CASCADE,
    started_at timestamptz NOT NULL,
    ended_at   timestamptz,
    duration_s integer,
    reason     text,
    fai        text,
    asn        text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_uid, started_at)
);
CREATE INDEX IF NOT EXISTS incidents_asn_idx ON incidents (asn, started_at);
