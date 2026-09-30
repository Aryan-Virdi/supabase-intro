-- Run in Supabase: SQL Editor -> paste -> Run.
-- roles first, because users references it.
 
CREATE TABLE IF NOT EXISTS roles (
  id        SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  role_name TEXT NOT NULL UNIQUE
);
 
CREATE TABLE IF NOT EXISTS users (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username        TEXT NOT NULL UNIQUE,   -- also the client-side hash salt
  name            TEXT NOT NULL,
  hashed_password TEXT NOT NULL,          -- server-side scrypt of the client hash
  role_id         SMALLINT NOT NULL REFERENCES roles(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
 
INSERT INTO roles (role_name) VALUES ('operator'), ('agronomist'), ('admin')
ON CONFLICT (role_name) DO NOTHING;
 
-- Supabase exposes public tables through its REST API. This app talks to the DB
-- only from server.js, so lock the API out: RLS on + no policies = anon/authenticated see nothing.
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;