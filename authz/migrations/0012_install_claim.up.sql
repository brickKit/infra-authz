-- Foundations item 3, T6g (security 08's install claim, A130): the claim recorded at installation names an exact
-- platform principal or the digest of a one-time code, with its expiry, under the deployment recovery generation of
-- this database; consumed once by its claimant. A database restored from an older backup has advanced its generation,
-- so a claim consumed since is not open again.
CREATE TABLE authz_claim (
    generation  bigint PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('principal', 'code')),
    value       text NOT NULL, -- the principal, or the code's sha256 (hex)
    expires_at  timestamptz NOT NULL,
    consumed_by text,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
