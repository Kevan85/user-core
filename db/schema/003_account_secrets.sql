-- =============================================================================
-- 003 — account_secrets : les secrets de connexion (CDC §5), historisés.
-- Un changement de secret = une NOUVELLE ligne ; l'ancienne passe RETIRED et
-- se fige. RETIRED -> ACTIVE est interdit : un secret ne ressuscite jamais.
--
-- C7 : le hash est stocké en FORME ENCODÉE argon2id (il porte ses paramètres
-- m/t/p) — un durcissement futur est un re-hash à la connexion, jamais une
-- migration de crise. Le CHECK de forme rend le clair (ou tout autre
-- algorithme) NON REPRÉSENTABLE en base.
--
-- C8 : le verrouillage progressif est écrit par l'application (backoff en
-- config), mais il est NON CONTOURNABLE par accident : un verrou dans le
-- futur ne recule jamais, et failed_attempts s'incrémente de 1 ou retombe à
-- zéro (authentification réussie) — jamais autre chose.
--
-- Standard 002 appliqué : GRANT colonne par colonne (INSERT comme UPDATE),
-- horodatages posés par la BASE, search_path épinglé, forbid_delete()
-- réutilisé, preuves aux deux étages dans les tests.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE account_secret_status AS ENUM (
  'ACTIVE',
  'RETIRED'   -- retiré, jamais supprimé (§3.10) — et jamais réactivé
);

CREATE TABLE account_secrets (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id      uuid NOT NULL REFERENCES accounts(id),
  secret_hash     text NOT NULL,
  is_temporary    boolean NOT NULL DEFAULT false,
  expires_at      timestamptz,
  status          account_secret_status NOT NULL DEFAULT 'ACTIVE',
  retired_at      timestamptz,
  failed_attempts integer NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  -- C7 : forme encodée argon2id OBLIGATOIRE — le clair ne peut pas entrer.
  CONSTRAINT chk_account_secrets_argon2id CHECK (secret_hash ~ '^\$argon2id\$'),
  -- Un provisoire expire toujours ; un permanent ne porte pas d'échéance.
  CONSTRAINT chk_account_secrets_temporary_pair
    CHECK (is_temporary = (expires_at IS NOT NULL)),
  -- Le statut et son horodatage vivent et meurent ensemble.
  CONSTRAINT chk_account_secrets_retired_pair
    CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
  CONSTRAINT chk_account_secrets_attempts_positive CHECK (failed_attempts >= 0)
);

-- Au plus UN secret ACTIVE par compte ; l'historique RETIRED reste.
CREATE UNIQUE INDEX uq_account_secrets_active
  ON account_secrets (account_id) WHERE status = 'ACTIVE';

CREATE INDEX idx_account_secrets_account ON account_secrets (account_id);

CREATE FUNCTION guard_account_secret_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
     OR NEW.is_temporary IS DISTINCT FROM OLD.is_temporary
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'account_secrets : contenu immuable — changer de secret = une NOUVELLE ligne';
  END IF;

  -- Une ligne RETIRED est FIGÉE : ni résurrection, ni re-datation, ni compteur.
  IF OLD.status = 'RETIRED' THEN
    RAISE EXCEPTION 'account_secrets : une ligne RETIRED est figée — un secret ne ressuscite jamais';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    -- Ici OLD.status = ACTIVE ; la seule destination est RETIRED.
    -- La base horodate elle-même : toute valeur envoyée est écrasée (D1).
    NEW.retired_at := now();
  ELSIF NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'account_secrets : retired_at est posé par la base au retrait et ne se réécrit jamais';
  END IF;

  -- C8 : un verrou DANS LE FUTUR ne recule jamais — ni NULL, ni plus tôt.
  -- Il s'étend (valeur strictement supérieure) ou s'éteint par écoulement.
  IF NEW.locked_until IS DISTINCT FROM OLD.locked_until
     AND OLD.locked_until IS NOT NULL AND OLD.locked_until > now()
     AND (NEW.locked_until IS NULL OR NEW.locked_until <= OLD.locked_until) THEN
    RAISE EXCEPTION 'account_secrets : un verrou dans le futur ne recule jamais (ni NULL, ni date antérieure)';
  END IF;

  -- C8 : le compteur d'échecs s'incrémente de 1 ou retombe à 0 — rien d'autre.
  IF NEW.failed_attempts IS DISTINCT FROM OLD.failed_attempts
     AND NEW.failed_attempts <> 0
     AND NEW.failed_attempts <> OLD.failed_attempts + 1 THEN
    RAISE EXCEPTION 'account_secrets : failed_attempts s''incrémente de 1 ou retombe à 0 — jamais % -> %',
      OLD.failed_attempts, NEW.failed_attempts;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_account_secrets_guard
  BEFORE UPDATE ON account_secrets
  FOR EACH ROW EXECUTE FUNCTION guard_account_secret_update();

CREATE TRIGGER trg_account_secrets_no_delete
  BEFORE DELETE ON account_secrets
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- Standard 002 : tout ce que la base pose elle-même (id, status, retired_at,
-- failed_attempts initial, created_at) n'est JAMAIS accordé au client.
GRANT SELECT ON account_secrets TO user_core_app;
GRANT INSERT (account_id, secret_hash, is_temporary, expires_at)
  ON account_secrets TO user_core_app;
GRANT UPDATE (status, failed_attempts, locked_until)
  ON account_secrets TO user_core_app;
REVOKE DELETE, TRUNCATE ON account_secrets FROM user_core_app;
