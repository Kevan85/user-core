-- =============================================================================
-- 005 — Codes d'erreur applicatifs sur TOUS les RAISE des gardes (002-004).
--
-- Pourquoi : le code applicatif attrapait une erreur de trigger en MATCHANT
-- SON TEXTE (auth.service.ts : err.message.includes('ne recule jamais')). Le
-- jour où quelqu'un reformule un message — pour le clarifier, en toute bonne
-- foi — la garde applicative tombe en silence. Un contrat entre la base et le
-- service ne s'écrit pas en français : il s'écrit en CODE.
--
-- 002, 003 et 004 sont FUSIONNÉES, donc immuables (le runner refuse un
-- checksum divergent, et c'est voulu) : on corrige par CREATE OR REPLACE dans
-- une migration signée, jamais en éditant le passé.
--
-- Huit familles, un code chacune (préfixe P0 = « applicatif » côté PostgreSQL) :
--   P0101 identité/contenu immuable        P0105 verrou qui recule
--   P0102 transition interdite             P0106 compteur d'échecs illégal
--   P0103 ligne terminale figée            P0107 suppression interdite
--   P0104 horodatage de registre réécrit   P0108 naissance sous parent mort
--
-- Les messages ne changent PAS : les tests existants qui les lisent restent
-- verts. C'est le code qui devient le contrat.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 002 — forbid_delete (P0107) et guard_account_update (P0101/P0102/P0104)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION forbid_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% : suppression interdite — corriger par statut (§3.10)', TG_TABLE_NAME
    USING ERRCODE = 'P0107';
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION guard_account_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.public_identifier IS DISTINCT FROM OLD.public_identifier
     OR NEW.role IS DISTINCT FROM OLD.role
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'accounts : identité immuable (id, public_identifier, role, created_at)'
      USING ERRCODE = 'P0101';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT (OLD.status = 'ACTIVE' AND NEW.status = 'DEACTIVATED') THEN
      RAISE EXCEPTION 'accounts : % -> % interdit — la réactivation n''est pas une transition posée en V1',
        OLD.status, NEW.status USING ERRCODE = 'P0102';
    END IF;
    NEW.deactivated_at := now();
  ELSIF NEW.deactivated_at IS DISTINCT FROM OLD.deactivated_at THEN
    RAISE EXCEPTION 'accounts : deactivated_at est posé par la base à la désactivation et ne se réécrit jamais'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 003 — guard_account_secret_update (P0101/P0103/P0104/P0105/P0106)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_account_secret_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
     OR NEW.is_temporary IS DISTINCT FROM OLD.is_temporary
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'account_secrets : contenu immuable — changer de secret = une NOUVELLE ligne'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'RETIRED' THEN
    RAISE EXCEPTION 'account_secrets : une ligne RETIRED est figée — un secret ne ressuscite jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    NEW.retired_at := now();
  ELSIF NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'account_secrets : retired_at est posé par la base au retrait et ne se réécrit jamais'
      USING ERRCODE = 'P0104';
  END IF;

  IF NEW.locked_until IS DISTINCT FROM OLD.locked_until
     AND OLD.locked_until IS NOT NULL AND OLD.locked_until > now()
     AND (NEW.locked_until IS NULL OR NEW.locked_until <= OLD.locked_until) THEN
    RAISE EXCEPTION 'account_secrets : un verrou dans le futur ne recule jamais (ni NULL, ni date antérieure)'
      USING ERRCODE = 'P0105';
  END IF;

  IF NEW.failed_attempts IS DISTINCT FROM OLD.failed_attempts
     AND NEW.failed_attempts <> 0
     AND NEW.failed_attempts <> OLD.failed_attempts + 1 THEN
    RAISE EXCEPTION 'account_secrets : failed_attempts s''incrémente de 1 ou retombe à 0 — jamais % -> %',
      OLD.failed_attempts, NEW.failed_attempts USING ERRCODE = 'P0106';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 004 — gardes des sessions et des jetons (P0101/P0102/P0103/P0104/P0108)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_session_insert() RETURNS trigger AS $$
DECLARE
  account_status account_status;
BEGIN
  SELECT status INTO account_status FROM accounts WHERE id = NEW.account_id FOR SHARE;
  IF account_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'sessions : aucune session ne naît sous un compte % (C13)', account_status
      USING ERRCODE = 'P0108';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION guard_session_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'sessions : identité immuable — prolonger une session = en ouvrir une nouvelle'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'sessions : une session révoquée est figée — elle ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.revoke_reason IS NULL THEN
      RAISE EXCEPTION 'sessions : une révocation porte toujours son motif'
        USING ERRCODE = 'P0102';
    END IF;
    NEW.revoked_at := now();
  ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
     OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason THEN
    RAISE EXCEPTION 'sessions : revoked_at et revoke_reason sont posés à la révocation, jamais avant ni après'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION guard_refresh_token_insert() RETURNS trigger AS $$
DECLARE
  session_row sessions%ROWTYPE;
BEGIN
  SELECT * INTO session_row FROM sessions WHERE id = NEW.session_id FOR SHARE;

  IF session_row.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'session_refresh_tokens : aucun jeton ne naît sous une session % (C5-bis)',
      session_row.status USING ERRCODE = 'P0108';
  END IF;
  IF session_row.absolute_expires_at <= now() THEN
    RAISE EXCEPTION 'session_refresh_tokens : la session a dépassé son échéance absolue (C5)'
      USING ERRCODE = 'P0108';
  END IF;
  IF NEW.expires_at > session_row.absolute_expires_at THEN
    RAISE EXCEPTION 'session_refresh_tokens : un jeton ne survit jamais à sa session (échéance absolue dépassée)'
      USING ERRCODE = 'P0108';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION guard_refresh_token_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.jti IS DISTINCT FROM OLD.jti
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'session_refresh_tokens : contenu immuable — tourner = émettre un successeur'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'session_refresh_tokens : un jeton révoqué est figé — il ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF OLD.status = 'ACTIVE' AND NEW.status = 'ROTATED' THEN
      IF NEW.grace_until IS NULL THEN
        RAISE EXCEPTION 'session_refresh_tokens : la rotation pose sa fenêtre de grâce'
          USING ERRCODE = 'P0102';
      END IF;
      NEW.rotated_at := now();
    ELSIF NEW.status = 'REVOKED' THEN
      IF NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
         OR NEW.grace_until IS DISTINCT FROM OLD.grace_until
         OR NEW.replaced_by_id IS DISTINCT FROM OLD.replaced_by_id THEN
        RAISE EXCEPTION 'session_refresh_tokens : la révocation ne retouche pas la rotation'
          USING ERRCODE = 'P0104';
      END IF;
    ELSE
      RAISE EXCEPTION 'session_refresh_tokens : % -> % interdit — aucun retour vers ACTIVE',
        OLD.status, NEW.status USING ERRCODE = 'P0102';
    END IF;
  ELSE
    IF NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
       OR NEW.grace_until IS DISTINCT FROM OLD.grace_until THEN
      RAISE EXCEPTION 'session_refresh_tokens : rotated_at et grace_until sont posés à la rotation, jamais réécrits'
        USING ERRCODE = 'P0104';
    END IF;
    IF NEW.replaced_by_id IS DISTINCT FROM OLD.replaced_by_id
       AND NOT (OLD.status = 'ROTATED' AND OLD.replaced_by_id IS NULL
                AND NEW.replaced_by_id IS NOT NULL) THEN
      RAISE EXCEPTION 'session_refresh_tokens : replaced_by_id est set-once, posé juste après la rotation'
        USING ERRCODE = 'P0104';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;
