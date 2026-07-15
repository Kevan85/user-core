-- =============================================================================
-- 013 — Le registre anti-rejeu des assertions de programme (LOT 4, étape 6).
--
-- Un programme obtient son jeton en présentant une ASSERTION SIGNÉE (JWT
-- EdDSA : son client_id, un jti unique, une échéance courte). Le rejeu d'une
-- assertion interceptée doit être IMPOSSIBLE — et l'impossibilité ne vit pas
-- dans un « if » du service : elle vit ici, dans une contrainte d'unicité.
-- Le service INSÈRE le jti ; s'il existe déjà, la base refuse (23505), et ce
-- refus EST le verdict de rejeu. Il n'y a pas de « WHERE déjà vu ? » à
-- écrire, donc pas de WHERE à oublier dans une v2.
--
-- Append-only : un jti consommé ne se libère JAMAIS (le libérer, c'est
-- réouvrir le rejeu). Les lignes expirées deviennent des archives — leur
-- purge éventuelle sera un acte d'exploitation sous le rôle propriétaire,
-- jamais un droit du service.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TABLE program_client_assertions (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  program_client_id uuid NOT NULL REFERENCES program_clients(id),
  jti               text NOT NULL,
  -- L'échéance DE L'ASSERTION (posée par le programme, bornée par le
  -- service) : au-delà, l'assertion est refusée pour expiration avant même
  -- de consulter ce registre — la ligne n'est plus qu'une archive.
  expires_at        timestamptz NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  -- LE mur : un (client, jti) ne s'enregistre qu'UNE fois.
  CONSTRAINT uq_program_client_assertions_jti UNIQUE (program_client_id, jti),
  CONSTRAINT chk_program_client_assertions_jti_shape
    CHECK (jti ~ '^[A-Za-z0-9_-]{8,128}$')
);

CREATE INDEX idx_program_client_assertions_client
  ON program_client_assertions (program_client_id, created_at);

-- Aucune assertion ne s'enregistre sous un client mort (P0108) — ceinture :
-- le service ne vérifie de toute façon que les clés ACTIVES de clients
-- ACTIFS, mais la garde ne dépend pas de sa discipline.
CREATE FUNCTION guard_program_client_assertion_insert() RETURNS trigger AS $$
DECLARE
  client_status program_client_status;
BEGIN
  SELECT status INTO client_status FROM program_clients
   WHERE id = NEW.program_client_id FOR SHARE;
  IF client_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_client_assertions : aucune assertion ne s''enregistre sous un client % (P0108)',
      client_status USING ERRCODE = 'P0108';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_client_assertions_guard_insert
  BEFORE INSERT ON program_client_assertions
  FOR EACH ROW EXECUTE FUNCTION guard_program_client_assertion_insert();

-- Un jti consommé est FIGÉ : ni réécriture, ni libération.
CREATE TRIGGER trg_program_client_assertions_no_update
  BEFORE UPDATE ON program_client_assertions
  FOR EACH ROW EXECUTE FUNCTION forbid_update();

CREATE TRIGGER trg_program_client_assertions_no_delete
  BEFORE DELETE ON program_client_assertions
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- Le service INSÈRE (c'est son verdict de rejeu) et LIT ; il ne retouche
-- jamais. created_at vient de la base.
GRANT SELECT ON program_client_assertions TO user_core_app;
GRANT INSERT (program_client_id, jti, expires_at)
  ON program_client_assertions TO user_core_app;
REVOKE UPDATE, DELETE, TRUNCATE ON program_client_assertions FROM user_core_app;
