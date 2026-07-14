-- =============================================================================
-- 008 — Le catalogue : le DROIT D'ACCÈS d'un compte à un programme.
--
-- CE QUE LE CATALOGUE N'EST PAS (CLAUDE.md §3.8, CDC §2.2) : un moteur
-- d'abonnement. Il dit « activé » ou « désactivé », et RIEN de plus. Tarifs,
-- échéances, relances, suspension pour impayé : ailleurs (Payment-Core, futur
-- module de facturation). Aucune colonne de tarification, de cycle de
-- facturation ou de renouvellement n'entre ici — et la garde CI §3.8 le
-- vérifie à chaque commit, pour que la règle ne dépende de la vigilance de
-- personne. (Elle a d'ailleurs refusé la première version de ce commentaire,
-- qui citait les motifs interdits : une garde littérale ne fait pas de
-- distinguo entre un nom de colonne et une prose qui l'énumère.)
--
-- LE CODE D'UN PROGRAMME EST UNE DONNÉE, JAMAIS UN ENUM : ajouter un programme
-- est un INSERT, pas une migration. Un ENUM ferait entrer les noms des
-- verticales dans le SCHÉMA — le jour où le cœur sait ce qu'est une école, il
-- est mort. (Et la garde A du dépôt refuserait le commit.)
--
-- Historique APPEND-ONLY (CDC §7) : désactiver un programme n'écrase JAMAIS la
-- ligne d'activation. Patron phone_claims, validé : transition de statut
-- BORNÉE (ACTIVE -> REVOKED seulement), ligne révoquée FIGÉE, horodatages
-- posés par la base, et réactiver = une LIGNE NEUVE. L'histoire de ce que la
-- famille a utilisé reste lisible pour toujours.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE program_status AS ENUM (
  'ACTIVE',
  'RETIRED'   -- le programme n'est plus proposé ; les droits déjà accordés survivent
);

CREATE TABLE programs (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code       text NOT NULL,
  label      text NOT NULL,
  status     program_status NOT NULL DEFAULT 'ACTIVE',
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_programs_code UNIQUE (code),
  -- Forme d'un code : minuscules, chiffres, tirets. Stable, dictable, et sans
  -- surprise dans une URL.
  CONSTRAINT chk_programs_code_shape CHECK (code ~ '^[a-z][a-z0-9-]{2,31}$'),
  CONSTRAINT chk_programs_retired_pair
    CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL))
);

CREATE TYPE program_grant_status AS ENUM ('ACTIVE', 'REVOKED');

CREATE TYPE program_grant_revoke_reason AS ENUM (
  'SELF',                 -- la famille a désactivé le programme
  'ADMIN',
  'ACCOUNT_DEACTIVATED'   -- cascade : le compte est mort
);

CREATE TABLE program_grants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id    uuid NOT NULL REFERENCES accounts(id),
  program_id    uuid NOT NULL REFERENCES programs(id),
  status        program_grant_status NOT NULL DEFAULT 'ACTIVE',
  granted_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz,
  revoke_reason program_grant_revoke_reason,
  CONSTRAINT chk_program_grants_revoked_pair
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CONSTRAINT chk_program_grants_revoked_reason
    CHECK ((status = 'REVOKED') = (revoke_reason IS NOT NULL))
);

-- Au plus UN droit ACTIVE par (compte, programme). L'historique des droits
-- révoqués reste, autant qu'il en faut.
CREATE UNIQUE INDEX uq_program_grants_active
  ON program_grants (account_id, program_id) WHERE status = 'ACTIVE';

CREATE INDEX idx_program_grants_account ON program_grants (account_id);
CREATE INDEX idx_program_grants_program ON program_grants (program_id);

-- -----------------------------------------------------------------------------
-- Gardes
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_program_grant_insert() RETURNS trigger AS $$
DECLARE
  account_status account_status;
  program_state program_status;
BEGIN
  SELECT status INTO account_status FROM accounts WHERE id = NEW.account_id FOR SHARE;
  IF account_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_grants : aucun droit ne naît sous un compte % (C13)', account_status
      USING ERRCODE = 'P0108';
  END IF;

  -- On n'accorde pas l'accès à un programme retiré du catalogue. (Les droits
  -- DÉJÀ accordés, eux, survivent au retrait : on ne coupe pas une famille
  -- parce qu'un programme cesse d'être proposé aux nouveaux.)
  SELECT status INTO program_state FROM programs WHERE id = NEW.program_id FOR SHARE;
  IF program_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_grants : le programme n''est plus proposé (%)', program_state
      USING ERRCODE = 'P0108';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
-- SECURITY DEFINER : le verrou de ligne (FOR SHARE) exige plus que le simple
-- SELECT, et le rôle applicatif n'a QUE SELECT sur programs — c'est voulu (le
-- catalogue est un acte d'administration). La garde ne doit pas dépendre d'un
-- droit qu'on lui refuse par ailleurs.
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_grants_guard_insert
  BEFORE INSERT ON program_grants
  FOR EACH ROW EXECUTE FUNCTION guard_program_grant_insert();

CREATE FUNCTION guard_program_grant_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.program_id IS DISTINCT FROM OLD.program_id
     OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
    RAISE EXCEPTION 'program_grants : contenu immuable — réactiver = une NOUVELLE ligne'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'program_grants : un droit révoqué est figé — réactiver = une NOUVELLE ligne'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status <> 'REVOKED' THEN
      RAISE EXCEPTION 'program_grants : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
    IF NEW.revoke_reason IS NULL THEN
      RAISE EXCEPTION 'program_grants : une révocation porte toujours son motif'
        USING ERRCODE = 'P0102';
    END IF;
    NEW.revoked_at := now();   -- la base horodate, jamais le client
  ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
     OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason THEN
    RAISE EXCEPTION 'program_grants : les horodatages de registre sont posés par la base'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_grants_guard_update
  BEFORE UPDATE ON program_grants
  FOR EACH ROW EXECUTE FUNCTION guard_program_grant_update();

CREATE TRIGGER trg_program_grants_no_delete
  BEFORE DELETE ON program_grants
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

CREATE TRIGGER trg_programs_no_delete
  BEFORE DELETE ON programs
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- Cascade C13, troisième extension : un compte désactivé perd ses DROITS.
-- (CREATE OR REPLACE : 004 et 006 sont fusionnées, donc immuables.)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cascade_account_deactivation() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'DEACTIVATED' AND OLD.status IS DISTINCT FROM NEW.status THEN
    UPDATE sessions
       SET status = 'REVOKED', revoke_reason = 'ADMIN'
     WHERE account_id = NEW.id
       AND status = 'ACTIVE';

    UPDATE phone_claims
       SET status = 'REVOKED', revoke_reason = 'ACCOUNT_DEACTIVATED'
     WHERE account_id = NEW.id
       AND status IN ('PENDING', 'ACTIVE');

    UPDATE program_grants
       SET status = 'REVOKED', revoke_reason = 'ACCOUNT_DEACTIVATED'
     WHERE account_id = NEW.id
       AND status = 'ACTIVE';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- Droits : le catalogue des programmes est un acte d'ADMINISTRATION — le
-- service le lit, il ne l'écrit pas. Un compte, lui, active et désactive SON
-- droit d'accès (et le service filtre sur account_id : BOLA, §6).
-- -----------------------------------------------------------------------------
GRANT SELECT ON programs TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON programs FROM user_core_app;

GRANT SELECT ON program_grants TO user_core_app;
GRANT INSERT (account_id, program_id) ON program_grants TO user_core_app;
GRANT UPDATE (status, revoke_reason) ON program_grants TO user_core_app;
REVOKE DELETE, TRUNCATE ON program_grants FROM user_core_app;
