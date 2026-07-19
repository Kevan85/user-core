-- =============================================================================
-- 019 — Le droit d'accès appartient à la PERSONNE (LOT 5, étape 6 — la
-- décision n°2 du cadrage Kevin, CDC §2.1.1.2) : « Scolaria pour Junior »,
-- jamais « la famille a Scolaria ». RAISON DÉCISIVE : à l'émancipation, il
-- n'y a RIEN à transférer — les accès étaient déjà les siens, il en prend la
-- main. Un compte GÈRE les droits des personnes dont il est responsable,
-- dont lui-même : c'est une question d'écran et de BOLA de service — la
-- base, elle, enregistre le droit DE LA PERSONNE.
--
-- C13 FINIT ICI : un compte désactivé ne perd plus que ses SESSIONS. Les
-- droits d'accès sont des faits de la personne — l'accès de Junior ne meurt
-- pas parce que le compte d'un de ses responsables meurt (l'invariant
-- orphelin de 017 garantit qu'il reste quelqu'un pour agir, ou un acte staff
-- pour le rétablir). La revendication de ligne était déjà sortie de la
-- cascade en 018.
--
-- LE DROIT NE NAÎT PLUS « SOUS UN COMPTE » : l'ancienne garde exigeait un
-- compte ACTIF au porteur du droit — un mineur sans compte est désormais le
-- cas NOMINAL. Aucun contrôle de vitalité ne le remplace : une personne n'a
-- pas de statut (zéro suppression), et QUI a le droit d'ouvrir un droit est
-- le BOLA du service et des fonctions (l'acteur, lui, reste contrôlé : mode
-- d'accès, matrice de réactivation — inchangés, transposés à la personne).
--
-- TRANSFORMATION : backfill compte → personne par jointure (1:1, aucune
-- information perdue — account_id est ensuite supprimé) ; DISABLE TRIGGER
-- USER borné au backfill (lignes REVOKED figées par P0103), réarmé aussitôt
-- et vérifié par le test C3 (pg_trigger.tgenabled) à chaque run.
-- L'index d'unicité GARDE SON NOM (les services le reconnaissent par nom).
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

ALTER TABLE program_grants ADD COLUMN person_id uuid REFERENCES persons(id);

ALTER TABLE program_grants DISABLE TRIGGER USER;
UPDATE program_grants g SET person_id = a.person_id
  FROM accounts a WHERE a.id = g.account_id;
ALTER TABLE program_grants ENABLE TRIGGER USER;

ALTER TABLE program_grants ALTER COLUMN person_id SET NOT NULL;

DROP INDEX uq_program_grants_active;
CREATE UNIQUE INDEX uq_program_grants_active
  ON program_grants (person_id, program_id) WHERE status = 'ACTIVE';

DROP INDEX idx_program_grants_account;
CREATE INDEX idx_program_grants_person ON program_grants (person_id);

ALTER TABLE program_grants DROP COLUMN account_id;

-- -----------------------------------------------------------------------------
-- La garde d'insertion, transposée à la personne. La matrice de réactivation
-- (008/012) ne change PAS d'un iota de sens : ce que la famille a fermé,
-- elle seule le rouvre ; ce qu'un tiers a retiré, la famille ne le rouvre
-- pas ; un programme ne pousse un droit que sur le mode accordé. La clé de
-- lecture passe simplement du compte à la personne.
-- (CREATE OR REPLACE : 008 et 012 sont fusionnées — patron 005.)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_program_grant_insert() RETURNS trigger AS $$
DECLARE
  p programs%ROWTYPE;
  last_grant program_grants%ROWTYPE;
BEGIN
  SELECT * INTO p FROM programs WHERE id = NEW.program_id FOR SHARE;
  IF p.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_grants : le programme n''est plus proposé (%)', p.status
      USING ERRCODE = 'P0108';
  END IF;

  IF p.access_mode = 'GRANTED' AND NEW.granted_by = 'SELF' THEN
    SELECT * INTO last_grant FROM program_grants g
     WHERE g.person_id = NEW.person_id
       AND g.program_id = NEW.program_id
     ORDER BY g.seq DESC
     LIMIT 1;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'program_grants : un programme sur accès accordé ne s''ouvre pas soi-même'
        USING ERRCODE = 'P0110';
    END IF;

    IF last_grant.revoke_reason IS DISTINCT FROM 'SELF' THEN
      RAISE EXCEPTION 'program_grants : accès retiré par un tiers (motif %) — la famille ne peut pas le rouvrir',
        last_grant.revoke_reason
        USING ERRCODE = 'P0110';
    END IF;
  END IF;

  IF NEW.granted_by = 'PROGRAM' THEN
    IF p.access_mode <> 'GRANTED' THEN
      RAISE EXCEPTION 'program_grants : un programme n''ouvre un droit que sur le mode accordé (LOT 4)'
        USING ERRCODE = 'P0110';
    END IF;

    SELECT * INTO last_grant FROM program_grants g
     WHERE g.person_id = NEW.person_id
       AND g.program_id = NEW.program_id
     ORDER BY g.seq DESC
     LIMIT 1;

    IF FOUND AND last_grant.revoke_reason = 'SELF' THEN
      RAISE EXCEPTION 'program_grants : la famille a fermé ce programme — elle seule le rouvre'
        USING ERRCODE = 'P0110';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION guard_program_grant_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.program_id IS DISTINCT FROM OLD.program_id
     OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
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

-- -----------------------------------------------------------------------------
-- C13, forme FINALE (engagement de l'étape 5, tenu ici) : un compte
-- désactivé ne perd que ses SESSIONS. La revendication de ligne (018) et les
-- droits d'accès (019) appartiennent à la personne, qui survit au compte.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cascade_account_deactivation() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'DEACTIVATED' AND OLD.status IS DISTINCT FROM NEW.status THEN
    UPDATE sessions
       SET status = 'REVOKED', revoke_reason = 'ADMIN'
     WHERE account_id = NEW.id
       AND status = 'ACTIVE';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- Accepter une invitation : le droit naît pour la PERSONNE du compte qui
-- accepte (la note « le droit reste au compte jusqu'à 019 » tombe ici).
-- Le BOLA « détenir la ligne » (018) et la matrice d'acteur ne changent pas.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION accept_program_invitation(p_invitation_id uuid, p_account_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  inv program_invitations%ROWTYPE;
  accepting_person_id uuid;
  last_grant program_grants%ROWTYPE;
  actor program_grant_actor;
BEGIN
  SELECT * INTO inv FROM program_invitations WHERE id = p_invitation_id FOR UPDATE;
  IF NOT FOUND OR inv.suppressed THEN
    RETURN 'UNKNOWN';
  END IF;
  IF inv.status <> 'PENDING' THEN
    RETURN 'ALREADY_SETTLED';
  END IF;
  IF inv.expires_at <= now() THEN
    UPDATE program_invitations SET status = 'EXPIRED' WHERE id = inv.id;
    RETURN 'EXPIRED';
  END IF;

  SELECT a.person_id INTO accepting_person_id FROM accounts a WHERE a.id = p_account_id;
  IF accepting_person_id IS NULL THEN
    RETURN 'UNKNOWN';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM phone_claims c
     WHERE c.person_id = accepting_person_id
       AND c.hmac_key_id = inv.hmac_key_id
       AND c.phone_hmac = inv.phone_hmac
       AND c.status = 'ACTIVE'
  ) THEN
    RETURN 'LINE_NOT_PROVEN';
  END IF;

  SELECT * INTO last_grant FROM program_grants g
   WHERE g.person_id = accepting_person_id
     AND g.program_id = inv.program_id
   ORDER BY g.seq DESC
   LIMIT 1;

  IF FOUND AND last_grant.status = 'ACTIVE' THEN
    NULL;
  ELSE
    actor := 'PROGRAM';
    IF FOUND AND last_grant.revoke_reason = 'SELF' THEN
      actor := 'SELF';
    END IF;
    INSERT INTO program_grants (person_id, program_id, granted_by)
    VALUES (accepting_person_id, inv.program_id, actor);
  END IF;

  UPDATE program_invitations
     SET status = 'ACCEPTED', accepted_account_id = p_account_id
   WHERE id = inv.id;

  RETURN 'ACCEPTED';
END;
$$;

-- -----------------------------------------------------------------------------
-- Droits : la colonne nouvelle porte le GRANT d'insertion (celui d'account_id
-- est parti avec la colonne). Le reste ne bouge pas.
-- -----------------------------------------------------------------------------
GRANT INSERT (person_id, program_id, granted_by) ON program_grants TO user_core_app;
