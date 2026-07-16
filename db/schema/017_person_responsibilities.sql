-- =============================================================================
-- 017 — person_responsibilities : le lien de responsabilité, HISTORISÉ
-- (début, fin, motif — CDC §2.1.1.4), et LES MURS du lot personnes.
--
-- LE MUR PORTEUR — l'invariant d'émancipation (« invariant E »), DIFFÉRÉ au
-- commit, dans les DEUX directions :
--     une personne ne peut pas À LA FOIS avoir un compte ACTIF et être
--     l'ayant droit d'une responsabilité ACTIVE. (P0113)
-- C'est lui qui rend la coupure d'émancipation NON REPRÉSENTABLE (piège n°1 :
-- aucun chemin — service, job, v2, owner — ne peut créer un compte à un ayant
-- droit sans clore ses liens DANS LA MÊME transaction) et qui tue TOUS les
-- cycles (piège n°4) : un responsable exige un compte actif à l'insertion,
-- un ayant droit ne peut pas en avoir — tout nœud d'un cycle devrait être
-- les deux à la fois. Le trigger d'insertion n'est qu'une façade rapide ;
-- le verdict qui compte tombe AU COMMIT, sous owner comme sous rôle bridé.
--
-- L'INVARIANT ORPHELIN (P0114, différé) : clore la DERNIÈRE responsabilité
-- active d'une personne sans compte actif est refusé au commit — le
-- remplacement d'un responsable se fait dans la MÊME transaction (fin de
-- l'ancien + ajout du nouveau). Décision D-D : la désactivation du compte du
-- responsable, elle, ne touche PAS le lien (la tutelle est un fait de
-- registre, pas un artefact de session) — la sortie de cet état est l'ACTE
-- STAFF (contrôlé, tracé par le registre lui-même : ligne ENDED + motif +
-- ligne neuve portée par opened_by), jamais un self-service (conflit de
-- garde : le système ne tranche pas à la place d'un juge).
--
-- LE MUR DE MINORITÉ à l'insertion — et SA VRAIE RAISON : sans lui, un
-- MAJEUR redeviendrait rattachable comme ayant droit. Son compte désactivé
-- passe le contrôle « pas de compte ACTIF » (délibérément : un compte mort ne
-- verrouille pas la personne, 016) — seule la borne d'âge empêche alors un
-- ex-responsable de reprendre la main sur un adulte, et la « coupure nette »
-- du CDC §2.1.1.3 resterait réversible sans elle. NE PAS L'ASSOUPLIR.
--
-- LE COMPARATEUR (arbitrage D-C, exigence 1 — le verdict tombe ici) : le mur
-- n'a que l'ANNÉE (la date complète est chiffrée, délibérément). L'âge réel
-- est dans [diff-1, diff] où diff = année courante - birth_year. La règle :
-- LE MUR NE MORD JAMAIS SUR LE LÉGITIME — un vrai mineur (âge < seuil) a
-- toujours diff <= seuil, donc on REFUSE seulement diff > seuil (l'adulte
-- certain). Le doute à la frontière (un « tout juste 16 ans ») passe le mur
-- et c'est la FAÇADE du service, qui voit la date complète fournie, qui
-- tranche au jour près (§3.1). Symétriquement, le mur d'émancipation (020)
-- ACCEPTERA diff >= seuil — jamais plus dur. Le seuil vient de
-- emancipation_minimum_age(), qui échoue FERMÉ (P0112) : aucun NULL à
-- oublier ici.
--
-- ERRCODE : cette migration ajoute P0113 (coupure d'émancipation : ayant
-- droit actif ⇔ aucun compte actif) et P0114 (dernier responsable : la fin
-- du lien laisserait la personne sans personne pour agir).
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE responsibility_status AS ENUM ('ACTIVE', 'ENDED');

CREATE TYPE responsibility_end_reason AS ENUM (
  'EMANCIPATED',  -- coupure nette : la personne a acquis son compte (020)
  'ADMIN'         -- acte staff contrôlé et tracé — jamais un self-service
);

-- QUI a ouvert ce lien (patron program_grant_actor, 008).
CREATE TYPE responsibility_actor AS ENUM (
  'RESPONSIBLE',    -- un responsable déjà en place (ou le premier, au rattachement)
  'PLATFORM_STAFF'
);

CREATE TABLE person_responsibilities (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Ordre monotone, indépendant de l'horloge et du hasard (patron 008).
  seq                   bigint GENERATED ALWAYS AS IDENTITY,
  responsible_person_id uuid NOT NULL REFERENCES persons(id),
  dependent_person_id   uuid NOT NULL REFERENCES persons(id),
  opened_by             responsibility_actor NOT NULL,
  status                responsibility_status NOT NULL DEFAULT 'ACTIVE',
  started_at            timestamptz NOT NULL DEFAULT now(),
  ended_at              timestamptz,
  end_reason            responsibility_end_reason,
  -- Ceinture et bretelles du piège n°4 : le mur structurel (compte actif
  -- exigé du responsable, interdit à l'ayant droit) tue déjà tout cycle.
  CONSTRAINT chk_responsibilities_not_self
    CHECK (responsible_person_id <> dependent_person_id),
  CONSTRAINT chk_responsibilities_ended_pair
    CHECK ((status = 'ENDED') = (ended_at IS NOT NULL)),
  CONSTRAINT chk_responsibilities_ended_reason
    CHECK ((status = 'ENDED') = (end_reason IS NOT NULL))
);

-- Au plus UN lien ACTIF par couple (responsable, ayant droit) ; l'histoire
-- des liens clos reste, autant qu'il en faut.
CREATE UNIQUE INDEX uq_person_responsibilities_active
  ON person_responsibilities (responsible_person_id, dependent_person_id)
  WHERE status = 'ACTIVE';

CREATE INDEX idx_responsibilities_dependent ON person_responsibilities (dependent_person_id);
CREATE INDEX idx_responsibilities_responsible ON person_responsibilities (responsible_person_id);

-- -----------------------------------------------------------------------------
-- Façade rapide à l'insertion (le mur porteur est DIFFÉRÉ, plus bas).
-- SECURITY DEFINER : lit accounts et persons au-delà des droits du rôle.
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_responsibility_insert() RETURNS trigger AS $$
DECLARE
  v_birth_year smallint;
  v_min_age integer;
BEGIN
  -- Un responsable AGIT : il lui faut un compte ACTIF au moment du lien.
  -- (FOR SHARE : sérialise avec une désactivation concurrente.)
  IF NOT EXISTS (SELECT 1 FROM accounts a
                  WHERE a.person_id = NEW.responsible_person_id
                    AND a.status = 'ACTIVE'
                  FOR SHARE) THEN
    RAISE EXCEPTION 'person_responsibilities : le responsable n''a aucun compte actif'
      USING ERRCODE = 'P0108';
  END IF;

  -- Direction immédiate de l'invariant E (le différé re-vérifie au commit).
  IF EXISTS (SELECT 1 FROM accounts a
              WHERE a.person_id = NEW.dependent_person_id
                AND a.status = 'ACTIVE'
              FOR SHARE) THEN
    RAISE EXCEPTION 'person_responsibilities : l''ayant droit a un compte actif — une personne autonome n''a pas de responsable (coupure d''émancipation)'
      USING ERRCODE = 'P0113';
  END IF;

  -- LA COUPURE EST IRRÉVERSIBLE (C11, CDC §2.1.1.3) : une personne émancipée
  -- ne redevient JAMAIS un ayant droit — même si son compte meurt ensuite
  -- (un compte désactivé passe le contrôle ci-dessus, délibérément), même
  -- dans l'année frontière où le mur de minorité la laisserait passer. Le
  -- registre porte déjà ce fait (end_reason = 'EMANCIPATED') : le mur le
  -- consulte. La course « émancipation concurrente » n'a pas besoin d'être
  -- traitée ici : elle crée un compte ACTIF, et l'invariant E différé
  -- l'attrape au commit quel que soit l'ordre des transactions.
  IF EXISTS (SELECT 1 FROM person_responsibilities r
              WHERE r.dependent_person_id = NEW.dependent_person_id
                AND r.end_reason = 'EMANCIPATED') THEN
    RAISE EXCEPTION 'person_responsibilities : personne émancipée — la coupure est définitive, aucun responsable ne revient'
      USING ERRCODE = 'P0113';
  END IF;

  -- Le mur de minorité (voir l'en-tête : sa raison est la coupure nette).
  SELECT p.birth_year INTO v_birth_year FROM persons p
   WHERE p.id = NEW.dependent_person_id FOR SHARE;
  IF v_birth_year IS NULL THEN
    RAISE EXCEPTION 'person_responsibilities : un ayant droit sans borne d''âge n''est pas rattachable'
      USING ERRCODE = 'P0111';
  END IF;
  v_min_age := emancipation_minimum_age();  -- échoue FERMÉ (P0112), jamais NULL
  IF EXTRACT(YEAR FROM now())::int - v_birth_year > v_min_age THEN
    RAISE EXCEPTION 'person_responsibilities : la personne est majeure au sens du seuil — un adulte n''a pas de responsable'
      USING ERRCODE = 'P0111';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_responsibilities_guard_insert
  BEFORE INSERT ON person_responsibilities
  FOR EACH ROW EXECUTE FUNCTION guard_responsibility_insert();

CREATE FUNCTION guard_responsibility_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.seq IS DISTINCT FROM OLD.seq
     OR NEW.responsible_person_id IS DISTINCT FROM OLD.responsible_person_id
     OR NEW.dependent_person_id IS DISTINCT FROM OLD.dependent_person_id
     OR NEW.opened_by IS DISTINCT FROM OLD.opened_by
     OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
    RAISE EXCEPTION 'person_responsibilities : contenu immuable — remplacer un responsable = une NOUVELLE ligne'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'ENDED' THEN
    RAISE EXCEPTION 'person_responsibilities : un lien clos est figé — il ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status <> 'ENDED' THEN
      RAISE EXCEPTION 'person_responsibilities : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
    IF NEW.end_reason IS NULL THEN
      RAISE EXCEPTION 'person_responsibilities : une fin de lien porte toujours son motif'
        USING ERRCODE = 'P0102';
    END IF;
    NEW.ended_at := now();   -- la base horodate, jamais le client
  ELSIF NEW.ended_at IS DISTINCT FROM OLD.ended_at
     OR NEW.end_reason IS DISTINCT FROM OLD.end_reason THEN
    RAISE EXCEPTION 'person_responsibilities : les horodatages de registre sont posés par la base'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_responsibilities_guard_update
  BEFORE UPDATE ON person_responsibilities
  FOR EACH ROW EXECUTE FUNCTION guard_responsibility_update();

CREATE TRIGGER trg_responsibilities_no_delete
  BEFORE DELETE ON person_responsibilities
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- LE MUR PORTEUR : l'invariant E, différé au COMMIT, les deux directions.
-- READ COMMITTED : un trigger différé ré-évalue avec un instantané pris au
-- commit — une course entre « créer le compte » et « poser le lien » dans
-- deux transactions se fait attraper par celle qui committe en second.
-- -----------------------------------------------------------------------------
CREATE FUNCTION assert_dependent_has_no_active_account() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'ACTIVE'
     AND EXISTS (SELECT 1 FROM accounts a
                  WHERE a.person_id = NEW.dependent_person_id
                    AND a.status = 'ACTIVE') THEN
    RAISE EXCEPTION 'invariant d''émancipation : l''ayant droit % a un compte actif au commit', NEW.dependent_person_id
      USING ERRCODE = 'P0113';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE CONSTRAINT TRIGGER trg_responsibilities_emancipation_cut
  AFTER INSERT OR UPDATE ON person_responsibilities
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_dependent_has_no_active_account();

CREATE FUNCTION assert_account_person_not_dependent() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'ACTIVE'
     AND EXISTS (SELECT 1 FROM person_responsibilities r
                  WHERE r.dependent_person_id = NEW.person_id
                    AND r.status = 'ACTIVE') THEN
    RAISE EXCEPTION 'invariant d''émancipation : la personne du compte est encore l''ayant droit d''un lien actif — la coupure se fait dans la MÊME transaction'
      USING ERRCODE = 'P0113';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE CONSTRAINT TRIGGER trg_accounts_emancipation_cut
  AFTER INSERT OR UPDATE ON accounts
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_account_person_not_dependent();

-- L'invariant orphelin : la fin d'un lien ne laisse jamais une personne sans
-- compte actif ET sans responsable actif. Le remplacement est ATOMIQUE.
CREATE FUNCTION assert_dependent_not_orphaned() RETURNS trigger AS $$
BEGIN
  IF OLD.status = 'ACTIVE' AND NEW.status = 'ENDED'
     AND NOT EXISTS (SELECT 1 FROM person_responsibilities r
                      WHERE r.dependent_person_id = NEW.dependent_person_id
                        AND r.status = 'ACTIVE')
     AND NOT EXISTS (SELECT 1 FROM accounts a
                      WHERE a.person_id = NEW.dependent_person_id
                        AND a.status = 'ACTIVE') THEN
    RAISE EXCEPTION 'person_responsibilities : dernier lien actif — le remplacement du responsable se fait dans la même transaction'
      USING ERRCODE = 'P0114';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE CONSTRAINT TRIGGER trg_responsibilities_no_orphan
  AFTER UPDATE ON person_responsibilities
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION assert_dependent_not_orphaned();

-- -----------------------------------------------------------------------------
-- attach_dependent() : LE chemin du rattachement — la personne mineure et son
-- PREMIER lien naissent ensemble, une transaction. La personne naît par
-- create_person() (C9 : une porte, pour toujours). L'identité civile est
-- EXIGÉE ici : un ayant droit est rattaché POUR être identifié auprès des
-- programmes — c'est sa finalité écrite ; un rattachement anonyme n'a pas de
-- sens (et le mur de minorité exige la borne d'âge de toute façon).
-- -----------------------------------------------------------------------------
CREATE FUNCTION attach_dependent(
  p_responsible_person_id       uuid,
  p_dependent_public_identifier text,
  p_dependent_erasure_salt      bytea,
  p_dependent_identity_encrypted text,
  p_dependent_enc_key_id        text,
  p_dependent_birth_year        integer,
  p_opened_by                   responsibility_actor
) RETURNS TABLE (dependent_person_id uuid, responsibility_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  new_person_id uuid;
  new_link_id uuid;
BEGIN
  IF p_dependent_identity_encrypted IS NULL
     OR p_dependent_enc_key_id IS NULL
     OR p_dependent_birth_year IS NULL THEN
    RAISE EXCEPTION 'attach_dependent : un ayant droit naît identifié (blob, clé, année exigés)'
      USING ERRCODE = 'P0111';
  END IF;

  new_person_id := create_person(p_dependent_public_identifier, p_dependent_erasure_salt,
                                 p_dependent_identity_encrypted, p_dependent_enc_key_id,
                                 p_dependent_birth_year);

  INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
  VALUES (p_responsible_person_id, new_person_id, p_opened_by)
  RETURNING id INTO new_link_id;

  dependent_person_id := new_person_id;
  responsibility_id := new_link_id;
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION attach_dependent(uuid, text, bytea, text, text, integer, responsibility_actor)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION attach_dependent(uuid, text, bytea, text, text, integer, responsibility_actor)
  TO user_core_app;

-- -----------------------------------------------------------------------------
-- end_responsibility() : LE chemin de clôture d'un lien (C11, CDC §2.1.1.4).
-- « Retirer un responsable est un acte contrôlé et tracé, JAMAIS un
-- self-service » est une règle de la BASE, pas du service : le rôle de
-- l'acteur est une donnée d'accounts — la base n'a besoin de personne pour
-- le lire. Le rôle applicatif PERD tout droit d'UPDATE : aucun chemin —
-- endpoint d'admin, job, v2 — ne peut clore un lien sans passer ici. La
-- symétrie est rétablie : naître = attach_dependent()/INSERT gardé, mourir =
-- end_responsibility(). (L'émancipation, 020, clôturera par SA fonction
-- SECURITY DEFINER — le REVOKE ne la concerne pas.)
-- Le remplacement éventuel est ATOMIQUE (même transaction) ; les murs
-- différés (orphelin P0114, coupure P0113) rendent leur verdict au commit.
-- Verdicts : ENDED · FORBIDDEN (acteur non-staff ou inactif) · UNKNOWN.
-- -----------------------------------------------------------------------------
CREATE FUNCTION end_responsibility(
  p_responsibility_id                 uuid,
  p_actor_account_id                  uuid,
  p_replacement_responsible_person_id uuid
) RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor accounts%ROWTYPE;
  link person_responsibilities%ROWTYPE;
BEGIN
  SELECT * INTO actor FROM accounts WHERE id = p_actor_account_id FOR SHARE;
  IF NOT FOUND
     OR actor.status <> 'ACTIVE'
     OR actor.role NOT IN ('PLATFORM_STAFF', 'PLATFORM_ADMIN') THEN
    verdict := 'FORBIDDEN'; RETURN NEXT; RETURN;
  END IF;

  SELECT * INTO link FROM person_responsibilities
   WHERE id = p_responsibility_id AND status = 'ACTIVE'
   FOR UPDATE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN'; RETURN NEXT; RETURN;
  END IF;

  IF p_replacement_responsible_person_id IS NOT NULL THEN
    INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
    VALUES (p_replacement_responsible_person_id, link.dependent_person_id, 'PLATFORM_STAFF');
  END IF;

  UPDATE person_responsibilities
     SET status = 'ENDED', end_reason = 'ADMIN'
   WHERE id = p_responsibility_id;

  verdict := 'ENDED'; RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION end_responsibility(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION end_responsibility(uuid, uuid, uuid) TO user_core_app;

-- -----------------------------------------------------------------------------
-- Droits : ajouter un co-responsable à une personne EXISTANTE est un INSERT
-- direct (les triggers portent les murs) ; CLORE un lien n'est PAS un droit
-- du rôle applicatif (C11) — end_responsibility() est le seul chemin. Ce que
-- la base pose n'est jamais accordé au client.
-- -----------------------------------------------------------------------------
GRANT SELECT ON person_responsibilities TO user_core_app;
GRANT INSERT (responsible_person_id, dependent_person_id, opened_by)
  ON person_responsibilities TO user_core_app;
-- Les deux formes, table ET colonne (piège Postgres vérifié en 011 : un
-- REVOKE de table ne retire pas un GRANT de colonne) — ici aucun GRANT
-- UPDATE n'a jamais existé dans ce fichier, la forme colonne est la ceinture.
REVOKE UPDATE ON person_responsibilities FROM user_core_app;
REVOKE UPDATE (status, end_reason) ON person_responsibilities FROM user_core_app;
REVOKE DELETE, TRUNCATE ON person_responsibilities FROM user_core_app;
