-- =============================================================================
-- 016 — accounts.person_id : un compte appartient à UNE personne (LOT 5,
-- étape 3 ; CDC §2.1). Le COMPTE est le moyen d'agir, la PERSONNE est
-- l'identité : désormais aucun compte n'existe sans la personne qu'il fait
-- agir — non représentable, pas une convention.
--
-- TRANSFORMATION FAIL-CLOSED, et pourquoi elle a le droit d'être stricte :
-- transformer des comptes existants exigerait de fabriquer, pour chacun, un
-- identifiant public de personne (CSPRNG — patron 002 : jamais énumérable)
-- et un sel d'effacement de 32 octets (CSPRNG aussi). Le SQL pur n'a ni l'un
-- ni l'autre (random() n'est pas cryptographique ; gen_random_bytes exige une
-- extension bannie du socle). Or AUCUNE base déployée ne porte de comptes
-- (le LOT prod n'existe pas ; dev et CI migrent des bases vierges). La
-- migration VÉRIFIE donc cette vacuité et REFUSE net si elle est démentie :
-- le jour — improbable — où des comptes existeraient, la réponse est une
-- migration de backfill OUTILLÉE (générateurs du service), écrite ce jour-là,
-- jamais un random() qui fabrique des identifiants devinables en silence.
--
-- AU PLUS UN COMPTE ACTIF PAR PERSONNE (unique partiel) : un compte désactivé
-- ne verrouille pas la personne à vie — la ré-acquisition d'un moyen d'agir
-- (émancipation, récupération) reste possible sans jamais faire coexister
-- deux comptes actifs de la même personne.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM accounts) THEN
    RAISE EXCEPTION '016 : des comptes existent déjà — cette transformation exige un backfill OUTILLÉ (identifiants et sels CSPRNG), à écrire en migration dédiée';
  END IF;
END
$$;

-- Table vérifiée vide : la colonne naît NOT NULL, sans étape nullable.
ALTER TABLE accounts
  ADD COLUMN person_id uuid NOT NULL REFERENCES persons(id);

-- Au plus UN compte ACTIF par personne. L'histoire (comptes désactivés)
-- reste, autant qu'il en faut.
CREATE UNIQUE INDEX uq_accounts_active_person
  ON accounts (person_id) WHERE status = 'ACTIVE';

CREATE INDEX idx_accounts_person ON accounts (person_id);

-- -----------------------------------------------------------------------------
-- Le rattachement est IMMUABLE : un compte ne change jamais de personne (un
-- transfert de compte serait un vol d'identité avec les droits de la victime).
-- CREATE OR REPLACE : la forme précédente vit dans 005, immuable — patron 005.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_account_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.public_identifier IS DISTINCT FROM OLD.public_identifier
     OR NEW.role IS DISTINCT FROM OLD.role
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'accounts : identité immuable (id, public_identifier, role, person_id, created_at)'
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
-- create_account() refondu : PERSONNE + compte + secret, UNE transaction.
-- Le chemin unique de 011 reste le chemin unique (F5 est mort, il le reste :
-- le REVOKE INSERT ON accounts de 011 n'est pas touché) — il crée désormais
-- aussi la personne, par l'INSERT du propriétaire (les gardes de 014
-- s'appliquent à l'intérieur : forme de l'identifiant, taille du sel).
--
-- Le rattachement d'un compte à une personne DÉJÀ existante (émancipation)
-- n'est PAS ce chemin : il arrive avec sa machinerie propre (020) et son mur
-- (l'invariant d'émancipation, 017) — livrer cette porte avant ce mur
-- ouvrirait le piège n°1 du lot le temps d'une étape.
-- -----------------------------------------------------------------------------
DROP FUNCTION create_account(text, account_role, text, boolean, timestamptz);

CREATE FUNCTION create_account(
  p_public_identifier        text,
  p_role                     account_role,
  p_secret_hash              text,
  p_is_temporary             boolean,
  p_expires_at               timestamptz,
  p_person_public_identifier text,
  p_person_erasure_salt      bytea
) RETURNS TABLE (account_id uuid, person_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  new_person_id  uuid;
  new_account_id uuid;
BEGIN
  INSERT INTO persons (public_identifier, erasure_salt)
  VALUES (p_person_public_identifier, p_person_erasure_salt)
  RETURNING id INTO new_person_id;

  INSERT INTO accounts (public_identifier, role, person_id)
  VALUES (p_public_identifier, p_role, new_person_id)
  RETURNING id INTO new_account_id;

  INSERT INTO account_secrets (account_id, secret_hash, is_temporary, expires_at)
  VALUES (new_account_id, p_secret_hash, p_is_temporary, p_expires_at);

  account_id := new_account_id;
  person_id := new_person_id;
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION create_account(text, account_role, text, boolean, timestamptz, text, bytea)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_account(text, account_role, text, boolean, timestamptz, text, bytea)
  TO user_core_app;
