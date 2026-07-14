-- =============================================================================
-- 006 — phone_claims : la revendication d'une ligne téléphonique.
--
-- LE NUMÉRO N'EXISTE JAMAIS EN CLAIR (CDC §6.1) : empreinte HMAC déterministe
-- (indexée, pour l'unicité et la limitation de débit) + valeur chiffrée
-- AES-256-GCM. Les deux portent leur key_id, et leurs cycles de vie sont
-- DISTINCTS : tourner la clé de chiffrement est ordinaire ; tourner la clé
-- d'empreinte oblige à déchiffrer et re-hacher TOUTE la PII.
--
-- Aucune colonne téléphone dans accounts, ni ici « en attendant » : la
-- possession se prouve (007), elle ne se déclare pas.
--
-- Le piège que ce fichier ferme (Q2) : si deux hmac_key_id coexistaient, la
-- MÊME ligne physique pourrait porter deux empreintes différentes, donc deux
-- revendications ACTIVE — et l'unicité mondiale tomberait EN SILENCE. D'où :
--   1. l'unicité porte sur le COUPLE (hmac_key_id, phone_hmac), jamais sur
--      l'empreinte seule ;
--   2. une table de référence nomme LA clé d'empreinte active, le rôle
--      applicatif ne peut pas l'écrire, et un trigger impose que toute
--      revendication VIVANTE la porte. Une rotation devient donc forcément
--      une migration signée qui re-hache et bascule la référence : la
--      « procédure exceptionnelle » du CDC cesse d'être une phrase dans un
--      document, elle devient non contournable.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- La clé d'empreinte active : UNE ligne, écrite par migration, jamais par le
-- service. Le matériel de la clé vit dans Vault ; ici ne vit que son NOM.
-- -----------------------------------------------------------------------------
CREATE TABLE hmac_key_reference (
  singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  hmac_key_id text NOT NULL,
  rotated_at timestamptz NOT NULL DEFAULT now()
);

-- Le premier nom de clé est CONTRACTUEL : tout environnement démarre sur H1
-- (le matériel, lui, diffère partout — dev, CI, prod). Une rotation = une
-- migration signée qui re-hache la PII puis met cette ligne à jour.
INSERT INTO hmac_key_reference (hmac_key_id) VALUES ('H1');

-- Lecture seule pour le service (il doit pouvoir vérifier qu'il est aligné
-- avec la base) ; aucune écriture, jamais.
GRANT SELECT ON hmac_key_reference TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON hmac_key_reference FROM user_core_app;

CREATE FUNCTION active_hmac_key_id() RETURNS text AS $$
  SELECT hmac_key_id FROM hmac_key_reference WHERE singleton;
$$ LANGUAGE sql STABLE
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- La revendication
-- -----------------------------------------------------------------------------
CREATE TYPE phone_claim_status AS ENUM (
  'PENDING',   -- déclarée, possession NON prouvée — ne vaut rien pour payer
  'ACTIVE',    -- possession prouvée par la SIM (SMS ou appel)
  'REVOKED'    -- révoquée, jamais supprimée (§3.10), jamais ressuscitée
);

-- Le niveau de preuve ne DESCEND jamais (patron assurance_level de
-- payment-core) : on peut prouver, jamais « dé-prouver ».
CREATE TYPE phone_assurance_level AS ENUM (
  'DECLARED',  -- le compte l'affirme — aucune valeur de preuve
  'PROVEN'     -- la SIM a répondu
);

CREATE TYPE phone_revoke_reason AS ENUM (
  'SUPERSEDED',           -- numéro recyclé : une preuve PLUS RÉCENTE a gagné (007)
  'REPLACED',             -- le compte a déclaré un autre numéro à la place
  'ACCOUNT_DEACTIVATED',  -- cascade : le compte est mort
  'ADMIN'
);

CREATE TABLE phone_claims (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id      uuid NOT NULL REFERENCES accounts(id),
  phone_hmac      text NOT NULL,   -- empreinte déterministe — JAMAIS le clair
  hmac_key_id     text NOT NULL,   -- la clé sous laquelle l'empreinte a été calculée
  phone_encrypted text NOT NULL,   -- AES-256-GCM ; illisible au rôle applicatif
  enc_key_id      text NOT NULL,   -- cycle de vie DISTINCT de hmac_key_id
  status          phone_claim_status NOT NULL DEFAULT 'PENDING',
  assurance_level phone_assurance_level NOT NULL DEFAULT 'DECLARED',
  verified_at     timestamptz,
  revoked_at      timestamptz,
  revoke_reason   phone_revoke_reason,
  created_at      timestamptz NOT NULL DEFAULT now(),

  -- « ACTIF mais NON PROUVÉ » est NON REPRÉSENTABLE : aucun chemin d'appel ne
  -- pourra jamais activer un numéro sans que la SIM ait répondu.
  -- ⚠️ IMPLICATION, jamais équivalence : une revendication RÉVOQUÉE reste
  -- PROUVÉE (le niveau de preuve ne descend jamais — CDC §7). Une ligne
  -- recyclée garde dans l'historique le fait que cette SIM avait bien
  -- répondu, ce jour-là. L'équivalence rendrait la révocation impossible.
  CONSTRAINT chk_phone_claims_active_is_proven
    CHECK (status <> 'ACTIVE' OR assurance_level = 'PROVEN'),
  CONSTRAINT chk_phone_claims_proven_is_dated
    CHECK ((assurance_level = 'PROVEN') = (verified_at IS NOT NULL)),
  CONSTRAINT chk_phone_claims_revoked_pair
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CONSTRAINT chk_phone_claims_revoked_reason
    CHECK ((status = 'REVOKED') = (revoke_reason IS NOT NULL))
);

-- UNICITÉ MONDIALE de la ligne : au plus UNE revendication ACTIVE par ligne
-- physique. Le COUPLE (clé, empreinte), jamais l'empreinte seule (Q2).
CREATE UNIQUE INDEX uq_phone_claims_active_line
  ON phone_claims (hmac_key_id, phone_hmac) WHERE status = 'ACTIVE';

-- Une seule revendication VIVANTE par compte (Q3) : déclarer un autre numéro
-- révoque la précédente (REPLACED). Sans cela, un compte accumulerait des
-- numéros de TIERS — de la PII qu'on n'a aucune raison de détenir, et une
-- surface d'énumération offerte.
CREATE UNIQUE INDEX uq_phone_claims_alive_per_account
  ON phone_claims (account_id) WHERE status IN ('PENDING', 'ACTIVE');

-- La limitation de débit par LIGNE (007) interroge l'empreinte : elle protège
-- le téléphone d'un TIERS, pas notre facture.
CREATE INDEX idx_phone_claims_hmac ON phone_claims (phone_hmac);
CREATE INDEX idx_phone_claims_account ON phone_claims (account_id);

-- -----------------------------------------------------------------------------
-- Gardes
-- -----------------------------------------------------------------------------
-- SECURITY DEFINER : le trigger lit hmac_key_reference (le rôle applicatif n'a
-- qu'un SELECT, mais un futur durcissement pourrait le lui retirer — la garde
-- ne doit pas en dépendre).
CREATE FUNCTION guard_phone_claim_insert() RETURNS trigger AS $$
BEGIN
  -- Une revendication naît TOUJOURS sous la clé d'empreinte active : sinon la
  -- rotation laisserait entrer des lignes hors référence, et l'unicité
  -- mondiale se fissurerait en silence.
  IF NEW.hmac_key_id <> active_hmac_key_id() THEN
    RAISE EXCEPTION 'phone_claims : empreinte calculée sous la clé « % », active = « % » — une rotation est une migration signée',
      NEW.hmac_key_id, active_hmac_key_id() USING ERRCODE = 'P0109';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_phone_claims_guard_insert
  BEFORE INSERT ON phone_claims
  FOR EACH ROW EXECUTE FUNCTION guard_phone_claim_insert();

CREATE FUNCTION guard_phone_claim_update() RETURNS trigger AS $$
BEGIN
  -- Le contenu d'une revendication est IMMUABLE : on ne « corrige » pas un
  -- numéro, on en déclare un autre et on révoque celui-ci.
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.phone_hmac IS DISTINCT FROM OLD.phone_hmac
     OR NEW.hmac_key_id IS DISTINCT FROM OLD.hmac_key_id
     OR NEW.phone_encrypted IS DISTINCT FROM OLD.phone_encrypted
     OR NEW.enc_key_id IS DISTINCT FROM OLD.enc_key_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'phone_claims : contenu immuable — déclarer un autre numéro, révoquer celui-ci'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'phone_claims : une revendication révoquée est figée — elle ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  -- Le niveau de preuve ne descend JAMAIS.
  IF OLD.assurance_level = 'PROVEN' AND NEW.assurance_level = 'DECLARED' THEN
    RAISE EXCEPTION 'phone_claims : le niveau de preuve ne descend jamais (PROVEN -> DECLARED)'
      USING ERRCODE = 'P0102';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'ACTIVE' THEN
      -- Activer, c'est constater que la SIM a répondu : la base horodate.
      IF NEW.assurance_level <> 'PROVEN' THEN
        RAISE EXCEPTION 'phone_claims : une revendication ne devient ACTIVE que PROUVÉE (SMS ou appel)'
          USING ERRCODE = 'P0102';
      END IF;
      -- Une activation exige la clé d'empreinte ACTIVE (cf. INSERT).
      IF NEW.hmac_key_id <> active_hmac_key_id() THEN
        RAISE EXCEPTION 'phone_claims : activation sous une clé d''empreinte périmée'
          USING ERRCODE = 'P0109';
      END IF;
      NEW.verified_at := now();
    ELSIF NEW.status = 'REVOKED' THEN
      IF NEW.revoke_reason IS NULL THEN
        RAISE EXCEPTION 'phone_claims : une révocation porte toujours son motif'
          USING ERRCODE = 'P0102';
      END IF;
      NEW.revoked_at := now();
    ELSE
      RAISE EXCEPTION 'phone_claims : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
  ELSE
    IF NEW.verified_at IS DISTINCT FROM OLD.verified_at
       OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason THEN
      RAISE EXCEPTION 'phone_claims : les horodatages de registre sont posés par la base, jamais réécrits'
        USING ERRCODE = 'P0104';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_phone_claims_guard_update
  BEFORE UPDATE ON phone_claims
  FOR EACH ROW EXECUTE FUNCTION guard_phone_claim_update();

CREATE TRIGGER trg_phone_claims_no_delete
  BEFORE DELETE ON phone_claims
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- Cascade C13 étendue : un compte désactivé perd AUSSI sa revendication.
-- (CREATE OR REPLACE : 004 est fusionnée, donc immuable.)
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
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- Droits : phone_encrypted est ABSENT du SELECT (patron C9/C10). Le service ne
-- lit jamais un numéro « au cas où » ; le déchiffrement passera par un chemin
-- contrôlé, au moment d'envoyer, et par lui seul.
-- Le service ne peut PAS écrire assurance_level : il lui est donc
-- structurellement impossible d'activer une revendication (le CHECK exige
-- PROVEN). Seule la fonction de vérification (007, SECURITY DEFINER) le peut.
-- -----------------------------------------------------------------------------
GRANT SELECT (id, account_id, phone_hmac, hmac_key_id, enc_key_id, status,
              assurance_level, verified_at, revoked_at, revoke_reason, created_at)
  ON phone_claims TO user_core_app;
GRANT INSERT (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
  ON phone_claims TO user_core_app;
GRANT UPDATE (status, revoke_reason) ON phone_claims TO user_core_app;
REVOKE DELETE, TRUNCATE ON phone_claims FROM user_core_app;
