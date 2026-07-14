-- =============================================================================
-- 010 — L'identité cliente des programmes : la porte d'entrée de l'API /v1.
--
-- UN PROGRAMME EST UN CLIENT EXTERNE COMME UN AUTRE (CONTRAT §1) : il parle à
-- User-Core par l'API publique, sous une identité cliente révocable. Un
-- programme compromis se coupe d'un statut, sans toucher aux autres.
--
-- AUTHENTIFICATION PAR SIGNATURE Ed25519 (patron payment-core
-- 005_applications.sql, arbitrage Auditeur du 15/07/2026) : le programme
-- signe avec sa clé PRIVÉE — qu'il génère et garde chez lui — et User-Core
-- vérifie avec la clé PUBLIQUE enregistrée ici. AUCUN secret partagé : nous
-- ne détenons jamais de quoi usurper un programme, il n'existe aucun instant
-- où un secret transite, et Scolaria implémente la même mécanique que pour
-- Payment-Core.
--
-- ROTATION = NOUVELLE LIGNE (patron 003) : une clé ne se réécrit pas, on en
-- enregistre une neuve et l'ancienne passe REVOKED, figée. Au plus UNE clé
-- ACTIVE par client (index unique partiel) : la clé qui vérifie est toujours
-- sans ambiguïté.
--
-- CE QUE LE SERVICE NE PEUT PAS FAIRE, PAR CONSTRUCTION : créer, modifier ou
-- révoquer une identité cliente (aucun GRANT d'écriture — c'est un acte
-- d'administration, patron programs 008). Il LIT les clés publiques — qui
-- sont publiques — et vérifie des signatures. C'est tout.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE program_client_status AS ENUM (
  'ACTIVE',
  'REVOKED'   -- coupé, jamais supprimé (§3.10), jamais réactivé
);

CREATE TYPE program_client_key_status AS ENUM (
  'ACTIVE',
  'REVOKED'
);

CREATE TABLE program_clients (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  program_id uuid NOT NULL REFERENCES programs(id),
  -- Identifiant OPAQUE, généré par CSPRNG côté outillage d'administration :
  -- ni le code du programme, ni rien d'énumérable.
  client_id  text NOT NULL,
  status     program_client_status NOT NULL DEFAULT 'ACTIVE',
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_program_clients_client_id UNIQUE (client_id),
  CONSTRAINT chk_program_clients_client_id_shape CHECK (client_id ~ '^pc_[a-f0-9]{32}$'),
  CONSTRAINT chk_program_clients_revoked_pair
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

-- Au plus UNE identité cliente ACTIVE par programme : la révocation d'un
-- client ne laisse aucune porte jumelle oubliée, et « couper Scolaria » est
-- UNE écriture. Si un besoin réel de clients multiples arrive un jour
-- (métrique, pas anticipation), lever cet index sera une migration signée.
CREATE UNIQUE INDEX uq_program_clients_active
  ON program_clients (program_id) WHERE status = 'ACTIVE';

CREATE INDEX idx_program_clients_program ON program_clients (program_id);

CREATE TABLE program_client_keys (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  program_client_id uuid NOT NULL REFERENCES program_clients(id),
  kid               text NOT NULL,
  -- Clé PUBLIQUE Ed25519, SPKI DER en base64. L'en-tête DER d'une clé
  -- publique Ed25519 est CONSTANT (302a300506032b6570032100), donc ses seize
  -- premiers caractères base64 aussi : « MCowBQYDK2VwAyEA », suivi des
  -- 32 octets de la clé (43 caractères + « = »). Ce CHECK rend NON
  -- REPRÉSENTABLES : une clé d'un autre algorithme, un PEM, un JWK — et
  -- surtout une clé PRIVÉE (PKCS8, en-tête différent). Vérifié
  -- matériellement le 15/07/2026 (5 tirages crypto.generateKeyPairSync).
  public_key        text NOT NULL,
  status            program_client_key_status NOT NULL DEFAULT 'ACTIVE',
  revoked_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_program_client_keys_kid UNIQUE (program_client_id, kid),
  CONSTRAINT chk_program_client_keys_kid_shape
    CHECK (kid ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$'),
  CONSTRAINT chk_program_client_keys_ed25519_spki
    CHECK (public_key ~ '^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$'),
  CONSTRAINT chk_program_client_keys_revoked_pair
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

-- Au plus UNE clé ACTIVE par client ; l'historique des clés tournées reste.
CREATE UNIQUE INDEX uq_program_client_keys_active
  ON program_client_keys (program_client_id) WHERE status = 'ACTIVE';

CREATE INDEX idx_program_client_keys_client ON program_client_keys (program_client_id);

-- -----------------------------------------------------------------------------
-- Gardes de naissance (P0108) : un client ne naît que sous un programme
-- ACTIVE ; une clé ne naît que sous un client ACTIVE. FOR SHARE : sérialise
-- avec un retrait/une révocation concurrents (patron 004/008).
-- SECURITY DEFINER : le verrou de ligne exige plus que le simple SELECT du
-- rôle applicatif — la garde ne dépend pas d'un droit qu'on lui refuse.
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_program_client_insert() RETURNS trigger AS $$
DECLARE
  prog_status program_status;
BEGIN
  SELECT status INTO prog_status FROM programs WHERE id = NEW.program_id FOR SHARE;
  IF prog_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_clients : aucune identité cliente ne naît sous un programme % (P0108)',
      prog_status USING ERRCODE = 'P0108';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_clients_guard_insert
  BEFORE INSERT ON program_clients
  FOR EACH ROW EXECUTE FUNCTION guard_program_client_insert();

CREATE FUNCTION guard_program_client_key_insert() RETURNS trigger AS $$
DECLARE
  client_status program_client_status;
BEGIN
  SELECT status INTO client_status FROM program_clients
   WHERE id = NEW.program_client_id FOR SHARE;
  IF client_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_client_keys : aucune clé ne naît sous un client % (P0108)',
      client_status USING ERRCODE = 'P0108';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_client_keys_guard_insert
  BEFORE INSERT ON program_client_keys
  FOR EACH ROW EXECUTE FUNCTION guard_program_client_key_insert();

-- -----------------------------------------------------------------------------
-- Gardes de vie : contenu immuable, transition bornée, ligne révoquée figée,
-- horodatages posés par la base (patron 002/003/006).
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_program_client_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.program_id IS DISTINCT FROM OLD.program_id
     OR NEW.client_id IS DISTINCT FROM OLD.client_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'program_clients : identité immuable — remplacer un client = une NOUVELLE ligne'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'program_clients : un client révoqué est figé — il ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status <> 'REVOKED' THEN
      RAISE EXCEPTION 'program_clients : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
    NEW.revoked_at := now();   -- la base horodate, jamais le client
  ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'program_clients : revoked_at est posé par la base à la révocation et ne se réécrit jamais'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_clients_guard_update
  BEFORE UPDATE ON program_clients
  FOR EACH ROW EXECUTE FUNCTION guard_program_client_update();

CREATE FUNCTION guard_program_client_key_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.program_client_id IS DISTINCT FROM OLD.program_client_id
     OR NEW.kid IS DISTINCT FROM OLD.kid
     OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'program_client_keys : contenu immuable — tourner = enregistrer une NOUVELLE clé'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'program_client_keys : une clé révoquée est figée — elle ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status <> 'REVOKED' THEN
      RAISE EXCEPTION 'program_client_keys : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
    NEW.revoked_at := now();
  ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'program_client_keys : revoked_at est posé par la base à la révocation et ne se réécrit jamais'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_client_keys_guard_update
  BEFORE UPDATE ON program_client_keys
  FOR EACH ROW EXECUTE FUNCTION guard_program_client_key_update();

-- -----------------------------------------------------------------------------
-- Cascade (patron C1) : révoquer un client éteint TOUTES ses clés, dans la
-- même écriture. Aucun chemin d'appel — outillage, endpoint futur, v2 — ne
-- peut révoquer l'identité en laissant une clé vivante derrière.
-- -----------------------------------------------------------------------------
CREATE FUNCTION cascade_program_client_revocation() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'REVOKED' AND OLD.status IS DISTINCT FROM NEW.status THEN
    UPDATE program_client_keys
       SET status = 'REVOKED'
     WHERE program_client_id = NEW.id
       AND status = 'ACTIVE';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_clients_cascade_revocation
  AFTER UPDATE ON program_clients
  FOR EACH ROW EXECUTE FUNCTION cascade_program_client_revocation();

CREATE TRIGGER trg_program_clients_no_delete
  BEFORE DELETE ON program_clients
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

CREATE TRIGGER trg_program_client_keys_no_delete
  BEFORE DELETE ON program_client_keys
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- Droits : l'identité cliente est un acte d'ADMINISTRATION (patron programs,
-- 008). Le service LIT — les clés publiques sont publiques — et n'écrit RIEN.
-- -----------------------------------------------------------------------------
GRANT SELECT ON program_clients TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON program_clients FROM user_core_app;

GRANT SELECT ON program_client_keys TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON program_client_keys FROM user_core_app;
