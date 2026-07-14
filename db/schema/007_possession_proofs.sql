-- =============================================================================
-- 007 — La preuve de possession de LIGNE, et le numéro recyclé.
--
-- DOCTRINE (CDC §6.2, non négociable) : seule la SIM prouve la possession.
-- Le canal est un ENUM à DEUX valeurs — 'SMS' et 'CALL'. WhatsApp n'est pas
-- « interdit par une règle qu'on répète » : il est NON REPRÉSENTABLE. Un
-- compte WhatsApp survit à la carte SIM (résiliée, réattribuée à un inconnu),
-- et c'est la SIM qui recevra la demande de paiement et sera débitée.
--
-- CE QUE LE SERVICE NE PEUT PAS FAIRE, PAR CONSTRUCTION :
--   - insérer une preuve (aucun GRANT INSERT) → le plafond par ligne (P3-bis)
--     et l'unicité de la preuve en cours sont NON CONTOURNABLES ;
--   - lire un code (code_hmac hors du SELECT, patron C9/C10) ;
--   - compter un essai (P2 : l'incrément vit DANS la fonction de
--     vérification, même transaction que le verdict) ;
--   - activer une revendication (006 : assurance_level hors de son GRANT).
-- Il appelle deux fonctions SECURITY DEFINER, il agit sur le VERDICT.
--
-- P1 : le code est haché par HMAC (clé DÉDIÉE, proof_code_key_id, troisième
-- trousseau). Un SHA-256 d'un code à 6 chiffres n'est pas un secret : 10⁶
-- essais suffisent à le retrouver. Le HMAC rend le condensat inattaquable
-- sans la clé.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE proof_channel AS ENUM (
  'SMS',    -- transite par la SIM — repli rationné et plafonné (SMS ≈ 0,25 $ en RDC)
  'CALL'    -- appel manqué (flash call) — transite par la SIM
  -- Et RIEN d'autre. Ajouter une valeur ici serait un acte grave et visible.
);

CREATE TYPE proof_status AS ENUM (
  'PENDING',
  'SUCCEEDED',
  'FAILED',    -- essais épuisés, ou le fournisseur n'a pas pu livrer
  'EXPIRED'
);

-- CHAQUE LIGNE DE CETTE TABLE = UN CODE RÉELLEMENT PARTI = UN COÛT.
-- C'est le critère qui a décidé de tout ici : Accounting-Core doit pouvoir
-- compter les SMS émis SANS jamais les confondre avec des refus. Un refus ne
-- crée donc AUCUNE ligne ici (il va dans possession_proof_refusals) : sinon,
-- toute requête de comptage devrait « penser » à exclure un statut — et un
-- WHERE qu'on oublie est exactement la faute que ce dépôt combat.
CREATE TABLE possession_proofs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id          uuid NOT NULL REFERENCES phone_claims(id),
  channel           proof_channel NOT NULL,
  code_hmac         text NOT NULL,   -- HMAC du code — jamais le code, jamais lisible
  proof_code_key_id text NOT NULL,   -- trousseau DÉDIÉ (ni AES, ni empreinte)
  attempts          integer NOT NULL DEFAULT 0,
  max_attempts      integer NOT NULL,
  expires_at        timestamptz NOT NULL,
  status            proof_status NOT NULL DEFAULT 'PENDING',
  provider_ref      text,            -- référence du fournisseur, posée après l'appel (§3.13)
  settled_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_proofs_terminal_settled
    CHECK ((status = 'PENDING') = (settled_at IS NULL)),
  CONSTRAINT chk_proofs_attempts_bounded
    CHECK (attempts >= 0 AND attempts <= max_attempts),
  CONSTRAINT chk_proofs_max_attempts_positive CHECK (max_attempts > 0),
  CONSTRAINT chk_proofs_expiry_future CHECK (expires_at > created_at)
);

-- Une seule preuve en cours par revendication : on ne fait pas sonner deux
-- fois le même téléphone parce qu'un client a double-cliqué.
CREATE UNIQUE INDEX uq_proofs_pending_per_claim
  ON possession_proofs (claim_id) WHERE status = 'PENDING';

CREATE INDEX idx_proofs_claim ON possession_proofs (claim_id);
CREATE INDEX idx_proofs_created ON possession_proofs (created_at);

-- -----------------------------------------------------------------------------
-- Les REFUS vivent à part (P3-bis). Aucun code, aucun coût, aucune confusion
-- possible avec un envoi réel.
-- -----------------------------------------------------------------------------
CREATE TYPE proof_refusal_reason AS ENUM (
  'LINE_DAILY_CAP',        -- la LIGNE a déjà trop sonné — on protège un TIERS
  'PROOF_ALREADY_PENDING',
  'CLAIM_NOT_PENDING'
);

CREATE TABLE possession_proof_refusals (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id    uuid NOT NULL REFERENCES phone_claims(id),
  account_id  uuid NOT NULL REFERENCES accounts(id),
  phone_hmac  text NOT NULL,   -- l'empreinte de la ligne protégée — jamais le clair
  channel     proof_channel NOT NULL,
  reason      proof_refusal_reason NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_proof_refusals_hmac ON possession_proof_refusals (phone_hmac, created_at);

-- -----------------------------------------------------------------------------
-- Outbox transactionnelle (Q1) — MÉCANISME DE FIABILITÉ, JAMAIS UN BROKER
-- (CLAUDE.md §3.12) : écrite DANS la transaction qui révoque, drainée plus
-- tard par UN publisher. Aucun topic, aucun offset, aucun replay sélectif,
-- aucune rétention — leur besoin serait le signal d'un vrai broker.
--
-- ⚠️ ZÉRO PII : des UUID, un type d'événement, un horodatage. JAMAIS le
-- numéro, même chiffré. Le dispatcher résoudra l'adresse au moment d'envoyer,
-- par le chemin de déchiffrement contrôlé — c'est lui qui a les clés, pas la
-- file d'attente.
-- -----------------------------------------------------------------------------
CREATE TYPE outbox_status AS ENUM ('PENDING', 'PUBLISHED');

CREATE TABLE outbox (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type   text NOT NULL,
  account_id   uuid NOT NULL REFERENCES accounts(id),
  claim_id     uuid REFERENCES phone_claims(id),
  status       outbox_status NOT NULL DEFAULT 'PENDING',
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  CONSTRAINT chk_outbox_published_pair
    CHECK ((status = 'PUBLISHED') = (published_at IS NOT NULL))
);

CREATE INDEX idx_outbox_pending ON outbox (occurred_at) WHERE status = 'PENDING';

-- -----------------------------------------------------------------------------
-- Gardes append-only
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_possession_proof_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
     OR NEW.channel IS DISTINCT FROM OLD.channel
     OR NEW.code_hmac IS DISTINCT FROM OLD.code_hmac
     OR NEW.proof_code_key_id IS DISTINCT FROM OLD.proof_code_key_id
     OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'possession_proofs : contenu immuable — une preuve ne se réécrit pas, on en ouvre une autre'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status <> 'PENDING' THEN
    RAISE EXCEPTION 'possession_proofs : une preuve close est figée (%)', OLD.status
      USING ERRCODE = 'P0103';
  END IF;

  -- Le compteur d'essais ne peut QU'incrémenter de 1 (patron C8) : il n'y a
  -- aucune raison légitime de le remettre à zéro — un plafond qui se remet à
  -- zéro n'est pas un plafond.
  IF NEW.attempts IS DISTINCT FROM OLD.attempts
     AND NEW.attempts <> OLD.attempts + 1 THEN
    RAISE EXCEPTION 'possession_proofs : attempts s''incrémente de 1, jamais % -> %',
      OLD.attempts, NEW.attempts USING ERRCODE = 'P0106';
  END IF;

  -- provider_ref : set-once, et seulement tant que la preuve est en cours.
  IF NEW.provider_ref IS DISTINCT FROM OLD.provider_ref
     AND OLD.provider_ref IS NOT NULL THEN
    RAISE EXCEPTION 'possession_proofs : provider_ref est set-once'
      USING ERRCODE = 'P0104';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    NEW.settled_at := now();   -- la base horodate la clôture, jamais le client
  ELSIF NEW.settled_at IS DISTINCT FROM OLD.settled_at THEN
    RAISE EXCEPTION 'possession_proofs : settled_at est posé par la base à la clôture'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_proofs_guard_update
  BEFORE UPDATE ON possession_proofs
  FOR EACH ROW EXECUTE FUNCTION guard_possession_proof_update();

CREATE TRIGGER trg_proofs_no_delete
  BEFORE DELETE ON possession_proofs
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

CREATE FUNCTION forbid_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% : append-only — cette ligne ne se modifie jamais', TG_TABLE_NAME
    USING ERRCODE = 'P0101';
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_refusals_no_update
  BEFORE UPDATE ON possession_proof_refusals
  FOR EACH ROW EXECUTE FUNCTION forbid_update();

CREATE TRIGGER trg_refusals_no_delete
  BEFORE DELETE ON possession_proof_refusals
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

CREATE TRIGGER trg_outbox_no_delete
  BEFORE DELETE ON outbox
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- P3-bis — OUVRIR une preuve : le plafond par LIGNE vit ICI, pas dans le
-- service. Le service n'a AUCUN droit d'insertion : il ne peut donc pas
-- contourner ce chemin, aujourd'hui ni dans une v2 écrite par quelqu'un
-- d'autre. Le plafond protège LE TÉLÉPHONE D'UN TIERS (empêcher qu'un compte
-- fasse sonner en boucle le numéro de quelqu'un d'autre) : il se compte donc
-- sur l'EMPREINTE DE LA LIGNE, jamais sur le compte demandeur — un compte se
-- multiplie, une ligne non.
--
-- Verdicts : OPENED · REFUSED_CAP · REFUSED_PENDING · REFUSED_CLAIM · UNKNOWN
-- -----------------------------------------------------------------------------
CREATE FUNCTION open_possession_proof(
  p_claim_id          uuid,
  p_channel           proof_channel,
  p_code_hmac         text,
  p_proof_code_key_id text,
  p_ttl_seconds       integer,
  p_max_attempts      integer,
  p_line_cap          integer,
  p_cap_window_seconds integer
)
RETURNS TABLE (proof_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  c phone_claims%ROWTYPE;
  sent_in_window integer;
  new_id uuid;
BEGIN
  -- FOR UPDATE : sérialise deux demandes concurrentes sur la même
  -- revendication (retry d'un mobile) — le plafond ne se contourne pas par
  -- une course.
  SELECT * INTO c FROM phone_claims WHERE id = p_claim_id FOR UPDATE;
  IF NOT FOUND THEN
    proof_id := NULL; verdict := 'UNKNOWN';
    RETURN NEXT; RETURN;
  END IF;

  IF c.status <> 'PENDING' THEN
    INSERT INTO possession_proof_refusals (claim_id, account_id, phone_hmac, channel, reason)
    VALUES (c.id, c.account_id, c.phone_hmac, p_channel, 'CLAIM_NOT_PENDING');
    proof_id := NULL; verdict := 'REFUSED_CLAIM';
    RETURN NEXT; RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM possession_proofs p
              WHERE p.claim_id = c.id AND p.status = 'PENDING') THEN
    INSERT INTO possession_proof_refusals (claim_id, account_id, phone_hmac, channel, reason)
    VALUES (c.id, c.account_id, c.phone_hmac, p_channel, 'PROOF_ALREADY_PENDING');
    proof_id := NULL; verdict := 'REFUSED_PENDING';
    RETURN NEXT; RETURN;
  END IF;

  -- Le plafond par LIGNE : toutes revendications confondues, tous comptes
  -- confondus — c'est la ligne physique qu'on protège.
  SELECT count(*) INTO sent_in_window
    FROM possession_proofs p
    JOIN phone_claims pc ON pc.id = p.claim_id
   WHERE pc.phone_hmac = c.phone_hmac
     AND p.created_at > now() - make_interval(secs => p_cap_window_seconds);

  IF sent_in_window >= p_line_cap THEN
    INSERT INTO possession_proof_refusals (claim_id, account_id, phone_hmac, channel, reason)
    VALUES (c.id, c.account_id, c.phone_hmac, p_channel, 'LINE_DAILY_CAP');
    proof_id := NULL; verdict := 'REFUSED_CAP';
    RETURN NEXT; RETURN;
  END IF;

  INSERT INTO possession_proofs (claim_id, channel, code_hmac, proof_code_key_id,
                                 max_attempts, expires_at)
  VALUES (p_claim_id, p_channel, p_code_hmac, p_proof_code_key_id, p_max_attempts,
          now() + make_interval(secs => p_ttl_seconds))
  RETURNING id INTO new_id;

  proof_id := new_id; verdict := 'OPENED';
  RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- P2 — VÉRIFIER un code : la fonction compte l'essai ELLE-MÊME, dans la même
-- transaction que le verdict. Le service ne compte rien : aucun chemin futur
-- ne peut donc « oublier » d'incrémenter, et le plafond n'est pas décoratif.
--
-- C'est aussi ICI que « la preuve la plus récente gagne » (CDC §6.5) : un
-- succès révoque d'office toute revendication ACTIVE antérieure sur la MÊME
-- ligne, et écrit dans l'outbox de quoi prévenir l'ancien détenteur — dans la
-- MÊME transaction. Deux personnes ne détiennent pas la même SIM au même
-- instant.
--
-- Verdicts : PROVEN · WRONG · EXPIRED · EXHAUSTED · ALREADY_SETTLED · UNKNOWN
-- -----------------------------------------------------------------------------
CREATE FUNCTION verify_possession_code(p_claim_id uuid, p_code_hmac text)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  p possession_proofs%ROWTYPE;
  c phone_claims%ROWTYPE;
  superseded_id uuid;
  superseded_account uuid;
BEGIN
  SELECT * INTO c FROM phone_claims WHERE id = p_claim_id FOR UPDATE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN'; RETURN NEXT; RETURN;
  END IF;

  SELECT * INTO p FROM possession_proofs
   WHERE claim_id = p_claim_id AND status = 'PENDING'
   FOR UPDATE;
  IF NOT FOUND THEN
    -- Aucune preuve en cours : soit rien n'a été ouvert, soit tout est clos.
    IF EXISTS (SELECT 1 FROM possession_proofs WHERE claim_id = p_claim_id) THEN
      verdict := 'ALREADY_SETTLED';
    ELSE
      verdict := 'UNKNOWN';
    END IF;
    RETURN NEXT; RETURN;
  END IF;

  IF p.expires_at <= now() THEN
    UPDATE possession_proofs SET status = 'EXPIRED' WHERE id = p.id;
    verdict := 'EXPIRED'; RETURN NEXT; RETURN;
  END IF;

  -- P2 : l'essai est compté ICI, avant toute comparaison, quoi qu'il arrive.
  UPDATE possession_proofs SET attempts = attempts + 1 WHERE id = p.id;
  p.attempts := p.attempts + 1;

  IF p.code_hmac = p_code_hmac THEN
    UPDATE possession_proofs SET status = 'SUCCEEDED' WHERE id = p.id;

    -- LA PREUVE LA PLUS RÉCENTE GAGNE : l'ancienne revendication ACTIVE de la
    -- MÊME ligne tombe d'office (jamais un refus « ce numéro est déjà pris »,
    -- qui serait un défaut de conception : la SIM a changé de mains).
    FOR superseded_id, superseded_account IN
      SELECT pc.id, pc.account_id FROM phone_claims pc
       WHERE pc.hmac_key_id = c.hmac_key_id
         AND pc.phone_hmac = c.phone_hmac
         AND pc.status = 'ACTIVE'
         AND pc.id <> c.id
    LOOP
      UPDATE phone_claims
         SET status = 'REVOKED', revoke_reason = 'SUPERSEDED'
       WHERE id = superseded_id;

      -- L'ancien détenteur DOIT être prévenu — par un AUTRE canal (CDC §6.5).
      -- L'intention est écrite dans la transaction qui révoque : elle ne peut
      -- pas se perdre. ZÉRO PII dans cette ligne.
      INSERT INTO outbox (event_type, account_id, claim_id)
      VALUES ('PHONE_LINE_SUPERSEDED', superseded_account, superseded_id);
    END LOOP;

    UPDATE phone_claims
       SET status = 'ACTIVE', assurance_level = 'PROVEN'
     WHERE id = c.id;

    verdict := 'PROVEN'; RETURN NEXT; RETURN;
  END IF;

  IF p.attempts >= p.max_attempts THEN
    UPDATE possession_proofs SET status = 'FAILED' WHERE id = p.id;
    verdict := 'EXHAUSTED'; RETURN NEXT; RETURN;
  END IF;

  verdict := 'WRONG'; RETURN NEXT;
END;
$$;

-- Le fournisseur n'a pas pu livrer (muet, erreur) : on clôt proprement. Le
-- service ne peut pas le faire à la main (aucun GRANT UPDATE (status)).
CREATE FUNCTION abandon_possession_proof(p_proof_id uuid) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE possession_proofs SET status = 'FAILED'
   WHERE id = p_proof_id AND status = 'PENDING';
END;
$$;

-- -----------------------------------------------------------------------------
-- Droits : le service n'INSÈRE ni ne MODIFIE rien ici (sauf provider_ref, posé
-- après l'appel au fournisseur, §3.13). Il EXÉCUTE, il obéit au verdict.
-- code_hmac est ABSENT du SELECT : le service ne compare aucun code (C9/C10).
-- -----------------------------------------------------------------------------
GRANT SELECT (id, claim_id, channel, proof_code_key_id, attempts, max_attempts,
              expires_at, status, provider_ref, settled_at, created_at)
  ON possession_proofs TO user_core_app;
GRANT UPDATE (provider_ref) ON possession_proofs TO user_core_app;
REVOKE INSERT, DELETE, TRUNCATE ON possession_proofs FROM user_core_app;

GRANT SELECT ON possession_proof_refusals TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON possession_proof_refusals FROM user_core_app;

GRANT SELECT ON outbox TO user_core_app;
GRANT UPDATE (status, published_at) ON outbox TO user_core_app;
REVOKE INSERT, DELETE, TRUNCATE ON outbox FROM user_core_app;

REVOKE ALL ON FUNCTION open_possession_proof(uuid, proof_channel, text, text, integer, integer, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION verify_possession_code(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION abandon_possession_proof(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_possession_proof(uuid, proof_channel, text, text, integer, integer, integer, integer) TO user_core_app;
GRANT EXECUTE ON FUNCTION verify_possession_code(uuid, text) TO user_core_app;
GRANT EXECUTE ON FUNCTION abandon_possession_proof(uuid) TO user_core_app;
