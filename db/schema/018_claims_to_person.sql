-- =============================================================================
-- 018 — La ligne téléphonique appartient à la PERSONNE (décision D-A, LOT 5
-- étape 5) — et la reprise d'une ligne détenue par une personne SANS compte
-- cesse d'être un abort (correction C1).
--
-- POURQUOI LA PERSONNE : une SIM est possédée par un humain, pas par un
-- artefact de connexion. Et l'émancipation (020) exige de prouver une ligne
-- AVANT d'avoir un compte — la revendication doit donc pouvoir exister pour
-- une personne sans compte. Conséquence assumée (D-A, actée) : C13 ne révoque
-- PLUS les revendications à la désactivation d'un compte — la possession
-- d'une ligne survit à la mort d'un compte ; le recyclage (§3.4) couvre le
-- reste. (Les droits d'accès, eux, restent au compte jusqu'à 019 : la
-- cascade les garde encore une étape.)
--
-- 🔴 C1 (démonstration Auditeur, vérifiée) : l'outbox portait
-- account_id NOT NULL REFERENCES accounts. Sous D-A, le supersédé est une
-- PERSONNE — qui peut ne pas avoir de compte (émancipation entamée, jamais
-- achevée). verify_possession_code aurait alors violé le NOT NULL : la
-- transaction du NOUVEAU détenteur — la mère qui reprend SA propre SIM —
-- aurait ABORTÉ. Le refus « ce numéro est déjà pris », que 007:427 interdit
-- en toutes lettres, revenait par la porte de derrière. §3.4 redevient vrai :
-- l'outbox porte la PERSONNE ; le compte du destinataire se résout AU MOMENT
-- de publier ; « aucun canal → on ne notifie pas, et on le trace » (009:32)
-- a désormais un chemin représentable — le silence était déjà la doctrine,
-- c'est l'abort qui ne l'était pas.
--
-- TRANSFORMATION : les lignes gelées (REVOKED figées par P0103, outbox close
-- par P0103) ne peuvent pas être backfillées triggers armés — DISABLE
-- TRIGGER USER le temps du backfill, réarmé aussitôt. Le test C3
-- (tests/db/triggers-armed.spec.ts) vérifie pg_trigger.tgenabled = 'O' sur
-- chaque table touchée : une migration qui désarme et oublie de réarmer ne
-- peut pas passer inaperçue.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) phone_claims : compte → personne.
-- -----------------------------------------------------------------------------
ALTER TABLE phone_claims ADD COLUMN person_id uuid REFERENCES persons(id);

ALTER TABLE phone_claims DISABLE TRIGGER USER;
UPDATE phone_claims pc SET person_id = a.person_id
  FROM accounts a WHERE a.id = pc.account_id;
ALTER TABLE phone_claims ENABLE TRIGGER USER;

ALTER TABLE phone_claims ALTER COLUMN person_id SET NOT NULL;

-- Une seule revendication VIVANTE par PERSONNE (Q3, transposée) ; l'unicité
-- mondiale de la ligne (couple clé/empreinte), elle, ne bouge pas.
DROP INDEX uq_phone_claims_alive_per_account;
CREATE UNIQUE INDEX uq_phone_claims_alive_per_person
  ON phone_claims (person_id) WHERE status IN ('PENDING', 'ACTIVE');

DROP INDEX idx_phone_claims_account;
CREATE INDEX idx_phone_claims_person ON phone_claims (person_id);

ALTER TABLE phone_claims DROP COLUMN account_id;

-- Le contenu immuable suit la colonne (patron 006, CREATE OR REPLACE — 006
-- est fusionnée).
CREATE OR REPLACE FUNCTION guard_phone_claim_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
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

  IF OLD.assurance_level = 'PROVEN' AND NEW.assurance_level = 'DECLARED' THEN
    RAISE EXCEPTION 'phone_claims : le niveau de preuve ne descend jamais (PROVEN -> DECLARED)'
      USING ERRCODE = 'P0102';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'ACTIVE' THEN
      IF NEW.assurance_level <> 'PROVEN' THEN
        RAISE EXCEPTION 'phone_claims : une revendication ne devient ACTIVE que PROUVÉE (SMS ou appel)'
          USING ERRCODE = 'P0102';
      END IF;
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

-- Droits recalés sur la nouvelle forme (patron 006 : la valeur chiffrée reste
-- hors du SELECT, ce que la base pose n'est jamais accordé).
GRANT SELECT (id, person_id, phone_hmac, hmac_key_id, enc_key_id, status,
              assurance_level, verified_at, revoked_at, revoke_reason, created_at)
  ON phone_claims TO user_core_app;
GRANT INSERT (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
  ON phone_claims TO user_core_app;

-- -----------------------------------------------------------------------------
-- 2) Les refus de preuve suivent (ils protègent une LIGNE, demandée par une
--    personne).
-- -----------------------------------------------------------------------------
ALTER TABLE possession_proof_refusals ADD COLUMN person_id uuid REFERENCES persons(id);

ALTER TABLE possession_proof_refusals DISABLE TRIGGER USER;
UPDATE possession_proof_refusals r SET person_id = pc.person_id
  FROM phone_claims pc WHERE pc.id = r.claim_id;
ALTER TABLE possession_proof_refusals ENABLE TRIGGER USER;

ALTER TABLE possession_proof_refusals ALTER COLUMN person_id SET NOT NULL;
ALTER TABLE possession_proof_refusals DROP COLUMN account_id;

-- -----------------------------------------------------------------------------
-- 3) C1 — l'outbox porte la PERSONNE. Le compte du destinataire n'est plus
--    une donnée de l'événement : il se résout au moment de PUBLIER (la
--    personne peut en acquérir un entre-temps — l'émancipation, précisément).
-- -----------------------------------------------------------------------------
ALTER TABLE outbox ADD COLUMN person_id uuid REFERENCES persons(id);

ALTER TABLE outbox DISABLE TRIGGER USER;
UPDATE outbox o SET person_id = a.person_id
  FROM accounts a WHERE a.id = o.account_id;
ALTER TABLE outbox ENABLE TRIGGER USER;

ALTER TABLE outbox ALTER COLUMN person_id SET NOT NULL;
ALTER TABLE outbox DROP COLUMN account_id;

CREATE OR REPLACE FUNCTION guard_outbox_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.event_type IS DISTINCT FROM OLD.event_type
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
     OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at THEN
    RAISE EXCEPTION 'outbox : contenu immuable — un événement survenu ne se réécrit pas'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status <> 'PENDING' THEN
    RAISE EXCEPTION 'outbox : un événement % est figé — il ne se rejoue jamais', OLD.status
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.attempts IS DISTINCT FROM OLD.attempts
     AND NEW.attempts <> OLD.attempts + 1 THEN
    RAISE EXCEPTION 'outbox : attempts s''incrémente de 1, jamais % -> %',
      OLD.attempts, NEW.attempts USING ERRCODE = 'P0106';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'PUBLISHED' THEN
      NEW.published_at := now();
    ELSIF NEW.status = 'FAILED' THEN
      NEW.failed_at := now();
    ELSE
      RAISE EXCEPTION 'outbox : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
  ELSE
    IF NEW.published_at IS DISTINCT FROM OLD.published_at
       OR NEW.failed_at IS DISTINCT FROM OLD.failed_at THEN
      RAISE EXCEPTION 'outbox : les horodatages de clôture sont posés par la base'
        USING ERRCODE = 'P0104';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 4) C13 rétréci (D-A) : un compte désactivé perd ses SESSIONS et — jusqu'à
--    019 — ses droits d'accès. Il ne perd PLUS sa revendication de ligne :
--    la possession appartient à la personne, qui survit au compte.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cascade_account_deactivation() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'DEACTIVATED' AND OLD.status IS DISTINCT FROM NEW.status THEN
    UPDATE sessions
       SET status = 'REVOKED', revoke_reason = 'ADMIN'
     WHERE account_id = NEW.id
       AND status = 'ACTIVE';

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
-- 5) Les fonctions de preuve suivent la personne (007 est fusionnée :
--    CREATE OR REPLACE à signature constante, DROP + CREATE sinon).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION open_possession_proof(
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
  SELECT * INTO c FROM phone_claims WHERE id = p_claim_id FOR UPDATE;
  IF NOT FOUND THEN
    proof_id := NULL; verdict := 'UNKNOWN';
    RETURN NEXT; RETURN;
  END IF;

  IF c.status <> 'PENDING' THEN
    INSERT INTO possession_proof_refusals (claim_id, person_id, phone_hmac, channel, reason)
    VALUES (c.id, c.person_id, c.phone_hmac, p_channel, 'CLAIM_NOT_PENDING');
    proof_id := NULL; verdict := 'REFUSED_CLAIM';
    RETURN NEXT; RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM possession_proofs p
              WHERE p.claim_id = c.id AND p.status = 'PENDING') THEN
    INSERT INTO possession_proof_refusals (claim_id, person_id, phone_hmac, channel, reason)
    VALUES (c.id, c.person_id, c.phone_hmac, p_channel, 'PROOF_ALREADY_PENDING');
    proof_id := NULL; verdict := 'REFUSED_PENDING';
    RETURN NEXT; RETURN;
  END IF;

  -- Le plafond par LIGNE : toutes revendications confondues, toutes personnes
  -- confondues — c'est la ligne physique qu'on protège.
  SELECT count(*) INTO sent_in_window
    FROM possession_proofs p
    JOIN phone_claims pc ON pc.id = p.claim_id
   WHERE pc.hmac_key_id = c.hmac_key_id
     AND pc.phone_hmac = c.phone_hmac
     AND p.created_at > now() - make_interval(secs => p_cap_window_seconds);

  IF sent_in_window >= p_line_cap THEN
    INSERT INTO possession_proof_refusals (claim_id, person_id, phone_hmac, channel, reason)
    VALUES (c.id, c.person_id, c.phone_hmac, p_channel, 'LINE_DAILY_CAP');
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

-- « La preuve la plus récente gagne » — l'outbox porte désormais la PERSONNE
-- supersédée : la reprise réussit même si elle n'a pas (ou plus) de compte.
CREATE OR REPLACE FUNCTION verify_possession_code(p_claim_id uuid, p_code_hmac text)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  p possession_proofs%ROWTYPE;
  c phone_claims%ROWTYPE;
  superseded_id uuid;
  superseded_person uuid;
BEGIN
  SELECT * INTO c FROM phone_claims WHERE id = p_claim_id FOR UPDATE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN'; RETURN NEXT; RETURN;
  END IF;

  SELECT * INTO p FROM possession_proofs
   WHERE claim_id = p_claim_id AND status = 'PENDING'
   FOR UPDATE;
  IF NOT FOUND THEN
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

  UPDATE possession_proofs SET attempts = attempts + 1 WHERE id = p.id;
  p.attempts := p.attempts + 1;

  IF p.code_hmac = p_code_hmac THEN
    UPDATE possession_proofs SET status = 'SUCCEEDED' WHERE id = p.id;

    FOR superseded_id, superseded_person IN
      SELECT pc.id, pc.person_id FROM phone_claims pc
       WHERE pc.hmac_key_id = c.hmac_key_id
         AND pc.phone_hmac = c.phone_hmac
         AND pc.status = 'ACTIVE'
         AND pc.id <> c.id
    LOOP
      UPDATE phone_claims
         SET status = 'REVOKED', revoke_reason = 'SUPERSEDED'
       WHERE id = superseded_id;

      -- L'intention de prévenir est écrite dans la transaction qui révoque —
      -- pour une PERSONNE. Son canal (compte actif, ou aucun) se résoudra au
      -- moment de publier. ZÉRO PII dans cette ligne.
      INSERT INTO outbox (event_type, person_id, claim_id)
      VALUES ('PHONE_LINE_SUPERSEDED', superseded_person, superseded_id);
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

-- BOLA par la PERSONNE : le nom du paramètre change — DROP + CREATE (un
-- CREATE OR REPLACE refuse de renommer un paramètre d'entrée).
DROP FUNCTION record_proof_dispatch(uuid, uuid, text);
CREATE FUNCTION record_proof_dispatch(
  p_proof_id     uuid,
  p_person_id    uuid,
  p_provider_ref text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  p possession_proofs%ROWTYPE;
BEGIN
  SELECT pr.* INTO p FROM possession_proofs pr
    JOIN phone_claims c ON c.id = pr.claim_id
   WHERE pr.id = p_proof_id
     AND c.person_id = p_person_id
   FOR UPDATE OF pr;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  INSERT INTO proof_dispatches (proof_id, channel, provider_ref)
  VALUES (p.id, p.channel, p_provider_ref)
  ON CONFLICT (proof_id) DO NOTHING;

  UPDATE possession_proofs SET provider_ref = p_provider_ref
   WHERE id = p.id AND provider_ref IS NULL;

  RETURN true;
END;
$$;

DROP FUNCTION abandon_possession_proof(uuid, uuid);
CREATE FUNCTION abandon_possession_proof(p_proof_id uuid, p_person_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  closed integer;
BEGIN
  UPDATE possession_proofs p SET status = 'FAILED'
   WHERE p.id = p_proof_id
     AND p.status = 'PENDING'
     AND EXISTS (SELECT 1 FROM phone_claims c
                  WHERE c.id = p.claim_id AND c.person_id = p_person_id);
  GET DIAGNOSTICS closed = ROW_COUNT;
  RETURN closed > 0;
END;
$$;

REVOKE ALL ON FUNCTION record_proof_dispatch(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_proof_dispatch(uuid, uuid, text) TO user_core_app;
REVOKE ALL ON FUNCTION abandon_possession_proof(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION abandon_possession_proof(uuid, uuid) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 6) Le drainage suit : le lot rend la personne ; la publication résout le
--    compte du destinataire À CE MOMENT-LÀ — et rend un verdict au lieu de
--    déposer dans le vide ou d'aborter.
-- -----------------------------------------------------------------------------
DROP FUNCTION claim_outbox_batch(integer, integer);
CREATE FUNCTION claim_outbox_batch(p_batch_size integer, p_lease_seconds integer)
RETURNS TABLE (id uuid, event_type text, person_id uuid, claim_id uuid, attempts integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  UPDATE outbox o
     SET next_attempt_at = now() + make_interval(secs => p_lease_seconds)
   WHERE o.id IN (
     SELECT c.id FROM outbox c
      WHERE c.status = 'PENDING'
        AND c.next_attempt_at <= now()
      ORDER BY c.occurred_at
      FOR UPDATE SKIP LOCKED
      LIMIT p_batch_size
   )
  RETURNING o.id, o.event_type, o.person_id, o.claim_id, o.attempts;
END;
$$;

DROP FUNCTION publish_outbox_event(uuid, boolean);
CREATE FUNCTION publish_outbox_event(p_id uuid, p_notify_account boolean) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  e outbox%ROWTYPE;
  holder_account_id uuid;
BEGIN
  SELECT * INTO e FROM outbox WHERE id = p_id AND status = 'PENDING' FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'ALREADY_SETTLED';   -- déjà clos : on ne rejoue jamais.
  END IF;

  IF p_notify_account THEN
    -- Au plus UN compte actif par personne (016) : la résolution est nette.
    SELECT a.id INTO holder_account_id FROM accounts a
     WHERE a.person_id = e.person_id AND a.status = 'ACTIVE';
    IF holder_account_id IS NULL THEN
      -- La personne n'a aucun canal AUJOURD'HUI (émancipation entamée sans
      -- compte, compte désactivé). VERDICT, pas dépôt dans le vide : c'est
      -- l'appelant qui trace — et qui repassera, la personne peut acquérir
      -- un compte demain (009:32 : le silence est acceptable, tracé).
      RETURN 'NO_ACCOUNT';
    END IF;
    INSERT INTO account_notifications (account_id, event_type, outbox_id)
    VALUES (holder_account_id, e.event_type, e.id)
    ON CONFLICT (outbox_id) DO NOTHING;
  END IF;

  UPDATE outbox SET status = 'PUBLISHED' WHERE id = e.id;
  RETURN 'PUBLISHED';
END;
$$;

REVOKE ALL ON FUNCTION claim_outbox_batch(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_outbox_batch(integer, integer) TO user_core_app;
REVOKE ALL ON FUNCTION publish_outbox_event(uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION publish_outbox_event(uuid, boolean) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 7) Les invitations : le BOLA « détenir la ligne » se lit par la PERSONNE du
--    compte qui accepte. Le droit créé, lui, reste au compte jusqu'à 019.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION accept_program_invitation(p_invitation_id uuid, p_account_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  inv program_invitations%ROWTYPE;
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

  IF NOT EXISTS (
    SELECT 1 FROM phone_claims c
      JOIN accounts a ON a.person_id = c.person_id
     WHERE a.id = p_account_id
       AND c.hmac_key_id = inv.hmac_key_id
       AND c.phone_hmac = inv.phone_hmac
       AND c.status = 'ACTIVE'
  ) THEN
    RETURN 'LINE_NOT_PROVEN';
  END IF;

  SELECT * INTO last_grant FROM program_grants g
   WHERE g.account_id = p_account_id
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
    INSERT INTO program_grants (account_id, program_id, granted_by)
    VALUES (p_account_id, inv.program_id, actor);
  END IF;

  UPDATE program_invitations
     SET status = 'ACCEPTED', accepted_account_id = p_account_id
   WHERE id = inv.id;

  RETURN 'ACCEPTED';
END;
$$;

CREATE OR REPLACE FUNCTION decline_program_invitation(p_invitation_id uuid, p_account_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  inv program_invitations%ROWTYPE;
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

  IF NOT EXISTS (
    SELECT 1 FROM phone_claims c
      JOIN accounts a ON a.person_id = c.person_id
     WHERE a.id = p_account_id
       AND c.hmac_key_id = inv.hmac_key_id
       AND c.phone_hmac = inv.phone_hmac
       AND c.status = 'ACTIVE'
  ) THEN
    RETURN 'LINE_NOT_PROVEN';
  END IF;

  UPDATE program_invitations SET status = 'DECLINED' WHERE id = inv.id;
  RETURN 'DECLINED';
END;
$$;
