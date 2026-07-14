-- =============================================================================
-- 009 — L'outbox devient drainable, et LE PIÈGE DU RECYCLAGE devient
-- non représentable.
--
-- 1) F1 — 007 est fusionnée (donc immuable) et son outbox ne porte AUCUN état
--    de retry : ni compteur, ni échéance. Sa garde n'autorise qu'une seule
--    transition (PENDING -> PUBLISHED). Un événement que le dispatcher ne
--    pourra JAMAIS livrer resterait donc PENDING pour toujours, re-tenté à
--    chaque tour du worker — sur un canal payant, c'est une facture qui court
--    dans la nuit (CDC §6.6). On corrige par migration signée, délibérément.
--    Ce n'est PAS un dead-letter par consommateur (§3.12 tenu) : c'est un
--    état terminal GLOBAL, sans replay sélectif, sans topic, sans offset.
--
-- 2) 🔴 LE PIÈGE. L'événement PHONE_LINE_SUPERSEDED existe pour prévenir
--    l'ANCIEN détenteur qu'on lui a retiré sa ligne. Le réflexe — lui envoyer
--    un SMS — est une FAUTE GRAVE : ce numéro n'est plus le sien. La SIM est
--    dans la main de quelqu'un d'autre (c'est précisément pourquoi on
--    révoque). Ce message :
--      · n'atteint PAS la personne qu'on veut prévenir ;
--      · atteint un INCONNU, et lui révèle qu'un compte de l'écosystème était
--        rattaché à ce numéro — une fuite sur un tiers ;
--      · coûte un envoi payant pour un résultat contraire au but.
--    Règle gravée : un événement de reprise de ligne ne peut JAMAIS être
--    délivré sur la ligne reprise. Rendue non représentable de deux façons :
--      · resolve_notification_address() REFUSE de rendre l'adresse d'une
--        revendication qui n'est pas ACTIVE — or l'événement porte justement
--        la revendication RÉVOQUÉE : elle est inatteignable par construction ;
--      · event_channel_policy (DONNÉES, pas code) n'autorise pour cet
--        événement AUCUN canal externe. La notification vit dans le compte
--        (account_notifications), que l'ancien détenteur lira à sa prochaine
--        connexion — son compte, lui, est toujours à lui.
--    S'il n'existe aucun canal permis : on NE NOTIFIE PAS, et on le trace. Le
--    silence est acceptable ; prévenir le voleur de SIM ne l'est pas.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) L'outbox retriable. (Un type NEUF plutôt qu'un ALTER TYPE ADD VALUE : une
--    valeur d'enum ajoutée ne peut pas être UTILISÉE dans la transaction qui
--    la crée — et le runner enveloppe cette migration. Le contournement
--    serait de casser l'atomicité : hors de question.)
-- -----------------------------------------------------------------------------
CREATE TYPE outbox_status_next AS ENUM ('PENDING', 'PUBLISHED', 'FAILED');

-- Le CHECK et l'INDEX PARTIEL de 007 gardent une constante typée à l'ANCIEN
-- enum : ils tombent le temps de la conversion, et sont reposés juste après.
ALTER TABLE outbox DROP CONSTRAINT chk_outbox_published_pair;
DROP INDEX idx_outbox_pending;
ALTER TABLE outbox ALTER COLUMN status DROP DEFAULT;
ALTER TABLE outbox ALTER COLUMN status TYPE outbox_status_next
  USING status::text::outbox_status_next;
ALTER TABLE outbox ALTER COLUMN status SET DEFAULT 'PENDING';
DROP TYPE outbox_status;
ALTER TYPE outbox_status_next RENAME TO outbox_status;
ALTER TABLE outbox ADD CONSTRAINT chk_outbox_published_pair
  CHECK ((status = 'PUBLISHED') = (published_at IS NOT NULL));
CREATE INDEX idx_outbox_pending ON outbox (occurred_at) WHERE status = 'PENDING';

ALTER TABLE outbox ADD COLUMN attempts integer NOT NULL DEFAULT 0;
ALTER TABLE outbox ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT now();
-- Code COURT (marqueur applicatif), jamais un message, jamais de PII.
ALTER TABLE outbox ADD COLUMN last_error_code text;
ALTER TABLE outbox ADD COLUMN failed_at timestamptz;

ALTER TABLE outbox ADD CONSTRAINT chk_outbox_attempts_positive CHECK (attempts >= 0);
ALTER TABLE outbox ADD CONSTRAINT chk_outbox_error_code_short
  CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z_]{3,32}$');
ALTER TABLE outbox ADD CONSTRAINT chk_outbox_failed_pair
  CHECK ((status = 'FAILED') = (failed_at IS NOT NULL));

CREATE INDEX idx_outbox_drainable ON outbox (next_attempt_at) WHERE status = 'PENDING';

-- La garde de P5, étendue aux deux nouvelles transitions. PUBLISHED et FAILED
-- restent FIGÉS : un événement publié ne se rejoue jamais (l'ancien détenteur
-- d'une ligne recyclée ne sera pas prévenu en boucle), un événement mort ne
-- ressuscite pas tout seul.
CREATE OR REPLACE FUNCTION guard_outbox_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.event_type IS DISTINCT FROM OLD.event_type
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
     OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at THEN
    RAISE EXCEPTION 'outbox : contenu immuable — un événement survenu ne se réécrit pas'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status <> 'PENDING' THEN
    RAISE EXCEPTION 'outbox : un événement % est figé — il ne se rejoue jamais', OLD.status
      USING ERRCODE = 'P0103';
  END IF;

  -- Le compteur d'essais ne peut QU'incrémenter de 1 (patron C8) : un
  -- compteur qui se remet à zéro n'est pas un plafond.
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
-- 2) La politique de canal : DES DONNÉES, pas du code.
-- -----------------------------------------------------------------------------
CREATE TABLE event_channel_policy (
  event_type       text PRIMARY KEY,
  -- Canaux EXTERNES permis pour cet événement. Un tableau VIDE = aucun envoi
  -- externe n'est permis, jamais.
  allowed_channels proof_channel[] NOT NULL,
  -- La notification est-elle déposée dans le compte (lue à la prochaine
  -- connexion) ? C'est le seul canal possible quand la ligne est perdue.
  in_account       boolean NOT NULL DEFAULT false,
  note             text NOT NULL
);

INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note) VALUES
  ('PHONE_LINE_SUPERSEDED', '{}', true,
   'La ligne vient d''être reprise : elle est dans la main d''un inconnu. AUCUN canal externe — un message y atteindrait le nouveau porteur de la SIM et lui révélerait qu''un compte était rattaché à ce numéro. La notification est déposée dans le compte, que son titulaire lira à sa prochaine connexion.');

GRANT SELECT ON event_channel_policy TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON event_channel_policy FROM user_core_app;

-- -----------------------------------------------------------------------------
-- 3) Les notifications déposées dans le compte. ZÉRO PII : un type
--    d'événement, un titulaire, un horodatage. Jamais un numéro, même
--    chiffré, même masqué.
-- -----------------------------------------------------------------------------
CREATE TABLE account_notifications (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES accounts(id),
  event_type text NOT NULL,
  outbox_id  uuid NOT NULL REFERENCES outbox(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  read_at    timestamptz,
  -- Une notification par événement : le drainage est idempotent, un retry ne
  -- la duplique pas.
  CONSTRAINT uq_account_notifications_outbox UNIQUE (outbox_id)
);

CREATE INDEX idx_account_notifications_account ON account_notifications (account_id, created_at);

CREATE TRIGGER trg_account_notifications_no_delete
  BEFORE DELETE ON account_notifications
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

GRANT SELECT ON account_notifications TO user_core_app;
GRANT UPDATE (read_at) ON account_notifications TO user_core_app;
REVOKE INSERT, DELETE, TRUNCATE ON account_notifications FROM user_core_app;

-- -----------------------------------------------------------------------------
-- 4) LA RÉSOLUTION D'ADRESSE — le cœur du piège.
--
-- On ne rend l'adresse d'une revendication QUE si elle est ACTIVE. L'événement
-- PHONE_LINE_SUPERSEDED porte la revendication RÉVOQUÉE : cette fonction
-- rendra donc NULL pour lui, toujours. Ce n'est pas un « if » dans le
-- publisher (qu'une v2 oublierait) : c'est une impossibilité.
-- -----------------------------------------------------------------------------
CREATE FUNCTION resolve_notification_address(p_claim_id uuid) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  token text;
BEGIN
  SELECT phone_encrypted INTO token
    FROM phone_claims
   WHERE id = p_claim_id
     AND status = 'ACTIVE';   -- une ligne révoquée n'a PLUS d'adresse. Jamais.
  RETURN token;   -- NULL si la revendication n'est pas active : rien à envoyer.
END;
$$;

REVOKE ALL ON FUNCTION resolve_notification_address(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_notification_address(uuid) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 5) Le drainage — UN publisher. Réserver un lot (bail), publier, échouer.
--    Aucun topic, aucun offset multi-consommateurs, aucun replay sélectif,
--    aucun dead-letter par consommateur (§3.12).
-- -----------------------------------------------------------------------------
CREATE FUNCTION claim_outbox_batch(p_batch_size integer, p_lease_seconds integer)
RETURNS TABLE (id uuid, event_type text, account_id uuid, claim_id uuid, attempts integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  -- SKIP LOCKED : deux workers ne prennent jamais le même événement. Le bail
  -- (next_attempt_at repoussé) évite qu'un worker mort bloque la file.
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
  RETURNING o.id, o.event_type, o.account_id, o.claim_id, o.attempts;
END;
$$;

-- Publication réussie. Idempotente : deux appels ne rejouent rien (la garde
-- fige la ligne au premier).
CREATE FUNCTION publish_outbox_event(p_id uuid, p_notify_account boolean) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  e outbox%ROWTYPE;
BEGIN
  SELECT * INTO e FROM outbox WHERE id = p_id AND status = 'PENDING' FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;   -- déjà clos : on ne rejoue jamais.
  END IF;

  IF p_notify_account THEN
    INSERT INTO account_notifications (account_id, event_type, outbox_id)
    VALUES (e.account_id, e.event_type, e.id)
    ON CONFLICT (outbox_id) DO NOTHING;
  END IF;

  UPDATE outbox SET status = 'PUBLISHED' WHERE id = e.id;
END;
$$;

-- Échec d'une tentative : on compte, on repousse (backoff calculé par
-- l'appelant, en config), et au-delà du plafond on FERME définitivement —
-- avec son code d'erreur. Un événement indélivrable ne tourne pas en boucle
-- pour l'éternité sur un canal payant.
CREATE FUNCTION fail_outbox_attempt(
  p_id uuid,
  p_error_code text,
  p_max_attempts integer,
  p_backoff_seconds integer
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  e outbox%ROWTYPE;
BEGIN
  SELECT * INTO e FROM outbox WHERE id = p_id AND status = 'PENDING' FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'ALREADY_SETTLED';
  END IF;

  UPDATE outbox
     SET attempts = attempts + 1,
         last_error_code = p_error_code,
         next_attempt_at = now() + make_interval(secs => p_backoff_seconds)
   WHERE id = e.id;

  IF e.attempts + 1 >= p_max_attempts THEN
    UPDATE outbox SET status = 'FAILED' WHERE id = e.id;
    RETURN 'FAILED';
  END IF;

  RETURN 'RETRY';
END;
$$;

REVOKE ALL ON FUNCTION claim_outbox_batch(integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION publish_outbox_event(uuid, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION fail_outbox_attempt(uuid, text, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_outbox_batch(integer, integer) TO user_core_app;
GRANT EXECUTE ON FUNCTION publish_outbox_event(uuid, boolean) TO user_core_app;
GRANT EXECUTE ON FUNCTION fail_outbox_attempt(uuid, text, integer, integer) TO user_core_app;
