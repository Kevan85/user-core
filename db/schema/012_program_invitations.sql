-- =============================================================================
-- 012 — Les invitations : le rattachement qui a cassé Scolaria, fait mur.
--
-- LE PIÈGE DE CE LOT (donné d'avance) : pour inviter, un programme fournit un
-- numéro. Répondre « connu / inconnu » serait une MACHINE À ÉNUMÉRER
-- l'écosystème : un client compromis sonderait tous les numéros du pays et
-- apprendrait qui possède un compte — une fuite sur des TIERS, invisible.
-- RÈGLE GRAVÉE ICI : open_program_invitation() NE CONSULTE JAMAIS
-- phone_claims. Le coût et la forme de la réponse sont identiques, numéro
-- connu ou non, PAR CONSTRUCTION — il n'y a pas de branche à tester, il n'y a
-- pas de branche du tout. Le programme n'apprend l'existence d'un compte que
-- si la personne ACCEPTE.
--
-- L'ORACLE SECONDAIRE, fermé par « suppressed » : le plafond par LIGNE se
-- refuse EN SILENCE (un refus franc dirait « d'autres programmes ont déjà
-- sondé ce numéro » — fuite inter-programmes). Mais un silence qui ne crée
-- rien casserait l'idempotence : ré-inviter rendrait un id NEUF à chaque
-- appel refusé, et le MÊME id sur le chemin réel — le client comparerait
-- deux réponses et détecterait le plafond. D'où : le refus silencieux CRÉE
-- une invitation réelle, marquée suppressed — idempotente comme les autres,
-- INVISIBLE de la famille, INACCEPTABLE (les fonctions la traitent comme
-- inexistante). Indiscernable du dehors, inerte au-dedans, journalisée.
-- Le plafond par CLIENT, lui, se refuse en 429 franc : il ne parle que de
-- l'appelant, il ne fuit rien sur les tiers.
--
-- LE RATTACHEMENT N'A AUCUN ÉTAT : une invitation est visible d'un compte si
-- l'empreinte de sa ligne PROUVÉE est celle de l'invitation — un SELECT,
-- rien à « nouer » au moment de la preuve, rien qu'un chemin d'appel puisse
-- oublier. JAMAIS un second compte pour la même personne : l'unicité
-- mondiale de la ligne prouvée (006) porte tout.
--
-- ⚠️ DETTE DE ROTATION HMAC (héritée de 006, ÉTENDUE ICI) : la procédure
-- exceptionnelle de rotation de la clé d'empreinte doit désormais re-hacher
-- TROIS tables — phone_claims, program_invitations ET
-- program_invitation_refusals. Toute table future qui range une empreinte
-- s'ajoute à cette liste, dans ce commentaire et dans la migration signée.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE program_invitation_status AS ENUM (
  'PENDING',
  'ACCEPTED',
  'DECLINED',   -- refusée par la famille : le programme ne le saura JAMAIS
                -- (pour lui, indiscernable d'une invitation restée sans suite)
  'EXPIRED'
);

CREATE TABLE program_invitations (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  program_id          uuid NOT NULL REFERENCES programs(id),
  -- L'empreinte de la ligne invitée — JAMAIS le clair, JAMAIS le chiffré :
  -- on n'envoie RIEN en V1, l'invitation se DÉCOUVRE (dans l'app du compte
  -- qui a prouvé cette ligne). Il n'y a donc aucune adresse à retenir.
  phone_hmac          text NOT NULL,
  hmac_key_id         text NOT NULL,
  status              program_invitation_status NOT NULL DEFAULT 'PENDING',
  -- Le refus silencieux du plafond par ligne (voir l'en-tête) : une ligne
  -- suppressed est invisible et inacceptable, mais elle occupe le créneau
  -- d'idempotence comme une vraie — l'appelant ne peut pas les distinguer.
  suppressed          boolean NOT NULL DEFAULT false,
  expires_at          timestamptz NOT NULL,
  accepted_account_id uuid REFERENCES accounts(id),
  settled_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_invitations_settled_pair
    CHECK ((status = 'PENDING') = (settled_at IS NULL)),
  CONSTRAINT chk_invitations_accepted_pair
    CHECK ((status = 'ACCEPTED') = (accepted_account_id IS NOT NULL)),
  CONSTRAINT chk_invitations_expiry_future CHECK (expires_at > created_at)
);

-- Ré-inviter = LA MÊME invitation (idempotence) : au plus une PENDING par
-- couple (programme, ligne). L'historique des invitations closes reste.
CREATE UNIQUE INDEX uq_program_invitations_pending
  ON program_invitations (program_id, hmac_key_id, phone_hmac)
  WHERE status = 'PENDING';

-- La découverte côté compte : « quelles invitations portent MA ligne ? »
CREATE INDEX idx_program_invitations_line
  ON program_invitations (hmac_key_id, phone_hmac);
CREATE INDEX idx_program_invitations_program
  ON program_invitations (program_id, created_at);

-- -----------------------------------------------------------------------------
-- Les SONDAGES sont journalisés (append-only) : chaque refus de plafond
-- laisse une trace horodatée que l'exploitation peut surveiller. Zéro PII :
-- une empreinte, un programme, un motif.
-- -----------------------------------------------------------------------------
CREATE TYPE program_invitation_refusal_reason AS ENUM (
  'CLIENT_INVITE_CAP',  -- le client a trop invité, toutes lignes confondues
  'LINE_INVITE_CAP'     -- la LIGNE a trop été invitée, tous programmes confondus
);

CREATE TABLE program_invitation_refusals (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  program_id  uuid NOT NULL REFERENCES programs(id),
  phone_hmac  text NOT NULL,
  hmac_key_id text NOT NULL,
  reason      program_invitation_refusal_reason NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_invitation_refusals_line
  ON program_invitation_refusals (phone_hmac, created_at);

-- -----------------------------------------------------------------------------
-- Gardes de naissance : programme ACTIVE (P0108), et l'empreinte TOUJOURS
-- sous la clé active (P0109, patron 006 — sinon la rotation laisserait des
-- invitations hors référence, introuvables par la ligne qui les cherche).
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_program_invitation_insert() RETURNS trigger AS $$
DECLARE
  prog_status program_status;
BEGIN
  SELECT status INTO prog_status FROM programs WHERE id = NEW.program_id FOR SHARE;
  IF prog_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_invitations : aucune invitation ne naît sous un programme % (P0108)',
      prog_status USING ERRCODE = 'P0108';
  END IF;
  IF NEW.hmac_key_id <> active_hmac_key_id() THEN
    RAISE EXCEPTION 'program_invitations : empreinte calculée sous la clé « % », active = « % » — une rotation est une migration signée',
      NEW.hmac_key_id, active_hmac_key_id() USING ERRCODE = 'P0109';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_invitations_guard_insert
  BEFORE INSERT ON program_invitations
  FOR EACH ROW EXECUTE FUNCTION guard_program_invitation_insert();

CREATE FUNCTION guard_program_invitation_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.program_id IS DISTINCT FROM OLD.program_id
     OR NEW.phone_hmac IS DISTINCT FROM OLD.phone_hmac
     OR NEW.hmac_key_id IS DISTINCT FROM OLD.hmac_key_id
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'program_invitations : contenu immuable — ré-inviter = la même invitation, ou une neuve après clôture'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status <> 'PENDING' THEN
    RAISE EXCEPTION 'program_invitations : une invitation close est figée (%)', OLD.status
      USING ERRCODE = 'P0103';
  END IF;

  -- suppressed ne va que vers la VISIBILITÉ (levée du silence quand le
  -- plafond s'est libéré), jamais l'inverse : cacher après coup une
  -- invitation qu'une famille a pu voir serait réécrire l'histoire.
  IF NEW.suppressed IS DISTINCT FROM OLD.suppressed THEN
    IF NOT (OLD.suppressed AND NOT NEW.suppressed) THEN
      RAISE EXCEPTION 'program_invitations : suppressed ne revient jamais — une invitation vue ne se cache plus'
        USING ERRCODE = 'P0102';
    END IF;
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'ACCEPTED' THEN
      IF NEW.accepted_account_id IS NULL THEN
        RAISE EXCEPTION 'program_invitations : une acceptation porte toujours son compte'
          USING ERRCODE = 'P0102';
      END IF;
    ELSIF NEW.accepted_account_id IS DISTINCT FROM OLD.accepted_account_id THEN
      RAISE EXCEPTION 'program_invitations : accepted_account_id ne se pose qu''à l''acceptation'
        USING ERRCODE = 'P0104';
    END IF;
    NEW.settled_at := now();   -- la base horodate la clôture, jamais le client
  ELSE
    IF NEW.settled_at IS DISTINCT FROM OLD.settled_at
       OR NEW.accepted_account_id IS DISTINCT FROM OLD.accepted_account_id THEN
      RAISE EXCEPTION 'program_invitations : les horodatages de registre sont posés par la base'
        USING ERRCODE = 'P0104';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_invitations_guard_update
  BEFORE UPDATE ON program_invitations
  FOR EACH ROW EXECUTE FUNCTION guard_program_invitation_update();

CREATE TRIGGER trg_program_invitations_no_delete
  BEFORE DELETE ON program_invitations
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

CREATE TRIGGER trg_invitation_refusals_no_update
  BEFORE UPDATE ON program_invitation_refusals
  FOR EACH ROW EXECUTE FUNCTION forbid_update();

CREATE TRIGGER trg_invitation_refusals_no_delete
  BEFORE DELETE ON program_invitation_refusals
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- La règle de Kevin (15/07/2026), gravée : « le bouton activé/désactivé est
-- un simple interrupteur dans l'app de la famille — pas besoin du tiers pour
-- ça. » Donc : granted_by = 'PROGRAM' est REFUSÉ si le dernier retrait du
-- couple porte revoke_reason = 'SELF'. Ce que la famille a fermé, ELLE SEULE
-- le rouvre, d'un clic. Miroir exact de la règle de 008 (la famille ne rouvre
-- pas ce qu'un tiers a fermé). Et un programme n'ouvre un droit QUE sur le
-- mode accordé : sur du libre-service, pousser un droit sans geste de la
-- famille n'existe pas.
-- (CREATE OR REPLACE : 008 est fusionnée, donc immuable — patron 005.)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_program_grant_insert() RETURNS trigger AS $$
DECLARE
  account_status account_status;
  p programs%ROWTYPE;
  last_grant program_grants%ROWTYPE;
BEGIN
  SELECT status INTO account_status FROM accounts WHERE id = NEW.account_id FOR SHARE;
  IF account_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_grants : aucun droit ne naît sous un compte % (C13)', account_status
      USING ERRCODE = 'P0108';
  END IF;

  SELECT * INTO p FROM programs WHERE id = NEW.program_id FOR SHARE;
  IF p.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_grants : le programme n''est plus proposé (%)', p.status
      USING ERRCODE = 'P0108';
  END IF;

  IF p.access_mode = 'GRANTED' AND NEW.granted_by = 'SELF' THEN
    SELECT * INTO last_grant FROM program_grants g
     WHERE g.account_id = NEW.account_id
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
     WHERE g.account_id = NEW.account_id
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

-- -----------------------------------------------------------------------------
-- OUVRIR une invitation : les plafonds vivent ICI, pas dans le service (le
-- rôle applicatif n'a AUCUN droit d'insertion — patron open_possession_proof,
-- 007). Le service passe les plafonds en paramètres (config, jamais figés).
--
-- ⚠️ CETTE FONCTION NE TOUCHE PAS phone_claims — c'est LA propriété du lot.
-- Verdicts : RECEIVED · RECEIVED_EXISTING · SUPPRESSED · REFUSED_CLIENT_CAP ·
-- UNKNOWN_PROGRAM. Côté API, RECEIVED / RECEIVED_EXISTING / SUPPRESSED
-- rendent LE MÊME accusé de réception ; le verdict interne vaut de l'or au
-- support, la réponse externe ne distingue rien.
-- -----------------------------------------------------------------------------
CREATE FUNCTION open_program_invitation(
  p_program_id              uuid,
  p_phone_hmac              text,
  p_hmac_key_id             text,
  p_ttl_seconds             integer,
  p_client_cap              integer,
  p_client_cap_window_seconds integer,
  p_line_cap                integer,
  p_line_cap_window_seconds integer
)
RETURNS TABLE (invitation_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  prog_status program_status;
  existing program_invitations%ROWTYPE;
  on_line integer;
  by_client integer;
  new_row program_invitations%ROWTYPE;
BEGIN
  SELECT status INTO prog_status FROM programs WHERE id = p_program_id;
  IF NOT FOUND OR prog_status <> 'ACTIVE' THEN
    invitation_id := NULL; verdict := 'UNKNOWN_PROGRAM';
    RETURN NEXT; RETURN;
  END IF;

  -- Sérialise deux appels concurrents pour le même couple (programme, ligne) :
  -- l'idempotence ne se perd pas dans une course, et aucune violation d'index
  -- ne remonte au client comme un signal.
  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_program_id::text || '/' || p_hmac_key_id || '/' || p_phone_hmac, 52170012)
  );

  SELECT * INTO existing FROM program_invitations i
   WHERE i.program_id = p_program_id
     AND i.hmac_key_id = p_hmac_key_id
     AND i.phone_hmac = p_phone_hmac
     AND i.status = 'PENDING'
   FOR UPDATE;

  IF FOUND THEN
    IF existing.expires_at <= now() THEN
      -- Clôture paresseuse : la vieille expire, une neuve pourra naître.
      UPDATE program_invitations SET status = 'EXPIRED' WHERE id = existing.id;
    ELSE
      -- Idempotence : LA MÊME invitation, suppressed ou non — indiscernable.
      -- Si le silence avait été imposé par le plafond de ligne et que la
      -- fenêtre s'est libérée, l'invitation devient VISIBLE : le programme
      -- qui ré-invite légitimement n'attend pas l'expiration du TTL.
      IF existing.suppressed THEN
        SELECT count(*) INTO on_line FROM program_invitations i
         WHERE i.hmac_key_id = p_hmac_key_id
           AND i.phone_hmac = p_phone_hmac
           AND i.id <> existing.id
           AND i.created_at > now() - make_interval(secs => p_line_cap_window_seconds);
        IF on_line < p_line_cap THEN
          UPDATE program_invitations SET suppressed = false WHERE id = existing.id;
        END IF;
      END IF;
      invitation_id := existing.id; verdict := 'RECEIVED_EXISTING';
      RETURN NEXT; RETURN;
    END IF;
  END IF;

  -- Plafond PAR CLIENT (toutes lignes confondues) : refus FRANC — il ne
  -- parle que de l'appelant, il ne fuit rien sur des tiers.
  SELECT count(*) INTO by_client FROM program_invitations i
   WHERE i.program_id = p_program_id
     AND i.created_at > now() - make_interval(secs => p_client_cap_window_seconds);
  IF by_client >= p_client_cap THEN
    INSERT INTO program_invitation_refusals (program_id, phone_hmac, hmac_key_id, reason)
    VALUES (p_program_id, p_phone_hmac, p_hmac_key_id, 'CLIENT_INVITE_CAP');
    invitation_id := NULL; verdict := 'REFUSED_CLIENT_CAP';
    RETURN NEXT; RETURN;
  END IF;

  -- Plafond PAR LIGNE (tous programmes confondus) : refus SILENCIEUX —
  -- l'invitation naît suppressed, le sondage est journalisé, la réponse
  -- externe est identique à un accusé normal.
  SELECT count(*) INTO on_line FROM program_invitations i
   WHERE i.hmac_key_id = p_hmac_key_id
     AND i.phone_hmac = p_phone_hmac
     AND i.created_at > now() - make_interval(secs => p_line_cap_window_seconds);

  INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, suppressed, expires_at)
  VALUES (p_program_id, p_phone_hmac, p_hmac_key_id, on_line >= p_line_cap,
          now() + make_interval(secs => p_ttl_seconds))
  RETURNING * INTO new_row;

  IF new_row.suppressed THEN
    INSERT INTO program_invitation_refusals (program_id, phone_hmac, hmac_key_id, reason)
    VALUES (p_program_id, p_phone_hmac, p_hmac_key_id, 'LINE_INVITE_CAP');
    invitation_id := new_row.id; verdict := 'SUPPRESSED';
  ELSE
    invitation_id := new_row.id; verdict := 'RECEIVED';
  END IF;
  RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- ACCEPTER : BOLA EN BASE — seul le compte qui détient la revendication
-- ACTIVE de LA ligne invitée peut accepter, même en connaissant l'uuid.
-- L'acceptation crée le droit et clôt l'invitation DANS LA MÊME TRANSACTION.
--
-- Qui ouvre le droit ? Le PROGRAMME (c'est son invitation, la famille
-- consent). UNE exception, exigée par la règle de Kevin : si la famille
-- avait fermé elle-même (dernier retrait SELF), c'est ELLE qui rouvre —
-- l'acceptation est précisément son clic — et le droit naît granted_by =
-- 'SELF', la seule forme que la garde de 008 accepte dans ce cas.
--
-- Verdicts : ACCEPTED · ALREADY_SETTLED · EXPIRED · LINE_NOT_PROVEN · UNKNOWN
-- -----------------------------------------------------------------------------
CREATE FUNCTION accept_program_invitation(p_invitation_id uuid, p_account_id uuid)
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
  -- Une invitation suppressed N'EXISTE PAS pour ce chemin : la famille ne
  -- l'a jamais vue, personne ne l'accepte — pas même son destinataire.
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
     WHERE c.account_id = p_account_id
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
    -- Le droit existe déjà : l'acceptation ne crée rien, elle clôt.
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

-- -----------------------------------------------------------------------------
-- DÉCLINER : même BOLA, aucun droit créé, et le programme n'en saura RIEN —
-- pour lui, une invitation déclinée est indiscernable d'une invitation restée
-- sans réponse. Refuser ne révèle pas d'exister.
-- -----------------------------------------------------------------------------
CREATE FUNCTION decline_program_invitation(p_invitation_id uuid, p_account_id uuid)
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
     WHERE c.account_id = p_account_id
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

-- -----------------------------------------------------------------------------
-- Droits : le service n'écrit RIEN ici. Il exécute, il obéit aux verdicts.
-- -----------------------------------------------------------------------------
GRANT SELECT ON program_invitations TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON program_invitations FROM user_core_app;

GRANT SELECT ON program_invitation_refusals TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON program_invitation_refusals FROM user_core_app;

REVOKE ALL ON FUNCTION open_program_invitation(uuid, text, text, integer, integer, integer, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION accept_program_invitation(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION decline_program_invitation(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_program_invitation(uuid, text, text, integer, integer, integer, integer, integer) TO user_core_app;
GRANT EXECUTE ON FUNCTION accept_program_invitation(uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION decline_program_invitation(uuid, uuid) TO user_core_app;
