-- =============================================================================
-- 004 — sessions : UN SEUL patron, web ET mobile (CLAUDE.md §3.6). Jamais de
-- jeton auto-suffisant longue durée : la lignée (sessions) est révocable
-- serveur, ses jetons de rafraîchissement sont HACHÉS, tournés, à jti unique.
--
-- C1 : la révocation CASCADE dans la base elle-même (trigger AFTER UPDATE) —
-- jamais dans le chemin de refresh, que la v2 d'un endpoint oublierait.
-- C5 : absolute_expires_at NOT NULL — une session ne devient pas immortelle
-- par rotation infinie. La valeur vient de la config, jamais figée ici.
-- C5-bis : la base REFUSE de créer un jeton sous une session révoquée ou
-- expirée (trigger BEFORE INSERT), et aucun statut ne revient vers ACTIVE.
--
-- Standard 002/003 : GRANT par colonne (INSERT et UPDATE), horodatages posés
-- par la base, search_path épinglé, forbid_delete() réutilisé, lignes
-- terminales figées.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE session_status AS ENUM (
  'ACTIVE',
  'REVOKED'   -- révoqué, jamais supprimé (§3.10) — et jamais réactivé
);

CREATE TYPE session_revoke_reason AS ENUM (
  'LOGOUT',
  'LOGOUT_ALL',
  'REPLAY_DETECTED',
  'ADMIN'
);

CREATE TYPE refresh_token_status AS ENUM (
  'ACTIVE',
  'ROTATED',
  'REVOKED'
);

CREATE TABLE sessions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id          uuid NOT NULL REFERENCES accounts(id),
  status              session_status NOT NULL DEFAULT 'ACTIVE',
  revoked_at          timestamptz,
  revoke_reason       session_revoke_reason,
  -- C5 : l'échéance absolue, obligatoire et immuable. La prolonger = ouvrir
  -- une nouvelle session (et donc se ré-authentifier).
  absolute_expires_at timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_sessions_absolute_future CHECK (absolute_expires_at > created_at),
  CONSTRAINT chk_sessions_revoked_pair
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CONSTRAINT chk_sessions_reason_pair
    CHECK ((status = 'REVOKED') = (revoke_reason IS NOT NULL))
);

CREATE INDEX idx_sessions_account ON sessions (account_id);

-- Le registre ne porte JAMAIS une ligne qui ment : pas de session ACTIVE
-- sous un compte non actif. Sans ça, une session « active » d'un compte mort
-- existe (ses jetons sont morts-nés, mais le registre affirme le faux).
-- FOR SHARE : sérialise avec une désactivation concurrente (le verrou force
-- l'INSERT à voir le statut committé), symétrique de guard_refresh_token_insert.
CREATE FUNCTION guard_session_insert() RETURNS trigger AS $$
DECLARE
  account_status account_status;
BEGIN
  SELECT status INTO account_status FROM accounts WHERE id = NEW.account_id FOR SHARE;
  IF account_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'sessions : aucune session ne naît sous un compte % (C13)', account_status;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_sessions_guard_insert
  BEFORE INSERT ON sessions
  FOR EACH ROW EXECUTE FUNCTION guard_session_insert();

CREATE TABLE session_refresh_tokens (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id     uuid NOT NULL REFERENCES sessions(id),
  jti            uuid NOT NULL,
  token_hash     text NOT NULL,   -- JAMAIS la valeur du jeton (§3.6)
  status         refresh_token_status NOT NULL DEFAULT 'ACTIVE',
  rotated_at     timestamptz,
  grace_until    timestamptz,
  replaced_by_id uuid,
  expires_at     timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_session_refresh_tokens_jti UNIQUE (jti),
  -- C11 : deux jetons de même valeur sont NON REPRÉSENTABLES. Sans cette
  -- contrainte, lookup_refresh_token (SELECT INTO non-STRICT) rendrait son
  -- verdict sur une ligne arbitraire — le jeton révoqué de la session A
  -- pourrait recevoir le verdict USABLE de la session B.
  CONSTRAINT uq_srt_token_hash UNIQUE (token_hash),
  CONSTRAINT chk_srt_expires_future CHECK (expires_at > created_at),
  -- Une rotation porte TOUJOURS son horodatage et sa fenêtre de grâce.
  CONSTRAINT chk_srt_rotated_fields
    CHECK (status <> 'ROTATED' OR (rotated_at IS NOT NULL AND grace_until IS NOT NULL)),
  -- Clé candidate pour la FK composite du chaînage (patron payment-core) :
  -- un successeur appartient à LA MÊME session, le compilateur de la base
  -- l'impose.
  CONSTRAINT uq_srt_id_session UNIQUE (id, session_id),
  CONSTRAINT fk_srt_replaced_by_same_session
    FOREIGN KEY (replaced_by_id, session_id)
    REFERENCES session_refresh_tokens (id, session_id)
);

-- Au plus UN jeton ACTIVE par session ; l'historique reste.
CREATE UNIQUE INDEX uq_session_refresh_tokens_active
  ON session_refresh_tokens (session_id) WHERE status = 'ACTIVE';

CREATE INDEX idx_srt_session ON session_refresh_tokens (session_id);
-- La recherche par hash passe par l'index de la contrainte uq_srt_token_hash
-- (C11) : pas d'index dédié redondant.

-- -----------------------------------------------------------------------------
-- sessions : identité immuable, révocation horodatée par la base, ligne
-- révoquée figée.
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_session_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'sessions : identité immuable — prolonger une session = en ouvrir une nouvelle';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'sessions : une session révoquée est figée — elle ne revient jamais';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    -- Ici OLD.status = ACTIVE ; la seule destination est REVOKED.
    IF NEW.revoke_reason IS NULL THEN
      RAISE EXCEPTION 'sessions : une révocation porte toujours son motif';
    END IF;
    -- La base horodate elle-même : toute valeur envoyée est écrasée (D1).
    NEW.revoked_at := now();
  ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
     OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason THEN
    RAISE EXCEPTION 'sessions : revoked_at et revoke_reason sont posés à la révocation, jamais avant ni après';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_sessions_guard
  BEFORE UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION guard_session_update();

-- C1 : LA cascade — quand une session passe REVOKED, la BASE éteint tous ses
-- jetons. Aucun chemin d'appel (refresh v2, job, endpoint admin) ne peut
-- l'oublier : elle n'est écrite nulle part ailleurs.
CREATE FUNCTION cascade_session_revocation() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'REVOKED' AND OLD.status IS DISTINCT FROM NEW.status THEN
    UPDATE session_refresh_tokens
       SET status = 'REVOKED'
     WHERE session_id = NEW.id
       AND status <> 'REVOKED';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_sessions_cascade_revocation
  AFTER UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION cascade_session_revocation();

-- C13 : désactiver un compte COUPE TOUT — le mur porteur est en base, patron
-- C1. Au passage à DEACTIVATED, la base révoque toutes les sessions du
-- compte (motif ADMIN), ce qui déclenche à son tour la cascade C1 sur les
-- jetons. Une seule écriture, tout tombe — aucun chemin d'appel à se
-- souvenir de rien. (Le trigger vit dans 004 : c'est ici que sessions
-- existe ; 002 ne la connaît pas.)
CREATE FUNCTION cascade_account_deactivation() RETURNS trigger AS $$
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

CREATE TRIGGER trg_accounts_cascade_deactivation
  AFTER UPDATE ON accounts
  FOR EACH ROW EXECUTE FUNCTION cascade_account_deactivation();

CREATE TRIGGER trg_sessions_no_delete
  BEFORE DELETE ON sessions
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- session_refresh_tokens : C5-bis à la naissance, machine d'état au vieillissement.
-- -----------------------------------------------------------------------------
-- C5-bis : aucun jeton ne naît sous une session morte ou hors échéance.
-- FOR SHARE : sérialise avec une révocation concurrente de la session (le
-- verrou de ligne force cette insertion à VOIR le statut committé) — sans
-- lui, un jeton pourrait naître pendant la cascade C1 et lui échapper.
CREATE FUNCTION guard_refresh_token_insert() RETURNS trigger AS $$
DECLARE
  session_row sessions%ROWTYPE;
BEGIN
  SELECT * INTO session_row FROM sessions WHERE id = NEW.session_id FOR SHARE;

  IF session_row.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'session_refresh_tokens : aucun jeton ne naît sous une session % (C5-bis)',
      session_row.status;
  END IF;
  IF session_row.absolute_expires_at <= now() THEN
    RAISE EXCEPTION 'session_refresh_tokens : la session a dépassé son échéance absolue (C5)';
  END IF;
  -- C10-b : un jeton ne survit JAMAIS à sa session.
  IF NEW.expires_at > session_row.absolute_expires_at THEN
    RAISE EXCEPTION 'session_refresh_tokens : un jeton ne survit jamais à sa session (échéance absolue dépassée)';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_srt_guard_insert
  BEFORE INSERT ON session_refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION guard_refresh_token_insert();

CREATE FUNCTION guard_refresh_token_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.jti IS DISTINCT FROM OLD.jti
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'session_refresh_tokens : contenu immuable — tourner = émettre un successeur';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'session_refresh_tokens : un jeton révoqué est figé — il ne revient jamais';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF OLD.status = 'ACTIVE' AND NEW.status = 'ROTATED' THEN
      IF NEW.grace_until IS NULL THEN
        RAISE EXCEPTION 'session_refresh_tokens : la rotation pose sa fenêtre de grâce';
      END IF;
      -- La base horodate elle-même : toute valeur envoyée est écrasée (D1).
      NEW.rotated_at := now();
    ELSIF NEW.status = 'REVOKED' THEN
      IF NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
         OR NEW.grace_until IS DISTINCT FROM OLD.grace_until
         OR NEW.replaced_by_id IS DISTINCT FROM OLD.replaced_by_id THEN
        RAISE EXCEPTION 'session_refresh_tokens : la révocation ne retouche pas la rotation';
      END IF;
    ELSE
      RAISE EXCEPTION 'session_refresh_tokens : % -> % interdit — aucun retour vers ACTIVE',
        OLD.status, NEW.status;
    END IF;
  ELSE
    IF NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
       OR NEW.grace_until IS DISTINCT FROM OLD.grace_until THEN
      RAISE EXCEPTION 'session_refresh_tokens : rotated_at et grace_until sont posés à la rotation, jamais réécrits';
    END IF;
    IF NEW.replaced_by_id IS DISTINCT FROM OLD.replaced_by_id
       AND NOT (OLD.status = 'ROTATED' AND OLD.replaced_by_id IS NULL
                AND NEW.replaced_by_id IS NOT NULL) THEN
      RAISE EXCEPTION 'session_refresh_tokens : replaced_by_id est set-once, posé juste après la rotation';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_srt_guard_update
  BEFORE UPDATE ON session_refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION guard_refresh_token_update();

CREATE TRIGGER trg_srt_no_delete
  BEFORE DELETE ON session_refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- Droits (standard 002/003) : la base pose id, statuts initiaux, horodatages.
-- -----------------------------------------------------------------------------
GRANT SELECT ON sessions TO user_core_app;
GRANT INSERT (account_id, absolute_expires_at) ON sessions TO user_core_app;
GRANT UPDATE (status, revoke_reason) ON sessions TO user_core_app;
REVOKE DELETE, TRUNCATE ON sessions FROM user_core_app;

-- C10 : token_hash n'est PAS lisible par le service — pas de GRANT SELECT au
-- niveau table (un REVOKE de colonne ne soustrait rien à un grant de table en
-- Postgres : on accorde la liste SANS token_hash). Retrouver un jeton par son
-- hash exigerait le privilège SELECT sur la colonne, même dans un WHERE :
-- c'est donc la BASE qui compare et rend un VERDICT (lookup_refresh_token).
-- Un « WHERE status = 'ACTIVE' » oublié dans une v2 du refresh n'existe
-- plus : il n'y a plus de WHERE à écrire dans le service.
GRANT SELECT (id, session_id, jti, status, rotated_at, grace_until,
              replaced_by_id, expires_at, created_at)
  ON session_refresh_tokens TO user_core_app;
GRANT INSERT (session_id, jti, token_hash, expires_at)
  ON session_refresh_tokens TO user_core_app;
GRANT UPDATE (status, grace_until, replaced_by_id)
  ON session_refresh_tokens TO user_core_app;
REVOKE DELETE, TRUNCATE ON session_refresh_tokens FROM user_core_app;

-- -----------------------------------------------------------------------------
-- C10 : LE verdict, calculé à un seul endroit, en base. SECURITY DEFINER :
-- la fonction lit token_hash avec les droits de son propriétaire ; le rôle
-- bridé n'a que EXECUTE. L'API n'agit que sur le verdict :
--   USABLE  → jeton ACTIVE non expiré, session ACTIVE dans son échéance ;
--   GRACE   → ROTATED dans sa fenêtre : rendre le successeur DÉJÀ émis ;
--   REPLAY  → ROTATED hors grâce ou REVOKED sous session vivante :
--             révoquer la session (REPLAY_DETECTED) ;
--   DEAD    → session révoquée ou hors échéance (ou jeton ACTIVE expiré :
--             refus simple, pas une preuve de vol) ;
--   UNKNOWN → aucun jeton ne porte ce hash.
-- -----------------------------------------------------------------------------
CREATE FUNCTION lookup_refresh_token(p_token_hash text)
RETURNS TABLE (token_id uuid, session_id uuid, account_id uuid,
               successor_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  t session_refresh_tokens%ROWTYPE;
  s sessions%ROWTYPE;
  a accounts%ROWTYPE;
BEGIN
  SELECT * INTO t FROM session_refresh_tokens srt
   WHERE srt.token_hash = p_token_hash;
  IF NOT FOUND THEN
    token_id := NULL; session_id := NULL; account_id := NULL;
    successor_id := NULL; verdict := 'UNKNOWN';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT * INTO s FROM sessions se WHERE se.id = t.session_id;
  SELECT * INTO a FROM accounts ac WHERE ac.id = s.account_id;

  token_id := t.id;
  session_id := t.session_id;
  account_id := s.account_id;
  successor_id := t.replaced_by_id;

  -- C13 (ceinture) : un compte non actif rend TOUT DEAD — même une session
  -- qu'un chemin oublieux aurait ouverte après la désactivation.
  IF a.status <> 'ACTIVE'
     OR s.status <> 'ACTIVE' OR s.absolute_expires_at <= now() THEN
    verdict := 'DEAD';
  ELSIF t.status = 'ACTIVE' AND t.expires_at > now() THEN
    verdict := 'USABLE';
  ELSIF t.status = 'ROTATED' AND t.grace_until > now() THEN
    verdict := 'GRACE';
  ELSIF t.status = 'ACTIVE' THEN
    -- ACTIVE mais expiré : un client resté longtemps hors ligne, pas une
    -- preuve de vol — refus simple, jamais une sanction de session.
    verdict := 'DEAD';
  ELSE
    -- ROTATED hors grâce ou REVOKED, sous une session vivante : rejeu.
    verdict := 'REPLAY';
  END IF;

  RETURN NEXT;
END;
$$;

-- EXECUTE est accordé à PUBLIC par défaut sur toute fonction : on ferme, puis
-- on rouvre pour le seul rôle applicatif.
REVOKE ALL ON FUNCTION lookup_refresh_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_refresh_token(text) TO user_core_app;
