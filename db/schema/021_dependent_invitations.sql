-- =============================================================================
-- 021 — Le rattachement porté par l'invitation (lot /v1, étape 2).
--
-- LE NŒUD RÉSOLU (cadrage du 21/07/2026) : trois faits, trois moments.
--   1. AU CLIC du programme : la personne-ayant droit naît (create_person, la
--      porte unique), son droit d'accès naît (granted_by = 'PROGRAM', mode
--      GRANTED exigé), et l'invitation part vers la ligne du responsable —
--      UNE transaction. Le droit de l'ayant droit N'ATTEND PAS le compte du
--      responsable (décision Kevin, verrouillée).
--   2. ENTRE le clic et l'acceptation : la personne existe SANS lien — état
--      NOMMÉ et VOULU. Personne ne peut agir sur elle dans User-Core (aucun
--      chemin BOLA n'y mène), son identité n'est lisible par aucun compte.
--      Sorties de secours : rattachement par acte staff, ou — l'âge venu —
--      l'émancipation par SA ligne (020).
--   3. À L'ACCEPTATION : le compte du responsable existe (il a posé SON
--      secret, sa ligne est PROUVÉE — sinon il ne découvre rien), et
--      l'acceptation crée les LIENS de responsabilité. Une invitation à
--      ayants droit ne crée AUCUN droit pour l'acceptant.
--
-- ÉTAT NOMMÉ — l'invitation supprimée (plafond de ligne) : l'ayant droit
-- naît AVEC son accès, l'invitation dort (suppressed, 012). Le rattachement
-- du responsable est REPORTÉ à une invitation ultérieure (qui lève le
-- silence si la fenêtre s'est libérée) ou à un acte staff. Ce n'est pas un
-- défaut : le droit n'attend pas le parent ; seule la découverte attend.
--
-- ÉTAT NOMMÉ — L'EXTINCTION SILENCIEUSE : une invitation supprimée qui
-- expire meurt comme elle a vécu — invisible. Personne ne l'a jamais vue :
-- son expiration ne produit RIEN (aucun événement d'outbox, aucune
-- notification, aucun signal à la ligne ni au programme). Sa clôture est
-- paresseuse (le prochain ré-appel du couple la passe EXPIRED, 012) et le
-- registre la garde, suppressed pour toujours — l'ORDRE DES CONTRÔLES la
-- protège : accept/decline testent suppressed AVANT l'expiration, donc une
-- supprimée expirée rend UNKNOWN, jamais EXPIRED (un EXPIRED révélerait
-- qu'elle a existé). Un test compte cette absence à chaque CI.
--
-- LA FENÊTRE UNIQUE (TTL) : l'expiration de l'invitation borne À LA FOIS le
-- rattachement par un détenteur recyclé de la ligne ET l'exposition du nom
-- de l'ayant droit (la lecture, étape 5, exige : PENDING ∧ non supprimée ∧
-- non expirée ∧ ligne prouvée de l'appelant). Résidu déclaré : dans la
-- fenêtre, qui prouve la ligne (acte coûteux et tracé, SMS/CALL) voit le nom
-- d'affichage et peut accepter — remédiation : end_responsibility (staff).
--
-- LA CLÉ D'IDEMPOTENCE (Q1, fermée sur ses deux risques) : un re-clic du
-- programme (réponse perdue, retry réseau) ne crée JAMAIS une deuxième
-- personne pour le même enfant. Le programme fournit une référence opaque ;
-- on n'en stocke que l'EMPREINTE HMAC (clé DÉDIÉE, tenue par le service —
-- ni le trousseau du téléphone, ni celui des codes) :
--   · PII fermée PAR CONSTRUCTION : si un programme y met un nom, le cœur
--     est incapable de le lire — l'empreinte survit à la crypto-destruction
--     SANS rien révéler (le piège birth_year, évité d'avance) ;
--   · frontière §7 tenue : ce registre est un VERROU ANTI-REJEU de requête,
--     pas une correspondance métier — la table « entité du programme ↔
--     identifiant » vit CHEZ le programme (CONTRAT_D_INTEGRATION) ; ici,
--     rien n'est lisible, pas même par le rôle applicatif (aucun GRANT).
--   · rotation de la clé de référence : procédure exceptionnelle documentée ;
--     conséquence déclarée — une référence rejouée SOUS UNE AUTRE CLÉ n'est
--     plus reconnue (l'idempotence ne traverse pas une rotation). Aucun
--     épinglage à une référence en base (contrairement à 012/P0109) : une
--     empreinte de référence n'est jamais CHERCHÉE depuis ailleurs, une clé
--     désalignée n'égare personne — elle élargit la fenêtre de doublon, et
--     c'est la procédure de rotation qui l'assume.
--
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) La jonction invitation ↔ ayants droit, et la TRACE de l'acceptation.
--    outcome est SET-ONCE (patron provider_ref, 007) : posé par la fonction
--    d'acceptation, dans SA transaction — le registre porte le fait, aucun
--    journal séparé (Q2).
-- -----------------------------------------------------------------------------
CREATE TYPE invitation_dependent_outcome AS ENUM (
  'LINKED',              -- le lien de responsabilité est né à l'acceptation
  'ALREADY_LINKED',      -- l'acceptant était déjà responsable de cette personne
  'SKIPPED_AUTONOMOUS',  -- émancipée ou compte actif : la lier lèverait P0113 —
                         -- et il n'y a rien à lier, la personne est autonome
  'SKIPPED_OF_AGE'       -- adulte certain au sens du seuil : la lier lèverait
                         -- P0111 et avorterait les liens légitimes des autres
);

CREATE TABLE program_invitation_dependents (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  invitation_id       uuid NOT NULL REFERENCES program_invitations(id),
  dependent_person_id uuid NOT NULL REFERENCES persons(id),
  outcome             invitation_dependent_outcome,  -- NULL tant que rien n'est accepté
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_invitation_dependents UNIQUE (invitation_id, dependent_person_id)
);

CREATE INDEX idx_invitation_dependents_person
  ON program_invitation_dependents (dependent_person_id);

CREATE FUNCTION guard_invitation_dependent_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.invitation_id IS DISTINCT FROM OLD.invitation_id
     OR NEW.dependent_person_id IS DISTINCT FROM OLD.dependent_person_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'program_invitation_dependents : contenu immuable'
      USING ERRCODE = 'P0101';
  END IF;

  -- outcome : set-once, posé par l'acceptation, jamais réécrit.
  IF NEW.outcome IS DISTINCT FROM OLD.outcome AND OLD.outcome IS NOT NULL THEN
    RAISE EXCEPTION 'program_invitation_dependents : outcome est set-once — le verdict d''une acceptation ne se réécrit pas'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_invitation_dependents_guard_update
  BEFORE UPDATE ON program_invitation_dependents
  FOR EACH ROW EXECUTE FUNCTION guard_invitation_dependent_update();

CREATE TRIGGER trg_invitation_dependents_no_delete
  BEFORE DELETE ON program_invitation_dependents
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- 2) Le verrou d'idempotence du clic. AUCUN droit du rôle applicatif, pas
--    même SELECT : seule la fonction du clic le consulte. Le COUPLE
--    (clé, empreinte) fait l'unicité, par cohérence avec 007/012.
-- -----------------------------------------------------------------------------
CREATE TABLE program_idempotency_keys (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  program_id   uuid NOT NULL REFERENCES programs(id),
  ref_hmac     text NOT NULL,   -- l'empreinte de la référence — JAMAIS la valeur
  hmac_key_id  text NOT NULL,   -- trousseau DÉDIÉ aux références (service)
  person_id    uuid NOT NULL REFERENCES persons(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_program_idempotency_keys UNIQUE (program_id, hmac_key_id, ref_hmac)
);

CREATE TRIGGER trg_idempotency_keys_no_update
  BEFORE UPDATE ON program_idempotency_keys
  FOR EACH ROW EXECUTE FUNCTION forbid_update();

CREATE TRIGGER trg_idempotency_keys_no_delete
  BEFORE DELETE ON program_idempotency_keys
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- 3) LE CLIC — open_dependent_access() : personne + droit + invitation, une
--    transaction. Ce chemin est celui des MINEURS : un usager adulte relève
--    de l'ouverture de droit sur personne connue (étape 3/4) — le verdict
--    OF_AGE le dit proprement au programme, au lieu d'un refus brut.
--
--    Verdicts : OPENED · OPENED_EXISTING (rejeu d'idempotence) ·
--    REFUSED_CLIENT_CAP (franc : ne parle que de l'appelant, RIEN n'est créé)
--    · NOT_GRANTED_MODE · UNKNOWN_PROGRAM · OF_AGE.
--    Le plafond de LIGNE, lui, reste SILENCIEUX (suppressed, 012) et le clic
--    CONTINUE : le droit de l'ayant droit n'attend pas le parent.
-- -----------------------------------------------------------------------------
CREATE FUNCTION open_dependent_access(
  p_program_id            uuid,
  p_public_identifier     text,
  p_erasure_salt          bytea,
  p_identity_encrypted    text,
  p_enc_key_id            text,
  p_birth_year            integer,
  p_phone_hmac            text,
  p_hmac_key_id           text,
  p_external_ref_hmac     text,
  p_ref_hmac_key_id       text,
  p_invitation_ttl_seconds integer,
  p_client_cap            integer,
  p_client_cap_window_seconds integer,
  p_line_cap              integer,
  p_line_cap_window_seconds integer
) RETURNS TABLE (dependent_public_identifier text, invitation_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  prog programs%ROWTYPE;
  existing_person_id uuid;
  new_person_id uuid;
  inv_id uuid;
  inv_verdict text;
  last_grant program_grants%ROWTYPE;
BEGIN
  SELECT * INTO prog FROM programs WHERE id = p_program_id FOR SHARE;
  IF NOT FOUND OR prog.status <> 'ACTIVE' THEN
    dependent_public_identifier := NULL; invitation_id := NULL;
    verdict := 'UNKNOWN_PROGRAM'; RETURN NEXT; RETURN;
  END IF;

  -- Le mode d'accès décide : ce chemin est celui du tiers qui ouvre.
  IF prog.access_mode <> 'GRANTED' THEN
    dependent_public_identifier := NULL; invitation_id := NULL;
    verdict := 'NOT_GRANTED_MODE'; RETURN NEXT; RETURN;
  END IF;

  -- Un ayant droit naît identifié (patron attach_dependent, P0111) : sa
  -- finalité est d'être identifié auprès des programmes, et le mur de
  -- minorité exige la borne d'âge.
  IF p_identity_encrypted IS NULL OR p_enc_key_id IS NULL OR p_birth_year IS NULL THEN
    RAISE EXCEPTION 'open_dependent_access : un ayant droit naît identifié (blob, clé, année exigés)'
      USING ERRCODE = 'P0111';
  END IF;

  -- LE MUR DE MINORITÉ AU CLIC (comparateur D-C, jamais plus dur que 017) :
  -- seul l'ADULTE CERTAIN (diff > seuil) est refusé — la frontière passe, la
  -- façade du service tranche au jour près. Verdict propre : l'usager adulte
  -- relève de l'ouverture de droit sur personne connue, pas de ce chemin.
  IF EXTRACT(YEAR FROM now())::int - p_birth_year > emancipation_minimum_age() THEN
    dependent_public_identifier := NULL; invitation_id := NULL;
    verdict := 'OF_AGE'; RETURN NEXT; RETURN;
  END IF;

  -- Idempotence, sérialisée (patron 012) : deux re-clics concurrents de la
  -- même référence ne créent qu'une personne.
  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_program_id::text || '/' || p_ref_hmac_key_id || '/' || p_external_ref_hmac, 52170021)
  );

  SELECT k.person_id INTO existing_person_id FROM program_idempotency_keys k
   WHERE k.program_id = p_program_id
     AND k.hmac_key_id = p_ref_hmac_key_id
     AND k.ref_hmac = p_external_ref_hmac;

  -- L'INVITATION D'ABORD : le seul refus qui doive tout arrêter (plafond par
  -- client) tombe AVANT la moindre naissance — rien à défaire, rien de créé.
  SELECT i.invitation_id, i.verdict INTO inv_id, inv_verdict
    FROM open_program_invitation(p_program_id, p_phone_hmac, p_hmac_key_id,
                                 p_invitation_ttl_seconds,
                                 p_client_cap, p_client_cap_window_seconds,
                                 p_line_cap, p_line_cap_window_seconds) i;

  IF inv_verdict = 'REFUSED_CLIENT_CAP' THEN
    dependent_public_identifier := NULL; invitation_id := NULL;
    verdict := 'REFUSED_CLIENT_CAP'; RETURN NEXT; RETURN;
  END IF;
  IF inv_id IS NULL THEN
    -- UNKNOWN_PROGRAM d'open_program_invitation : impossible ici (programme
    -- verrouillé FOR SHARE plus haut) — refus fermé par principe (P0112 est
    -- la famille « référence absente », le mur ne s'ouvre pas en silence).
    RAISE EXCEPTION 'open_dependent_access : invitation impossible (%) — incohérence de registre', inv_verdict
      USING ERRCODE = 'P0112';
  END IF;

  -- LA NAISSANCE — une seule fois par référence (le rejeu réutilise).
  IF existing_person_id IS NULL THEN
    new_person_id := create_person(p_public_identifier, p_erasure_salt,
                                   p_identity_encrypted, p_enc_key_id, p_birth_year);
    INSERT INTO program_idempotency_keys (program_id, ref_hmac, hmac_key_id, person_id)
    VALUES (p_program_id, p_external_ref_hmac, p_ref_hmac_key_id, new_person_id);
  ELSE
    new_person_id := existing_person_id;
  END IF;

  -- LE DROIT — idempotent, et la matrice de 019 RESPECTÉE sans l'avorter :
  -- si le dernier retrait du couple est SELF (la famille a fermé), le
  -- programme ne rouvre PAS (la garde lèverait P0110) — le choix de la
  -- famille tient, le clic n'y touche pas.
  SELECT * INTO last_grant FROM program_grants g
   WHERE g.person_id = new_person_id AND g.program_id = p_program_id
   ORDER BY g.seq DESC LIMIT 1;

  IF NOT FOUND
     OR (last_grant.status <> 'ACTIVE' AND last_grant.revoke_reason IS DISTINCT FROM 'SELF') THEN
    INSERT INTO program_grants (person_id, program_id, granted_by)
    VALUES (new_person_id, p_program_id, 'PROGRAM');
  END IF;

  -- LA JONCTION : cette invitation rattacherait cette personne. Idempotente.
  -- (Cible par NOM de contrainte : les colonnes nues seraient ambiguës avec
  -- les paramètres OUT de cette fonction.)
  INSERT INTO program_invitation_dependents (invitation_id, dependent_person_id)
  VALUES (inv_id, new_person_id)
  ON CONFLICT ON CONSTRAINT uq_invitation_dependents DO NOTHING;

  SELECT p.public_identifier INTO dependent_public_identifier FROM persons p
   WHERE p.id = new_person_id;
  invitation_id := inv_id;
  verdict := CASE WHEN existing_person_id IS NULL THEN 'OPENED' ELSE 'OPENED_EXISTING' END;
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION open_dependent_access(uuid, text, bytea, text, text, integer, text, text, text, text, integer, integer, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_dependent_access(uuid, text, bytea, text, text, integer, text, text, text, text, integer, integer, integer, integer, integer) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 4) L'ACCEPTATION, étendue : une invitation à ayants droit crée les LIENS
--    (opened_by = 'RESPONSIBLE'), AUCUN droit pour l'acceptant. Une
--    invitation SANS ayants droit garde EXACTEMENT le comportement de 019.
--    Chaque ayant droit reçoit son verdict sur SA ligne de jonction (Q2).
--    (CREATE OR REPLACE : 012/018/019 sont fusionnées — patron 005. Tous les
--    attributs re-déclarés : SECURITY DEFINER, search_path.)
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
  dep program_invitation_dependents%ROWTYPE;
  dep_birth_year smallint;
  dep_outcome invitation_dependent_outcome;
  has_dependents boolean;
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

  SELECT EXISTS (
    SELECT 1 FROM program_invitation_dependents d WHERE d.invitation_id = inv.id
  ) INTO has_dependents;

  IF has_dependents THEN
    -- LE RATTACHEMENT : un lien par ayant droit, verdict posé sur la ligne.
    -- Les sauts sont des façades de survie (le différé P0113 et le mur P0111
    -- avorteraient TOUTE la transaction au commit — y compris les liens
    -- légitimes des autres) ; les murs de 017 restent seuls porteurs.
    FOR dep IN
      SELECT * FROM program_invitation_dependents d
       WHERE d.invitation_id = inv.id
       FOR UPDATE
    LOOP
      IF EXISTS (SELECT 1 FROM person_responsibilities r
                  WHERE r.responsible_person_id = accepting_person_id
                    AND r.dependent_person_id = dep.dependent_person_id
                    AND r.status = 'ACTIVE') THEN
        dep_outcome := 'ALREADY_LINKED';
      ELSIF EXISTS (SELECT 1 FROM accounts a
                     WHERE a.person_id = dep.dependent_person_id
                       AND a.status = 'ACTIVE')
         OR EXISTS (SELECT 1 FROM person_responsibilities r
                     WHERE r.dependent_person_id = dep.dependent_person_id
                       AND r.end_reason = 'EMANCIPATED') THEN
        dep_outcome := 'SKIPPED_AUTONOMOUS';
      ELSE
        SELECT p.birth_year INTO dep_birth_year FROM persons p
         WHERE p.id = dep.dependent_person_id;
        IF dep_birth_year IS NULL
           OR EXTRACT(YEAR FROM now())::int - dep_birth_year > emancipation_minimum_age() THEN
          -- Adulte certain (ou borne absente — théorique : le clic l'exige).
          dep_outcome := 'SKIPPED_OF_AGE';
        ELSE
          INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
          VALUES (accepting_person_id, dep.dependent_person_id, 'RESPONSIBLE');
          dep_outcome := 'LINKED';
        END IF;
      END IF;

      UPDATE program_invitation_dependents
         SET outcome = dep_outcome
       WHERE id = dep.id;
    END LOOP;
    -- AUCUN droit pour l'acceptant : l'invitation-rattachement parle des
    -- ayants droit, pas de lui.
  ELSE
    -- Comportement 019, inchangé : le droit naît pour la personne du compte
    -- qui accepte, matrice d'acteur comprise.
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
  END IF;

  UPDATE program_invitations
     SET status = 'ACCEPTED', accepted_account_id = p_account_id
   WHERE id = inv.id;

  RETURN 'ACCEPTED';
END;
$$;

-- -----------------------------------------------------------------------------
-- Droits : le rôle applicatif LIT la jonction (des UUID techniques — la
-- découverte de l'étape 5 en a besoin), n'y écrit JAMAIS ; le verrou
-- d'idempotence lui est totalement invisible (pas même SELECT).
-- -----------------------------------------------------------------------------
GRANT SELECT ON program_invitation_dependents TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON program_invitation_dependents FROM user_core_app;
REVOKE UPDATE (outcome) ON program_invitation_dependents FROM user_core_app;

REVOKE ALL ON program_idempotency_keys FROM user_core_app;
