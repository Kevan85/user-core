-- =============================================================================
-- 026 — LE RÉGIME D'EFFACEMENT : paramètres, registre, murs (LOT effacement,
-- étape 1). AUCUNE PORTE : rien n'est encore destructible — les portes dans
-- les murs d'immuabilité (014/006) arrivent dans un lot ultérieur, APRÈS que
-- les murs ci-dessous existent (leçon ④ : une porte n'arrive jamais avant son
-- mur).
--
-- LE RÉGIME (CDC §10 n°14, verrouillé par Kevin les 21 et 30/07/2026) :
--   · MINEUR = acte STAFF sur base légale (le système ENREGISTRE l'acte, il
--     ne juge pas sa légalité) ; ADULTE/ÉMANCIPÉ = self-service ;
--   · le demandeur CHOISIT : exécution immédiate (irréversibilité énoncée
--     avant validation — par la façade) ou délai de réflexion ;
--   · le délai (7 jours) et le préavis de notification (48 h) sont des
--     VALEURS de référence, jamais des littéraux dans du code (§3.11) ;
--   · l'effacement d'un DERNIER responsable est refusé tant qu'un remplaçant
--     n'est pas désigné — le MUR est P0114 (017, différé au commit), déjà en
--     base ; ici ne vit que la FAÇADE du verdict propre (SOLE_RESPONSIBLE).
--
-- LES MURS QUI NAISSENT ICI :
--   · person_erasures : registre append-only de l'acte — la trace §3.14, et
--     la référence que TOUT verdict « effacé » interrogera (leçon ⑨ : on
--     interroge la référence, on ne devine pas l'état en trébuchant dessus) ;
--   · le NOM de la fonction EST l'acteur (patron 023) : deux chemins de
--     demande = deux fonctions, aucun paramètre d'acteur ;
--   · LE MUR DE RÉ-IDENTIFICATION (P0116) : une personne dont l'effacement
--     est ACCOMPLI (COMPLETED — et lui seul : pendant la fenêtre de
--     réflexion, l'usage normal continue, sinon la fenêtre voulue par Kevin
--     serait détruite) ne reçoit plus JAMAIS : une identité civile, une
--     revendication de ligne, un nom d'affichage. Sans ce mur, le premier
--     provide() ordinaire re-chiffrerait le nom sous le sel courant et
--     ré-identifierait la personne — aucun attaquant requis (§3.14bis ①).
--
-- PÉRIMÈTRE DU MUR : la RÉ-IDENTIFICATION (écritures de PII), jamais les
-- actes de registre en UUID (liens de responsabilité, droits d'accès) — le
-- devenir des droits d'une personne effacée est un arbitrage produit ouvert.
--
-- ERRCODE : cette migration ajoute P0116 = « personne effacée — toute
-- ré-identification est interdite ».
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) La politique : UNE ligne, écrite par migration, jamais par le service
--    (patron emancipation_policy, 014). 7 jours / 48 h = décisions de Kevin
--    (30/07/2026). Les bornes des CHECK sont une garde de saisie, pas une
--    doctrine.
-- -----------------------------------------------------------------------------
CREATE TABLE erasure_policy (
  singleton               boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  -- Jamais 0 : « pas de fenêtre » se dit IMMEDIATE. Un DELAYED à 0 jour
  -- serait une réflexion promise et jamais donnée — la contradiction est
  -- non représentable, une migration signée ne peut pas l'introduire.
  retraction_days         integer NOT NULL CHECK (retraction_days BETWEEN 1 AND 90),
  notification_lead_hours integer NOT NULL CHECK (notification_lead_hours BETWEEN 1 AND 168),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  -- Le préavis vit DANS la fenêtre : un préavis plus long qu'elle serait dû
  -- avant la demande — une notification qui ment sur la date, sur le seul
  -- sujet où la date est tout.
  CONSTRAINT chk_erasure_policy_lead_within_window
    CHECK (notification_lead_hours <= retraction_days * 24)
);

INSERT INTO erasure_policy (retraction_days, notification_lead_hours) VALUES (7, 48);

GRANT SELECT ON erasure_policy TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON erasure_policy FROM user_core_app;

-- Lectures qui échouent FERMÉ (P0112, patron emancipation_minimum_age — la
-- forme CORRIGÉE de 015 : un singleton absent n'ouvre aucun mur en silence).
CREATE FUNCTION erasure_retraction_days() RETURNS integer AS $$
DECLARE
  days integer;
BEGIN
  SELECT retraction_days INTO days FROM erasure_policy WHERE singleton;
  IF days IS NULL THEN
    RAISE EXCEPTION 'erasure_policy : table de référence vide — le socle est absent, aucun mur ne doit s''ouvrir'
      USING ERRCODE = 'P0112';
  END IF;
  RETURN days;
END;
$$ LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, public;

CREATE FUNCTION erasure_notification_lead_hours() RETURNS integer AS $$
DECLARE
  hours integer;
BEGIN
  SELECT notification_lead_hours INTO hours FROM erasure_policy WHERE singleton;
  IF hours IS NULL THEN
    RAISE EXCEPTION 'erasure_policy : table de référence vide — le socle est absent, aucun mur ne doit s''ouvrir'
      USING ERRCODE = 'P0112';
  END IF;
  RETURN hours;
END;
$$ LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 2) Le registre de l'acte. Append-only au sens de la maison (007) : contenu
--    immuable, transitions de statut contrôlées, horodatages posés par la
--    base, zéro DELETE. Le rôle applicatif n'a AUCUN droit d'écriture — tout
--    entre par les fonctions d'acteur.
-- -----------------------------------------------------------------------------
CREATE TYPE erasure_mode AS ENUM (
  'IMMEDIATE',  -- « ma décision s'applique tout de suite » — irréversibilité énoncée avant validation
  'DELAYED'     -- délai de réflexion (erasure_policy.retraction_days)
);

CREATE TYPE erasure_status AS ENUM (
  'REQUESTED',  -- demande enregistrée ; pendant la fenêtre, l'usage normal continue
  'COMPLETED',  -- crypto-destruction ACCOMPLIE — l'état que les murs et les lectures interrogent
  'RETRACTED'   -- rétractation dans la fenêtre ; une nouvelle demande reste possible
);

CREATE TABLE person_erasures (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Ordre monotone, indépendant de l'horloge et du hasard (patron 008).
  seq             bigint GENERATED ALWAYS AS IDENTITY,
  person_id       uuid NOT NULL REFERENCES persons(id),
  mode            erasure_mode NOT NULL,
  status          erasure_status NOT NULL DEFAULT 'REQUESTED',
  requested_at    timestamptz NOT NULL DEFAULT now(),
  -- Calculée EN BASE à l'insertion (jamais fournie par un client) : l'instant
  -- à partir duquel l'exécution est due et la rétractation close.
  effective_after timestamptz NOT NULL,
  -- Set-once, posé par la base au dépôt de la notification de préavis : c'est
  -- lui qui rend le dépôt IDEMPOTENT — l'outbox n'est pas un broker (§3.12),
  -- la déduplication ne peut pas y vivre.
  notified_at     timestamptz,
  completed_at    timestamptz,
  retracted_at    timestamptz,
  CONSTRAINT chk_person_erasures_completed_pair
    CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
  CONSTRAINT chk_person_erasures_retracted_pair
    CHECK ((status = 'RETRACTED') = (retracted_at IS NOT NULL)),
  CONSTRAINT chk_person_erasures_chronology
    CHECK (effective_after >= requested_at)
);

-- Au plus UNE demande en cours par personne — l'unicité est le mur, le
-- verdict ALREADY_REQUESTED des fonctions n'est que la façade.
CREATE UNIQUE INDEX uq_person_erasures_in_flight
  ON person_erasures (person_id) WHERE status = 'REQUESTED';

CREATE INDEX idx_person_erasures_person ON person_erasures (person_id);
-- Le balayage des échéances (préavis, exécution) par le worker.
CREATE INDEX idx_person_erasures_due
  ON person_erasures (effective_after) WHERE status = 'REQUESTED';

-- L'état que tout mur et toute lecture interrogent (leçon ⑨). SECURITY
-- DEFINER : le verdict ne dépend pas des droits de l'appelant.
CREATE FUNCTION person_is_erased(p_person_id uuid) RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM person_erasures
     WHERE person_id = p_person_id AND status = 'COMPLETED'
  );
END;
$$ LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public;

-- Une personne effacée ne reçoit plus de demande : il n'y a plus rien à
-- effacer, et un deuxième verdict brouillerait la seule date qui compte
-- (COMPLETED + R). Mur d'insertion, pas une politesse de fonction.
CREATE FUNCTION guard_person_erasure_insert() RETURNS trigger AS $$
BEGIN
  IF person_is_erased(NEW.person_id) THEN
    RAISE EXCEPTION 'person_erasures : personne déjà effacée — rien de plus ne peut lui arriver (P0116)'
      USING ERRCODE = 'P0116';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_person_erasures_guard_insert
  BEFORE INSERT ON person_erasures
  FOR EACH ROW EXECUTE FUNCTION guard_person_erasure_insert();

-- Contenu immuable, transitions contrôlées, horodatages posés par la base
-- (patron possession_proofs, 007).
CREATE FUNCTION guard_person_erasure_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.seq IS DISTINCT FROM OLD.seq
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.mode IS DISTINCT FROM OLD.mode
     OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
     OR NEW.effective_after IS DISTINCT FROM OLD.effective_after THEN
    RAISE EXCEPTION 'person_erasures : contenu immuable — une demande ne se réécrit pas, on en ouvre une autre'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status <> 'REQUESTED' THEN
    RAISE EXCEPTION 'person_erasures : une demande close est figée (%)', OLD.status
      USING ERRCODE = 'P0103';
  END IF;

  -- notified_at : set-once, posé par la base — jamais par un client.
  IF NEW.notified_at IS DISTINCT FROM OLD.notified_at THEN
    IF OLD.notified_at IS NOT NULL THEN
      RAISE EXCEPTION 'person_erasures : notified_at est set-once — le préavis ne se re-signale pas'
        USING ERRCODE = 'P0104';
    END IF;
    NEW.notified_at := now();
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'RETRACTED' THEN
      -- LE MUR de la fenêtre : passée l'échéance, la décision appartient à
      -- l'exécution — une rétractation tardive n'existe pas, quel que soit
      -- le chemin qui l'écrit.
      IF now() >= OLD.effective_after THEN
        RAISE EXCEPTION 'person_erasures : fenêtre de rétractation close — l''exécution est due'
          USING ERRCODE = 'P0102';
      END IF;
      NEW.retracted_at := now();
    ELSIF NEW.status = 'COMPLETED' THEN
      -- Le miroir du mur de rétractation : avant l'échéance, la décision
      -- appartient encore à la personne — une exécution pressée (un worker
      -- bogué, un script, la v2) ne détruit pas la fenêtre de réflexion.
      IF now() < OLD.effective_after THEN
        RAISE EXCEPTION 'person_erasures : exécution avant l''échéance — la fenêtre de réflexion court encore'
          USING ERRCODE = 'P0102';
      END IF;
      -- L'ordre doctrinal (révoquer PUIS neutraliser PUIS achever) cesse
      -- d'être une promesse du corps d'erase_person() : COMPLETED avec une
      -- revendication vivante est NON REPRÉSENTABLE. Sans ce mur, cet état
      -- ferait avorter une rotation d'empreinte entière sur un message
      -- « intégrité en défaut » — qui serait FAUX. PENDING compte : une
      -- vérification en vol pourrait encore l'activer (le mur 026 ne couvre
      -- que l'INSERT).
      IF EXISTS (SELECT 1 FROM phone_claims c
                  WHERE c.person_id = OLD.person_id
                    AND c.status IN ('PENDING', 'ACTIVE')) THEN
        RAISE EXCEPTION 'person_erasures : une revendication vivante subsiste — révoquer d''abord, achever ensuite'
          USING ERRCODE = 'P0102';
      END IF;
      NEW.completed_at := now();
    END IF;
  ELSE
    IF NEW.completed_at IS DISTINCT FROM OLD.completed_at
       OR NEW.retracted_at IS DISTINCT FROM OLD.retracted_at THEN
      RAISE EXCEPTION 'person_erasures : les horodatages de registre sont posés par la base'
        USING ERRCODE = 'P0104';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_person_erasures_guard_update
  BEFORE UPDATE ON person_erasures
  FOR EACH ROW EXECUTE FUNCTION guard_person_erasure_update();

CREATE TRIGGER trg_person_erasures_no_delete
  BEFORE DELETE ON person_erasures
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

GRANT SELECT ON person_erasures TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON person_erasures FROM user_core_app;

-- -----------------------------------------------------------------------------
-- 3) LE MUR DE RÉ-IDENTIFICATION (P0116) — condition : COMPLETED, et lui seul.
--    Pendant la fenêtre de réflexion, provide(), la déclaration de ligne et
--    le profil fonctionnent : tout ce qui s'écrit sera détruit à l'exécution,
--    et un mur qui mordrait dès REQUESTED détruirait la fenêtre elle-même
--    (la rétractation exige un compte utilisable).
--    L'exécution (lot ultérieur) écrit sous REQUESTED puis marque COMPLETED
--    en dernier, dans la même transaction : ces murs ne la gênent pas.
-- -----------------------------------------------------------------------------
CREATE FUNCTION wall_erased_person_identity() RETURNS trigger AS $$
BEGIN
  IF (NEW.civil_identity_encrypted IS DISTINCT FROM OLD.civil_identity_encrypted
      OR NEW.enc_key_id IS DISTINCT FROM OLD.enc_key_id
      OR NEW.birth_year IS DISTINCT FROM OLD.birth_year)
     AND person_is_erased(OLD.id) THEN
    RAISE EXCEPTION 'persons : personne effacée — toute ré-identification est interdite (P0116)'
      USING ERRCODE = 'P0116';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_persons_erasure_wall
  BEFORE UPDATE ON persons
  FOR EACH ROW EXECUTE FUNCTION wall_erased_person_identity();

-- Une effacée ne re-déclare pas de ligne : une revendication neuve porterait
-- une empreinte et une valeur chiffrée neuves — une ré-identification par le
-- téléphone.
CREATE FUNCTION wall_erased_person_claim() RETURNS trigger AS $$
BEGIN
  IF person_is_erased(NEW.person_id) THEN
    RAISE EXCEPTION 'phone_claims : personne effacée — aucune revendication neuve (P0116)'
      USING ERRCODE = 'P0116';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_phone_claims_erasure_wall
  BEFORE INSERT ON phone_claims
  FOR EACH ROW EXECUTE FUNCTION wall_erased_person_claim();

-- Le nom d'affichage est la seule PII nominative en CLAIR du dépôt (011) :
-- après effacement, ni renaissance ni retouche du profil des comptes de la
-- personne.
CREATE FUNCTION wall_erased_person_profile() RETURNS trigger AS $$
DECLARE
  v_person_id uuid;
BEGIN
  SELECT a.person_id INTO v_person_id FROM accounts a WHERE a.id = NEW.account_id;
  IF v_person_id IS NOT NULL AND person_is_erased(v_person_id) THEN
    RAISE EXCEPTION 'account_profiles : personne effacée — le profil ne se réécrit pas (P0116)'
      USING ERRCODE = 'P0116';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_account_profiles_erasure_wall
  BEFORE INSERT OR UPDATE ON account_profiles
  FOR EACH ROW EXECUTE FUNCTION wall_erased_person_profile();

-- -----------------------------------------------------------------------------
-- 4) La FAÇADE du refus « dernier responsable » (C2). LE MUR est P0114 (017,
--    différé au commit) : si l'exécution clôt le dernier lien actif d'un
--    mineur sans compte actif, le COMMIT tombe — job, script, v2 compris.
--    Mais un mur différé qui tombe au jour J, dans une boucle de worker, est
--    une panne silencieuse et répétée : le refus se rend AU MOMENT DE LA
--    DEMANDE, en verdict propre. La façade rend l'erreur propre ; elle ne
--    protège pas l'invariant (§3.1).
-- -----------------------------------------------------------------------------
CREATE FUNCTION person_is_sole_responsible(p_person_id uuid) RETURNS boolean AS $$
BEGIN
  -- Le même prédicat que P0114 (assert_dependent_not_orphaned, 017), lu à la
  -- demande : un ayant droit dont p_person_id porte le SEUL lien actif, et
  -- qui n'a pas de compte actif pour agir seul.
  RETURN EXISTS (
    SELECT 1 FROM person_responsibilities r
     WHERE r.responsible_person_id = p_person_id
       AND r.status = 'ACTIVE'
       AND NOT EXISTS (
         SELECT 1 FROM person_responsibilities o
          WHERE o.dependent_person_id = r.dependent_person_id
            AND o.status = 'ACTIVE'
            AND o.id <> r.id
       )
       AND NOT EXISTS (
         SELECT 1 FROM accounts a
          WHERE a.person_id = r.dependent_person_id
            AND a.status = 'ACTIVE'
       )
  );
END;
$$ LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 5) LES DEUX CHEMINS DE DEMANDE — le NOM de la fonction EST l'acteur (023) :
--    aucun paramètre d'acteur, aucun moyen de se faire passer pour l'autre.
-- -----------------------------------------------------------------------------

-- L'ADULTE / ÉMANCIPÉ, sur SA personne. Un compte ACTIF est exigé : par
-- P0113, son détenteur n'est l'ayant droit actif de personne — c'est bien un
-- majeur qui agit seul.
CREATE FUNCTION request_erasure_self(p_account_id uuid, p_mode erasure_mode)
RETURNS TABLE (verdict text, erasure_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  acting accounts%ROWTYPE;
  existing person_erasures%ROWTYPE;
  new_id uuid;
BEGIN
  SELECT * INTO acting FROM accounts WHERE id = p_account_id FOR SHARE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;
  IF acting.status <> 'ACTIVE' THEN
    verdict := 'ACCOUNT_NOT_ACTIVE'; RETURN NEXT; RETURN;
  END IF;

  -- Façades des murs (l'index partiel et le trigger d'insertion tiennent le
  -- vrai refus) : verdicts propres, idempotents pour le rejeu du clic.
  IF person_is_erased(acting.person_id) THEN
    verdict := 'ALREADY_ERASED'; RETURN NEXT; RETURN;
  END IF;
  SELECT * INTO existing FROM person_erasures
   WHERE person_id = acting.person_id AND status = 'REQUESTED';
  IF FOUND THEN
    verdict := 'ALREADY_REQUESTED'; erasure_id := existing.id; RETURN NEXT; RETURN;
  END IF;

  -- C2 — le refus du dernier responsable tombe ICI, à la demande. Le mur
  -- reste P0114, au commit de l'exécution.
  IF person_is_sole_responsible(acting.person_id) THEN
    verdict := 'SOLE_RESPONSIBLE'; RETURN NEXT; RETURN;
  END IF;

  INSERT INTO person_erasures (person_id, mode, effective_after)
  VALUES (acting.person_id, p_mode,
          CASE p_mode
            WHEN 'IMMEDIATE' THEN now()
            ELSE now() + erasure_retraction_days() * interval '1 day'
          END)
  RETURNING id INTO new_id;

  verdict := 'REQUESTED'; erasure_id := new_id; RETURN NEXT;
END;
$$;

-- LE STAFF, pour une personne SANS compte actif (le mineur en premier lieu).
-- Le contrôle de rôle vit ICI, en base (patron grant_program_staff, 023). Le
-- système ENREGISTRE l'acte sur base légale ; il ne juge pas la légalité.
-- IMMEDIATE est le SEUL mode de ce chemin (G1) : par construction, la
-- personne visée n'a aucun compte actif — un DELAYED ne pourrait être NI
-- annoncé (le préavis mourrait en NO_ACCOUNT puis OUTBOX MORTE, salissant le
-- canal d'alerte) NI rétracté (la rétractation est self, compte ACTIF exigé).
-- Un délai qui ne peut être ni annoncé ni rétracté n'est pas une fenêtre de
-- réflexion : c'est une attente. Refus par verdict propre, pas par doc.
CREATE FUNCTION request_erasure_staff(
  p_actor_account_id uuid,
  p_person_id        uuid,
  p_mode             erasure_mode DEFAULT 'IMMEDIATE'
) RETURNS TABLE (verdict text, erasure_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor accounts%ROWTYPE;
  existing person_erasures%ROWTYPE;
  new_id uuid;
BEGIN
  SELECT * INTO actor FROM accounts WHERE id = p_actor_account_id FOR SHARE;
  IF NOT FOUND
     OR actor.status <> 'ACTIVE'
     OR actor.role NOT IN ('PLATFORM_STAFF', 'PLATFORM_ADMIN') THEN
    verdict := 'FORBIDDEN'; RETURN NEXT; RETURN;
  END IF;

  -- G1 : le chemin staff ne connaît pas le délai (voir l'en-tête).
  IF p_mode = 'DELAYED' THEN
    verdict := 'DELAYED_NOT_APPLICABLE'; RETURN NEXT; RETURN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM persons WHERE id = p_person_id) THEN
    verdict := 'UNKNOWN_PERSON'; RETURN NEXT; RETURN;
  END IF;

  -- Une personne qui peut agir seule s'efface elle-même : le chemin staff ne
  -- double jamais le self-service (deux acteurs, deux fonctions — jamais un
  -- guichet qui parle au nom d'un majeur capable).
  IF EXISTS (SELECT 1 FROM accounts a
              WHERE a.person_id = p_person_id AND a.status = 'ACTIVE') THEN
    verdict := 'HAS_ACTIVE_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;

  IF person_is_erased(p_person_id) THEN
    verdict := 'ALREADY_ERASED'; RETURN NEXT; RETURN;
  END IF;
  SELECT * INTO existing FROM person_erasures
   WHERE person_id = p_person_id AND status = 'REQUESTED';
  IF FOUND THEN
    verdict := 'ALREADY_REQUESTED'; erasure_id := existing.id; RETURN NEXT; RETURN;
  END IF;

  -- C2, généralisé : le même refus propre sur le chemin staff (un adulte au
  -- compte désactivé peut être dernier responsable — décision D-D, 017).
  IF person_is_sole_responsible(p_person_id) THEN
    verdict := 'SOLE_RESPONSIBLE'; RETURN NEXT; RETURN;
  END IF;

  INSERT INTO person_erasures (person_id, mode, effective_after)
  VALUES (p_person_id, p_mode,
          CASE p_mode
            WHEN 'IMMEDIATE' THEN now()
            ELSE now() + erasure_retraction_days() * interval '1 day'
          END)
  RETURNING id INTO new_id;

  verdict := 'REQUESTED'; erasure_id := new_id; RETURN NEXT;
END;
$$;

-- LA RÉTRACTATION — self uniquement : elle défait une décision de la
-- personne, elle n'appartient qu'à elle. Le mur de la fenêtre vit dans le
-- trigger (P0102) ; ici, le verdict propre.
CREATE FUNCTION retract_erasure_self(p_account_id uuid)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  acting accounts%ROWTYPE;
  pending person_erasures%ROWTYPE;
BEGIN
  SELECT * INTO acting FROM accounts WHERE id = p_account_id FOR SHARE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;
  IF acting.status <> 'ACTIVE' THEN
    verdict := 'ACCOUNT_NOT_ACTIVE'; RETURN NEXT; RETURN;
  END IF;

  SELECT * INTO pending FROM person_erasures
   WHERE person_id = acting.person_id AND status = 'REQUESTED'
   FOR UPDATE;
  IF NOT FOUND THEN
    verdict := 'NOTHING_TO_RETRACT'; RETURN NEXT; RETURN;
  END IF;
  IF now() >= pending.effective_after THEN
    verdict := 'WINDOW_CLOSED'; RETURN NEXT; RETURN;
  END IF;

  UPDATE person_erasures SET status = 'RETRACTED' WHERE id = pending.id;
  verdict := 'RETRACTED'; RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION erasure_retraction_days() FROM PUBLIC;
REVOKE ALL ON FUNCTION erasure_notification_lead_hours() FROM PUBLIC;
REVOKE ALL ON FUNCTION person_is_erased(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION person_is_sole_responsible(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION request_erasure_self(uuid, erasure_mode) FROM PUBLIC;
REVOKE ALL ON FUNCTION request_erasure_staff(uuid, uuid, erasure_mode) FROM PUBLIC;
REVOKE ALL ON FUNCTION retract_erasure_self(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erasure_retraction_days() TO user_core_app;
GRANT EXECUTE ON FUNCTION erasure_notification_lead_hours() TO user_core_app;
GRANT EXECUTE ON FUNCTION person_is_erased(uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION request_erasure_self(uuid, erasure_mode) TO user_core_app;
GRANT EXECUTE ON FUNCTION request_erasure_staff(uuid, uuid, erasure_mode) TO user_core_app;
GRANT EXECUTE ON FUNCTION retract_erasure_self(uuid) TO user_core_app;
