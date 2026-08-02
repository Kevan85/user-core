-- =============================================================================
-- 027 — « EFFACÉ » EST UN ÉTAT QUE LA BASE DÉCLARE (LOT effacement, étape 2).
--
-- §3.14bis ② : le dépôt possède deux détecteurs d'intégrité qui rendent
-- bruyant, exprès, tout chiffré qui ne s'ouvre plus (la re-dérivation d'année
-- et la parade P4). Un effacé n'est PAS une corruption : si l'état devait se
-- déduire d'un échec de déchiffrement, ces détecteurs crieraient sur des
-- actes légitimes — et le prochain auteur assouplirait la comparaison pour
-- retrouver le silence (leçon ⑦, transposée d'une garde CI à un détecteur).
-- Donc : les chemins de LECTURE interrogent le registre (leçon ⑨) et rendent
-- l'état, AVANT toute destruction — le mur de lecture précède la porte
-- (leçon ④). À cette étape, aucune personne n'est encore destructible : ces
-- verdicts ne peuvent pas encore mentir en production.
--
-- QUATRE lectures, deux formes :
--   · les deux lectures d'IDENTITÉ déclarent (colonne erased) — le service
--     rend un verdict ERASED distinct d'INTEGRITY_VIOLATION et de
--     NOT_PROVIDED (l'ordre est un test : une effacée au blob NULL n'est
--     PAS « n'a jamais fourni ») ;
--   · les deux lectures d'ADRESSE se taisent (NULL → NO_ADDRESS, avant tout
--     déchiffrement). read_phone_encrypted n'avait AUCUN filtre de statut et
--     alimente les appelants requireActive=false : sans ce silence, une
--     revendication neutralisée ferait crier la parade P4 sur un acte
--     légitime. Il n'y a pas de WHERE que le service pourrait oublier.
--
-- read_person_identity et read_invited_dependent_identities changent de type
-- de retour : DROP puis CREATE (CREATE OR REPLACE ne change pas un RETURNS
-- TABLE), droits reposés à l'identique. Les deux lectures d'adresse gardent
-- leur signature : CREATE OR REPLACE, corps repris à l'identique de 007/009
-- plus la condition d'effacement.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) L'identité de la personne : la base DÉCLARE l'effacement.
-- -----------------------------------------------------------------------------
DROP FUNCTION read_person_identity(uuid);

CREATE FUNCTION read_person_identity(p_person_id uuid)
RETURNS TABLE (civil_identity_encrypted text, enc_key_id text, erasure_salt bytea,
               birth_year smallint, erased boolean)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT p.civil_identity_encrypted, p.enc_key_id, p.erasure_salt, p.birth_year,
         person_is_erased(p.id) AS erased
    FROM persons p
   WHERE p.id = p_person_id;
$$;

REVOKE ALL ON FUNCTION read_person_identity(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION read_person_identity(uuid) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 2) L'identité d'un ayant droit INVITÉ : mêmes quatre conditions que 022,
--    reprises à l'identique — plus la déclaration d'effacement par ligne.
-- -----------------------------------------------------------------------------
DROP FUNCTION read_invited_dependent_identities(uuid, uuid);

CREATE FUNCTION read_invited_dependent_identities(
  p_invitation_id uuid,
  p_account_id    uuid
) RETURNS TABLE (
  dependent_person_id      uuid,
  civil_identity_encrypted text,
  erasure_salt             bytea,
  birth_year               smallint,
  erased                   boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  inv program_invitations%ROWTYPE;
  accepting_person_id uuid;
BEGIN
  SELECT * INTO inv FROM program_invitations WHERE id = p_invitation_id;
  -- Les conditions 1-2-3 : toute défaillance rend la MÊME chose — rien.
  IF NOT FOUND OR inv.suppressed OR inv.status <> 'PENDING' OR inv.expires_at <= now() THEN
    RETURN;
  END IF;

  SELECT a.person_id INTO accepting_person_id FROM accounts a
   WHERE a.id = p_account_id AND a.status = 'ACTIVE';
  IF accepting_person_id IS NULL THEN
    RETURN;
  END IF;

  -- La condition 4 — le BOLA du rattachement sans état (012/018) : seule la
  -- ligne PROUVÉE qui est celle de l'invitation ouvre la lecture.
  IF NOT EXISTS (
    SELECT 1 FROM phone_claims c
     WHERE c.person_id = accepting_person_id
       AND c.hmac_key_id = inv.hmac_key_id
       AND c.phone_hmac = inv.phone_hmac
       AND c.status = 'ACTIVE'
  ) THEN
    RETURN;
  END IF;

  RETURN QUERY
    SELECT d.dependent_person_id, p.civil_identity_encrypted, p.erasure_salt, p.birth_year,
           person_is_erased(p.id) AS erased
      FROM program_invitation_dependents d
      JOIN persons p ON p.id = d.dependent_person_id
     WHERE d.invitation_id = inv.id
     ORDER BY d.created_at;
END;
$$;

REVOKE ALL ON FUNCTION read_invited_dependent_identities(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION read_invited_dependent_identities(uuid, uuid) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 3) Les deux lectures d'ADRESSE se taisent : une personne effacée n'a plus
--    d'adresse, quel que soit le statut de la revendication. Le NULL tombe
--    en NO_ADDRESS AVANT tout déchiffrement (verified-address) : la parade
--    P4 n'est jamais atteinte, le canal d'intégrité reste réservé aux vraies
--    corruptions.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION read_phone_encrypted(p_claim_id uuid) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  token text;
BEGIN
  SELECT phone_encrypted INTO token FROM phone_claims
   WHERE id = p_claim_id
     AND NOT person_is_erased(person_id);
  RETURN token;
END;
$$;

CREATE OR REPLACE FUNCTION resolve_notification_address(p_claim_id uuid) RETURNS text
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
     AND status = 'ACTIVE'   -- une ligne révoquée n'a PLUS d'adresse. Jamais.
     AND NOT person_is_erased(person_id);
  RETURN token;   -- NULL si inactive ou personne effacée : rien à envoyer.
END;
$$;

-- -----------------------------------------------------------------------------
-- 4) R3 — LA LISTE MONTRÉE ET LA LISTE AGIE SONT LA MÊME LISTE. Le service
--    (étape 2) retire un ayant droit effacé de l'affichage ; sans cette
--    section, la boucle d'acceptation de 021 lui créait quand même un lien
--    de responsabilité : le parent devenait responsable d'une personne qu'on
--    ne lui a jamais montrée — et P0114 l'y arrimait durablement. Le saut
--    vit dans la boucle SQL, tracé sur la ligne (outcome), jamais dans un
--    `if` de service. Corps de 021 repris à l'identique, seule la branche
--    SKIPPED_ERASED s'ajoute — EN TÊTE : quel que soit l'état du lien, un
--    effacé ne reçoit AUCUNE écriture de rattachement par ce chemin.
--    (`outcome` n'est l'entrée d'aucun mur — set-once par 021, lu par
--    personne d'autre : la valeur neuve est inerte, critère 023.)
--    NOTE runner : la valeur d'enum s'ajoute dans la transaction de cette
--    migration et n'y est jamais UTILISÉE (les corps plpgsql ne s'évaluent
--    pas à la création) — la contrainte Postgres est respectée.
-- -----------------------------------------------------------------------------
ALTER TYPE invitation_dependent_outcome ADD VALUE 'SKIPPED_ERASED';

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
      IF person_is_erased(dep.dependent_person_id) THEN
        -- R3 : la liste montrée (étape 2) l'a retiré — la liste agie fait
        -- de même, et la trace dit pourquoi au lieu d'un silence.
        dep_outcome := 'SKIPPED_ERASED';
      ELSIF EXISTS (SELECT 1 FROM person_responsibilities r
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
