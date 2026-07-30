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
