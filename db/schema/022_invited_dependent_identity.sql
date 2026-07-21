-- =============================================================================
-- 022 — La lecture de l'identité d'un ayant droit INVITÉ (lot /v1, étape 5).
--
-- LE POINT LE PLUS SENSIBLE DU LOT : le nom d'un mineur s'affiche au
-- responsable pressenti — et, dans la fenêtre TTL, à un éventuel détenteur
-- recyclé de la ligne (résidu déclaré en 021). La divulgation minimale est
-- donc UN MUR, pas une politesse de service :
--
-- LE PATRON DU VERDICT : le rôle applicatif n'a AUCUN accès direct au blob
-- d'identité (hors SELECT depuis 014). Cette fonction SECURITY DEFINER rend
-- les colonnes chiffrées SEULEMENT si les QUATRE conditions sont réunies —
--   1. invitation PENDING (jamais une close),
--   2. non supprimée (une invitation silencieuse n'existe pas),
--   3. non expirée (la fenêtre TTL de 021 borne l'exposition du nom),
--   4. ligne PROUVÉE de l'appelant = ligne de l'invitation (BOLA en base),
-- + le compte appelant est ACTIF. Sinon : ZÉRO ligne, sans distinction —
-- il n'y a pas de WHERE que le service pourrait oublier, il n'y a pas de
-- WHERE à écrire.
--
-- CE QUE LA BASE NE PEUT PAS FAIRE, ET QUI RESTE AU SERVICE : extraire le
-- nom d'affichage SEUL. Le blob est chiffré (délibéré, la base n'a pas les
-- clés) — le service déchiffre par le point unique (person-identity, motif
-- F) et n'expose QUE displayName : jamais les composantes, jamais la date.
-- Un test le prouve en comptant les champs de la réponse.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE FUNCTION read_invited_dependent_identities(
  p_invitation_id uuid,
  p_account_id    uuid
) RETURNS TABLE (
  dependent_person_id      uuid,
  civil_identity_encrypted text,
  erasure_salt             bytea,
  birth_year               smallint
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
    SELECT d.dependent_person_id, p.civil_identity_encrypted, p.erasure_salt, p.birth_year
      FROM program_invitation_dependents d
      JOIN persons p ON p.id = d.dependent_person_id
     WHERE d.invitation_id = inv.id
     ORDER BY d.created_at;
END;
$$;

REVOKE ALL ON FUNCTION read_invited_dependent_identities(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION read_invited_dependent_identities(uuid, uuid) TO user_core_app;
