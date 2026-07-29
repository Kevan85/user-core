-- =============================================================================
-- 024 — L'IDEMPOTENCE TRAVERSE LA ROTATION DU TROUSSEAU DES RÉFÉRENCES
-- (LOT prod, étape 4d — arbitrage C4).
--
-- LE PIÈGE SOLDÉ : la recherche d'idempotence de 021 ne regardait que SOUS
-- UNE clé (AND k.hmac_key_id = p_ref_hmac_key_id). Après une rotation du
-- trousseau des références, le re-clic d'une requête ancienne n'était plus
-- reconnu — et créait une DEUXIÈME fiche d'enfant. 021 déclarait la
-- conséquence (« l'idempotence ne traverse pas une rotation ») ; déclarer
-- n'est pas traiter.
--
-- L'ARBITRAGE (C4) — la recherche passe sous TOUTES les clés connues :
--   · contrairement au numéro de téléphone, la valeur de la référence est
--     DISPONIBLE EN CLAIR dans le payload /v1 à chaque appel — le service
--     peut donc calculer son empreinte sous chaque clé du trousseau ;
--   · le coût est borné par la taille du trousseau (une poignée de clés,
--     jamais plus — les anciennes se retirent une fois leur fenêtre passée) ;
--   · l'ÉCRITURE et le VERROU restent sous la seule paire ACTIVE : une
--     rotation est un redéploiement (SECRETS.md §1), deux époques de clés ne
--     se chevauchent jamais en vol — tous les appelants concurrents d'une
--     même référence calculent donc le même verrou.
-- La forme non retenue (fenêtre de recouvrement bornée) aurait accepté des
-- fiches d'enfant en double pendant la fenêtre : une conséquence de registre
-- contre un coût de calcul borné — le registre gagne.
--
-- DROP + CREATE (patron 016) : la signature change, l'ancienne forme ne doit
-- plus exister. Le corps est repris de 021 à l'identique hors de la recherche.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

DROP FUNCTION open_dependent_access(uuid, text, bytea, text, text, integer, text, text, text, text, integer, integer, integer, integer, integer);

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
  -- (024) Les empreintes de la MÊME référence sous chaque clé connue du
  -- trousseau — la recherche les couvre toutes, l'écriture reste à l'active.
  p_lookup_ref_hmacs      text[],
  p_lookup_key_ids        text[],
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
  -- Fail-closed sur la forme des tableaux : mêmes longueurs, non vides, et
  -- la paire ACTIVE en fait partie (sinon la ligne écrite aujourd'hui serait
  -- introuvable demain — la dérive exacte que cette migration ferme).
  IF p_lookup_ref_hmacs IS NULL OR p_lookup_key_ids IS NULL
     OR array_length(p_lookup_ref_hmacs, 1) IS NULL
     OR array_length(p_lookup_ref_hmacs, 1) IS DISTINCT FROM array_length(p_lookup_key_ids, 1) THEN
    RAISE EXCEPTION 'open_dependent_access : empreintes de recherche invalides (tableaux parallèles exigés)'
      USING ERRCODE = 'P0111';
  END IF;
  IF NOT (p_external_ref_hmac = ANY(p_lookup_ref_hmacs) AND p_ref_hmac_key_id = ANY(p_lookup_key_ids)) THEN
    RAISE EXCEPTION 'open_dependent_access : la paire active manque aux empreintes de recherche'
      USING ERRCODE = 'P0111';
  END IF;

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
  -- même référence ne créent qu'une personne. Le verrou reste sous la paire
  -- ACTIVE — tous les appelants concurrents la calculent (voir l'en-tête).
  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_program_id::text || '/' || p_ref_hmac_key_id || '/' || p_external_ref_hmac, 52170021)
  );

  -- (024) LA RECHERCHE SOUS TOUTES LES CLÉS CONNUES : un re-clic reconnaît
  -- sa référence même écrite sous une clé antérieure du trousseau.
  SELECT k.person_id INTO existing_person_id FROM program_idempotency_keys k
   WHERE k.program_id = p_program_id
     AND (k.hmac_key_id, k.ref_hmac) IN (
       SELECT unnest(p_lookup_key_ids), unnest(p_lookup_ref_hmacs)
     );

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

REVOKE ALL ON FUNCTION open_dependent_access(uuid, text, bytea, text, text, integer, text, text, text, text, text[], text[], integer, integer, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_dependent_access(uuid, text, bytea, text, text, integer, text, text, text, text, text[], text[], integer, integer, integer, integer, integer) TO user_core_app;
