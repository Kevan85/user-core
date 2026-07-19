-- =============================================================================
-- 020 — L'ÉMANCIPATION (LOT 5, étape 7 — le sommet du lot ; CDC §2.1.1.3).
--
-- « À l'âge, le jeune PEUT prouver SA ligne et acquérir son compte — même
-- person_id, identité stable, coupure NETTE. » C'est un ACTE, jamais un
-- basculement automatique. Tout ce qui compte existe déjà :
--   · la preuve de ligne est le LOT 2, inchangé (claims sur la personne, 018) ;
--   · la coupure est l'invariant E (017, différé) : le compte et les liens
--     actifs ne peuvent pas coexister au commit — la clôture est FORCÉE dans
--     la même transaction, par la base, pas par ce fichier ;
--   · l'irréversibilité est le mur C11 : end_reason = 'EMANCIPATED', posé
--     ici, ARME le refus définitif de tout rattachement futur ;
--   · le mur d'âge lit emancipation_minimum_age() (fail-closed, P0112) avec
--     le comparateur >= (D-C : l'âge réel est dans [diff-1, diff] — refuser
--     diff >= seuil refuserait de vrais jeunes majeurs ; le mur n'est JAMAIS
--     plus dur que la règle, symétrique du mur de minorité de 017) ;
--   · la preuve doit être FRAÎCHE (C14) : une revendication ACTIVE ancienne
--     ne suffit pas — le mur lit emancipation_proof_max_age() (fail-closed,
--     P0112) et settled_at, posé par la base, non falsifiable.
--
-- UNE PORTE DE NAISSANCE (leçon C9, appliquée d'avance) : le couple
-- compte + premier secret naît dans attach_account_to_person() — SANS
-- GRANT au rôle applicatif — et create_account() comme
-- complete_emancipation() passent par elle. Le jour où la naissance d'un
-- compte gagne une ligne, tous les chemins l'auront.
--
-- SANS ORACLE (patron 012) : les fonctions rendent des verdicts RICHES
-- (support), le service rend une réponse UNIFORME — l'existence d'une
-- personne ne se sonde pas depuis un endpoint public.
--
-- Les ex-responsables sont prévenus DANS LEUR COMPTE (outbox → personne,
-- politique '{}' + in_account : aucun canal externe — le patron du
-- recyclage, 009).
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) LA porte de naissance d'un couple compte + secret. Pas de GRANT : seul
--    le code signé des migrations (create_account, complete_emancipation)
--    l'appelle. Les gardes de 002/003/016 s'appliquent à l'intérieur.
-- -----------------------------------------------------------------------------
CREATE FUNCTION attach_account_to_person(
  p_person_id         uuid,
  p_public_identifier text,
  p_role              account_role,
  p_secret_hash       text,
  p_is_temporary      boolean,
  p_expires_at        timestamptz
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  new_account_id uuid;
BEGIN
  INSERT INTO accounts (public_identifier, role, person_id)
  VALUES (p_public_identifier, p_role, p_person_id)
  RETURNING id INTO new_account_id;

  INSERT INTO account_secrets (account_id, secret_hash, is_temporary, expires_at)
  VALUES (new_account_id, p_secret_hash, p_is_temporary, p_expires_at);

  RETURN new_account_id;
END;
$$;

REVOKE ALL ON FUNCTION attach_account_to_person(uuid, text, account_role, text, boolean, timestamptz)
  FROM PUBLIC;

-- create_account() passe par la porte (comportement identique, signature
-- identique — CREATE OR REPLACE, patron 005 ; 016 n'est pas rejouée).
CREATE OR REPLACE FUNCTION create_account(
  p_public_identifier        text,
  p_role                     account_role,
  p_secret_hash              text,
  p_is_temporary             boolean,
  p_expires_at               timestamptz,
  p_person_public_identifier text,
  p_person_erasure_salt      bytea
) RETURNS TABLE (account_id uuid, person_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  new_person_id  uuid;
BEGIN
  new_person_id := create_person(p_person_public_identifier, p_person_erasure_salt,
                                 NULL, NULL, NULL);
  account_id := attach_account_to_person(new_person_id, p_public_identifier, p_role,
                                         p_secret_hash, p_is_temporary, p_expires_at);
  person_id := new_person_id;
  RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- 2) OUVRIR une émancipation : le mur d'âge en base, la revendication de la
--    personne SANS compte (le cas que 018 a rendu représentable).
--    Verdicts : OPENED · UNKNOWN · HAS_ACCOUNT · UNDERAGE — le service rend
--    une réponse uniforme, les verdicts valent de l'or au support.
-- -----------------------------------------------------------------------------
CREATE FUNCTION open_emancipation(
  p_person_public_identifier text,
  p_phone_hmac               text,
  p_hmac_key_id              text,
  p_phone_encrypted          text,
  p_enc_key_id               text
) RETURNS TABLE (claim_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  subject persons%ROWTYPE;
  new_claim_id uuid;
BEGIN
  -- FOR UPDATE : sérialise avec un rattachement ou une émancipation
  -- concurrents sur la même personne.
  SELECT * INTO subject FROM persons
   WHERE public_identifier = p_person_public_identifier
   FOR UPDATE;
  IF NOT FOUND THEN
    claim_id := NULL; verdict := 'UNKNOWN'; RETURN NEXT; RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM accounts a
              WHERE a.person_id = subject.id AND a.status = 'ACTIVE') THEN
    claim_id := NULL; verdict := 'HAS_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;

  -- LE MUR D'ÂGE (piège n°2) : l'âge se vérifie EN BASE. Comparateur >= —
  -- jamais plus dur (D-C) ; le seuil échoue FERMÉ (P0112), aucun NULL.
  IF subject.birth_year IS NULL
     OR EXTRACT(YEAR FROM now())::int - subject.birth_year < emancipation_minimum_age() THEN
    claim_id := NULL; verdict := 'UNDERAGE'; RETURN NEXT; RETURN;
  END IF;

  -- Une seule revendication vivante par personne (Q3) : la PENDING
  -- précédente tombe, comme dans toute déclaration.
  UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'REPLACED'
   WHERE person_id = subject.id AND status = 'PENDING';

  INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
  VALUES (subject.id, p_phone_hmac, p_hmac_key_id, p_phone_encrypted, p_enc_key_id)
  RETURNING id INTO new_claim_id;

  claim_id := new_claim_id; verdict := 'OPENED';
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION open_emancipation(text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_emancipation(text, text, text, text, text) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 3) ACHEVER une émancipation : le compte naît (MÊME person_id) et TOUS les
--    liens actifs se closent EMANCIPATED — une transaction. L'invariant E
--    (différé) valide la coupure au commit ; le mur C11 devient définitif.
--    Verdicts : EMANCIPATED · UNKNOWN · HAS_ACCOUNT · UNDERAGE ·
--    LINE_NOT_PROVEN · PROOF_STALE.
-- -----------------------------------------------------------------------------
CREATE FUNCTION complete_emancipation(
  p_person_id                 uuid,
  p_account_public_identifier text,
  p_secret_hash               text
) RETURNS TABLE (account_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  subject persons%ROWTYPE;
  link RECORD;
  new_account_id uuid;
BEGIN
  SELECT * INTO subject FROM persons WHERE id = p_person_id FOR UPDATE;
  IF NOT FOUND THEN
    account_id := NULL; verdict := 'UNKNOWN'; RETURN NEXT; RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM accounts a
              WHERE a.person_id = subject.id AND a.status = 'ACTIVE') THEN
    account_id := NULL; verdict := 'HAS_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;

  -- Le mur d'âge, RE-vérifié à l'acte (l'ouverture peut dater d'hier soir,
  -- la politique peut avoir changé entre-temps).
  IF subject.birth_year IS NULL
     OR EXTRACT(YEAR FROM now())::int - subject.birth_year < emancipation_minimum_age() THEN
    account_id := NULL; verdict := 'UNDERAGE'; RETURN NEXT; RETURN;
  END IF;

  -- « Le jeune prouve SA ligne » : une revendication ACTIVE (donc PROUVÉE —
  -- le CHECK de 006 rend « active non prouvée » non représentable).
  IF NOT EXISTS (SELECT 1 FROM phone_claims c
                  WHERE c.person_id = subject.id AND c.status = 'ACTIVE') THEN
    account_id := NULL; verdict := 'LINE_NOT_PROVEN'; RETURN NEXT; RETURN;
  END IF;

  -- C14 — LA FRAÎCHEUR AU MÊME ÉTAGE QUE LE MUR (§3.1, « la v2 de cet
  -- endpoint ») : le service exige déjà un code frais, mais un service se
  -- réécrit. Sans ce mur, une revendication prouvée il y a six mois suffirait
  -- à un appel direct pour poser SON secret sur la personne d'autrui — la
  -- prise de compte fermée au service, survivant un étage plus bas.
  -- settled_at est posé par la BASE à la clôture (007), jamais par le client :
  -- l'horodatage ne se fournit ni ne se rejoue. Dans le flux légitime, la
  -- vérification du code et cet acte partagent la même horloge — celle de la
  -- base — à quelques secondes d'intervalle : la fenêtre (politique
  -- paramétrable, lecture fail-closed P0112) ne mord jamais sur le légitime.
  IF NOT EXISTS (
    SELECT 1 FROM phone_claims c
      JOIN possession_proofs p ON p.claim_id = c.id
     WHERE c.person_id = subject.id
       AND c.status = 'ACTIVE'
       AND p.status = 'SUCCEEDED'
       AND p.settled_at > now() - make_interval(secs => emancipation_proof_max_age())
  ) THEN
    account_id := NULL; verdict := 'PROOF_STALE'; RETURN NEXT; RETURN;
  END IF;

  -- Le compte naît par LA porte — même person_id, identité stable.
  new_account_id := attach_account_to_person(subject.id, p_account_public_identifier,
                                             'ACCOUNT_HOLDER', p_secret_hash, false, NULL);

  -- LA COUPURE NETTE, dans la même transaction : chaque lien actif se clôt
  -- EMANCIPATED (ce qui ARME l'irréversibilité C11 pour toujours), et chaque
  -- ex-responsable est prévenu DANS SON COMPTE (outbox → personne, politique
  -- sans canal externe). L'invariant E rend le tout vérifié au commit.
  FOR link IN
    SELECT id, responsible_person_id FROM person_responsibilities
     WHERE dependent_person_id = subject.id AND status = 'ACTIVE'
     FOR UPDATE
  LOOP
    UPDATE person_responsibilities
       SET status = 'ENDED', end_reason = 'EMANCIPATED'
     WHERE id = link.id;

    INSERT INTO outbox (event_type, person_id)
    VALUES ('DEPENDENT_EMANCIPATED', link.responsible_person_id);
  END LOOP;

  account_id := new_account_id; verdict := 'EMANCIPATED';
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION complete_emancipation(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION complete_emancipation(uuid, text, text) TO user_core_app;

-- -----------------------------------------------------------------------------
-- 4) La politique de canal de l'événement : DANS le compte de l'ex-
--    responsable, aucun canal externe (données, pas code — patron 009).
-- -----------------------------------------------------------------------------
INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note) VALUES
  ('DEPENDENT_EMANCIPATED', '{}', true,
   'Une personne dont ce compte était responsable vient d''acquérir son autonomie : le lien est clos, définitivement. Notification déposée dans le compte de l''ex-responsable — aucun canal externe : rien à envoyer sur une ligne, et rien qui presse.');
