-- =============================================================================
-- 033 — L'EFFACEMENT COUPE LES DROITS D'ACCÈS (dette E-1, étape 2 sur 2 : LA
-- COUPURE. Le mur est en place depuis 032 ; ce fichier le rend agissant).
--
-- LA DÉCISION (arbitrage produit, 04/08/2026) : à l'effacement, les droits
-- d'accès aux programmes sont révoqués dans le même geste. Motif — le cadre
-- juridique est établi et l'alignement décidé (CDC §10 n°17) : un programme qui
-- demandait « cette personne a-t-elle accès ? » recevait OUI pour une personne
-- qui venait d'exercer un droit légal. Répondre cela n'est pas un détail
-- d'affichage, c'est une réponse FAUSSE.
--
-- 🔴 LE FILTRE « AND status = 'ACTIVE' » EST UN MUR, PAS UNE OPTIMISATION.
-- guard_program_grant_update (023:147-149) fige toute ligne déjà révoquée :
-- « un droit révoqué est figé — réactiver = une NOUVELLE ligne » (P0103). Un
-- UPDATE non filtré lèverait donc sur la PREMIÈRE ligne d'historique, et
-- l'effacement échouerait — non pas dans un cas tordu, mais pour le cas le plus
-- ordinaire qui soit : une personne qui a utilisé le service, a fermé un
-- programme il y a six mois, en garde un autre ouvert. Son seul tort serait
-- d'avoir un passé. Le test porte cette forme exacte (un ACTIF + un RÉVOQUÉ
-- ancien) : sans elle, il passerait avec le défaut.
--
-- POURQUOI ICI, ET POURQUOI L'ORDRE EST INDIFFÉRENT — mesuré, pas supposé. Les
-- DEUX triggers de program_grants lisent bien accounts (guard_insert ET
-- guard_update), mais uniquement dans leur branche 'SELF' (granted_by = 'SELF',
-- revoke_reason = 'SELF' — 023:161-171). Poser ERASED n'en déclenche aucune :
-- la révocation peut donc vivre avant ou après la désactivation du compte
-- (geste 6) sans rien changer. Elle est placée juste après la fermeture des
-- liens, parce que c'est la même famille de geste — fermer ce qui est ouvert.
--
-- ⚠️ NUMÉROTATION : ce geste s'appelle « 1bis » et NON « 2 ». L'en-tête de 028
-- désigne nommément « la désactivation du compte (geste 6 du corps) » comme le
-- point de greffe d'un futur fait de publication. Renuméroter la suite rendrait
-- cette phrase fausse dans un fichier qu'on ne peut plus corriger (checksum
-- enregistré) — une justification périmée qui survivrait à ce qu'elle désigne
-- (§11 ⑤). Le coût d'un « bis » est nul ; celui d'un renvoi faux ne l'est pas.
--
-- ⚠️ CE QUE CETTE COUPURE N'ÉMET PAS, et c'est voulu : rien. Mesuré — ni les
-- deux portes de révocation, ni aucun des quatre triggers de program_grants
-- n'écrit dans outbox ou account_notifications. Une personne effacée ne doit
-- être notifiée de rien, et une ligne d'outbox porterait son person_id.
--
-- CE QUE CETTE MIGRATION NE FAIT PAS — la liste vit au runbook (§4), tenue à
-- jour dans le même commit, mais les deux plus importantes se disent ici :
-- les LIENS DE RESPONSABILITÉ où l'effacé est AYANT DROIT ne sont pas fermés
-- (028 ne touche que le côté responsable, mesuré), et les INVITATIONS de
-- programme en cours ne sont pas annulées. Aucune des deux n'est un oubli :
-- la première n'a pas été tranchée, la seconde ne l'a pas été non plus.
--
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- CREATE OR REPLACE à signature constante (patron 005/018/027) : TOUS les
-- attributs sont re-déclarés — un attribut omis retombe au défaut EN SILENCE.
-- Le corps est celui de 028, à l'identique, plus le seul geste 1bis.
CREATE OR REPLACE FUNCTION erase_person(p_erasure_id uuid)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  er person_erasures%ROWTYPE;
BEGIN
  SELECT * INTO er FROM person_erasures WHERE id = p_erasure_id FOR UPDATE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN'; RETURN NEXT; RETURN;
  END IF;
  IF er.status = 'COMPLETED' THEN
    verdict := 'ALREADY_COMPLETED'; RETURN NEXT; RETURN;
  END IF;
  IF er.status = 'RETRACTED' THEN
    verdict := 'RETRACTED'; RETURN NEXT; RETURN;
  END IF;
  IF now() < er.effective_after THEN
    verdict := 'NOT_DUE'; RETURN NEXT; RETURN;
  END IF;

  -- 1. Les liens où la personne est RESPONSABLE se ferment. P0114 (différé)
  --    tranche au commit si elle est restée dernier responsable.
  UPDATE person_responsibilities
     SET status = 'ENDED', end_reason = 'ERASED'
   WHERE responsible_person_id = er.person_id
     AND status = 'ACTIVE';

  -- 1bis. LES DROITS D'ACCÈS (E-1, 033). Le filtre sur ACTIVE est le mur
  --       contre P0103 (voir l'en-tête) : les lignes déjà révoquées sont
  --       FIGÉES, et les toucher ferait échouer l'effacement d'une personne
  --       dont le seul tort est d'avoir un historique. ERASED est une
  --       étiquette VÉRIDIQUE, pas une protection — le mur est le trigger de
  --       032, qui interroge l'état effacé de la personne (jamais ce motif).
  UPDATE program_grants
     SET status = 'REVOKED', revoke_reason = 'ERASED'
   WHERE person_id = er.person_id
     AND status = 'ACTIVE';

  -- 2. RÉVOQUER d'abord (l'ordre doctrinal, §3.14bis) : les revendications
  --    vivantes meurent avec leur vrai motif.
  UPDATE phone_claims
     SET status = 'REVOKED', revoke_reason = 'ERASED'
   WHERE person_id = er.person_id
     AND status IN ('PENDING', 'ACTIVE');

  -- 3. NEUTRALISER ensuite : les deux colonnes de valeur de ses revendications
  --    (phone_claims, et LUI SEUL). ⚠️ LE TEST DE PRÉSENCE (dump + trousseau
  --    HMAC → « ce numéro était-il là ? ») EST BORNÉ, PAS FERMÉ : la même
  --    empreinte survit, délibérément, dans TROIS registres strictement
  --    append-only laissés intacts — possession_proof_refusals.phone_hmac
  --    (007), program_invitations.phone_hmac (012) et
  --    program_invitation_refusals.phone_hmac (012). Percer un forbid_update
  --    de registre coûterait plus qu'il ne rend ; le résidu est ASSUMÉ et
  --    documenté au runbook (docs/ops/SAUVEGARDES.md — lot effacement,
  --    étape runbooks), qui en hérite. Tirage non déterministe : jamais un
  --    HMAC valide, aucune collision possible.
  UPDATE phone_claims
     SET phone_hmac = 'ERASED:' || gen_random_uuid(),
         phone_encrypted = 'ERASED:' || gen_random_uuid()
   WHERE person_id = er.person_id;

  -- 4. La crypto-destruction : blob à NULL (les dumps FUTURS) ET sel neuf
  --    (les dumps PASSÉS) — aucun des deux seul ne suffit (en-tête).
  --    ⚠️ Le tirage SQL ne contredit PAS la doctrine de 016 (« jamais un
  --    random() qui fabrique des identifiants devinables ») : 016 vise
  --    random(), non cryptographique, et les IDENTIFIANTS PUBLICS.
  --    gen_random_uuid() tire de la source forte de PostgreSQL, et un sel de
  --    remplacement n'a d'autre charge que d'être différent et non devinable
  --    (244 bits d'entropie sur 256 — les 12 bits de version/variante d'UUID
  --    sont fixes). Deux migrations qui semblent se contredire sans se
  --    répondre laisseraient le prochain lecteur choisir sa doctrine au
  --    hasard — d'où cette note.
  UPDATE persons
     SET erasure_salt = decode(
           replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
           'hex'),
         civil_identity_encrypted = NULL,
         enc_key_id = NULL
   WHERE id = er.person_id;

  -- 5. La seule PII nominative en CLAIR (011) : le profil s'éteint.
  UPDATE account_profiles p
     SET display_name = NULL, locale = NULL
    FROM accounts a
   WHERE a.id = p.account_id
     AND a.person_id = er.person_id;

  -- 6. C4 : le compte s'éteint dans la MÊME transaction — la cascade (019)
  --    révoque les sessions, et rien d'autre. (Point de greffe du futur fait
  --    de publication — voir l'en-tête de 028.)
  UPDATE accounts
     SET status = 'DEACTIVATED'
   WHERE person_id = er.person_id
     AND status = 'ACTIVE';

  -- 7. Le dernier geste : l'état que tous les murs et lectures interrogent.
  --    Le guard de 026 re-vérifie l'échéance ET l'absence de revendication
  --    vivante — l'ordre ci-dessus n'est pas une promesse, il est vérifié.
  UPDATE person_erasures SET status = 'COMPLETED' WHERE id = er.id;

  verdict := 'COMPLETED'; RETURN NEXT;
END;
$$;
