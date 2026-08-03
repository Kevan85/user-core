-- =============================================================================
-- 030 — LE MUR D'ÉCRITURE DES REVENDICATIONS DE LIGNE (LOT U-sec, étape 1).
--
-- CE QUE CE FICHIER FERME, ET QUI A ÉTÉ MESURÉ (pas supposé) : le rôle
-- applicatif détenait INSERT (person_id, phone_hmac, hmac_key_id,
-- phone_encrypted, enc_key_id) et UPDATE (status, revoke_reason) sur
-- phone_claims (006) — c'est-à-dire le droit d'écrire une revendication de
-- ligne SUR UNE PERSONNE QU'IL DÉSIGNE. Joué sous le rôle bridé, sans owner :
--
--     INSERT phone_claims(person_id = <autrui>, …empreinte de l'appelant…)
--   → open_possession_proof(…)   le code part sur la ligne de L'APPELANT
--   → verify_possession_code(…)  la revendication devient ACTIVE sur autrui
--   → complete_emancipation(…)   compte créé sur la personne d'autrui
--
-- Ce chemin ne passe JAMAIS par open_emancipation : ni son mur d'âge, ni son
-- contrôle HAS_ACCOUNT ne sont joués. Ceux de complete_emancipation, eux, le
-- sont (020:183-193) — mais ils n'arrêtent que la PRISE DE COMPTE. Ils ne
-- protègent pas le REGISTRE.
--
-- ⚠️ LA RAISON PRINCIPALE DE CE MUR N'EST DONC PAS LA PRISE DE COMPTE : c'est
-- que LA REVENDICATION FORGÉE SURVIT AU REFUS. Sur une personne trop jeune,
-- le verdict UNDERAGE ne ferme rien — il DIFFÈRE. Qui détient encore UPDATE
-- révoque sa propre revendication forgée, en repose une, la re-prouve : la
-- fraîcheur exigée par 020:212-218 se recharge à volonté. C'est une prise de
-- compte PRÉ-POSITIONNÉE ET RECHARGEABLE, qui mûrit seule jusqu'au seuil
-- d'âge — l'élargissement « à chaque cohorte » du CDC, mais avec la cible
-- déjà armée.
-- Et elle est SILENCIEUSE pour qui n'a pas de compte : PHONE_LINE_SUPERSEDED
-- porte allowed_channels = '{}' et in_account = true (009) — sa seule voie
-- est le dépôt dans un compte. La politique est juste (elle protège le
-- porteur d'une ligne recyclée) ; c'est la population SANS compte qui n'a
-- aucune voie, et n'apprend donc jamais que sa ligne a changé de main.
--
-- LE PATRON (§8.2, le NOM de la fonction EST l'acteur ; §3.1, l'invariant
-- vit en base) : le service perd le droit d'écrire, UNE porte nommée le lui
-- rend, et LA PERSONNE Y EST DÉRIVÉE DU COMPTE — jamais reçue en argument.
--
-- ⚠️ CE QUE CE FICHIER NE PROUVE PAS, et qu'il ne faut pas lui prêter : la
-- base n'a aucune notion d'« appelant ». Elle ne peut pas établir qu'un jeton
-- signé correspond à p_account_id — ce contrôle-là est du BOLA, il vit au
-- bord de l'API et y reste. Ce mur rend seulement NON REPRÉSENTABLE l'écriture
-- d'une revendication sur une personne QU'AUCUN COMPTE NE PORTE : la cible
-- cesse d'être un paramètre libre pour devenir une conséquence du compte.
--
-- Une seule porte naît ici, et c'est délibéré : PhoneService n'expose aucune
-- révocation (declare · requestProof · verify), et les deux dernières passent
-- déjà par des fonctions SECURITY DEFINER. Une porte de révocation sans
-- appelant serait une flexibilité « au cas où » (§3.9).
--
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- LA porte de déclaration d'une ligne, pour SOI. Forme copiée sur les *_self
-- de 023 (compte en premier argument, verdict rendu, façade du mur d'activité)
-- et relue : le verrou sur la personne est ajouté ici, car cette porte écrit
-- deux fois (révocation puis insertion) là où grant_program_self n'écrit
-- qu'une ligne.
--
-- ISO-COMPORTEMENT avec le chemin qu'elle remplace (phone.service.ts) : seules
-- les revendications PENDING de la personne tombent en REPLACED. Une
-- revendication ACTIVE, elle, n'est PAS touchée — et l'unicité « une seule
-- vivante par personne » (018) refusera alors l'insertion. C'est le
-- comportement d'aujourd'hui, déplacé, pas modifié : changer cette règle
-- serait un autre sujet, et il n'est pas ouvert.
-- -----------------------------------------------------------------------------
CREATE FUNCTION declare_phone_self(
  p_account_id      uuid,
  p_phone_hmac      text,
  p_hmac_key_id     text,
  p_phone_encrypted text,
  p_enc_key_id      text
) RETURNS TABLE (claim_id uuid, verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  acting       accounts%ROWTYPE;
  new_claim_id uuid;
BEGIN
  SELECT * INTO acting FROM accounts WHERE id = p_account_id FOR SHARE;
  IF NOT FOUND THEN
    claim_id := NULL; verdict := 'UNKNOWN_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;

  -- Un acte SELF exige un compte ACTIF (§8.2). Ici la règle n'a pas de trigger
  -- jumeau à couvrir : elle est portée par cette porte, qui est le seul chemin
  -- restant. En pratique un compte désactivé perd déjà ses sessions (018), donc
  -- son jeton — ce verdict est la ceinture, pas la découverte.
  IF acting.status <> 'ACTIVE' THEN
    claim_id := NULL; verdict := 'ACCOUNT_NOT_ACTIVE'; RETURN NEXT; RETURN;
  END IF;

  -- Sérialise avec une déclaration ou une émancipation concurrentes sur la
  -- même personne (patron 020) — et dans le MÊME sens de verrouillage
  -- qu'elles : persons d'abord, phone_claims ensuite. L'unicité de 018
  -- trancherait de toute façon ; ce verrou évite qu'elle se manifeste en
  -- erreur brute sur un chemin en ligne.
  PERFORM 1 FROM persons WHERE id = acting.person_id FOR UPDATE;

  UPDATE phone_claims
     SET status = 'REVOKED', revoke_reason = 'REPLACED'
   WHERE person_id = acting.person_id
     AND status = 'PENDING';

  INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
  VALUES (acting.person_id, p_phone_hmac, p_hmac_key_id, p_phone_encrypted, p_enc_key_id)
  RETURNING id INTO new_claim_id;

  claim_id := new_claim_id; verdict := 'DECLARED';
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION declare_phone_self(uuid, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION declare_phone_self(uuid, text, text, text, text) TO user_core_app;

-- -----------------------------------------------------------------------------
-- LE MUR. Patron 011:67-68 (§8.2) : le retrait se pose à la fois sur la TABLE
-- et sur les COLONNES — un GRANT de colonne survit à un REVOKE de table, et
-- l'inverse n'est pas vrai. Les deux formes, toujours.
--
-- Les fonctions SECURITY DEFINER qui écrivent phone_claims (verify_possession_code,
-- open_emancipation, erase_person, la rotation d'empreinte sous owner) sont
-- indifférentes à ce retrait : elles s'exécutent sous le propriétaire. C'est
-- exactement ce qu'on veut — les chemins signés restent, le droit nu disparaît.
-- -----------------------------------------------------------------------------
REVOKE INSERT, UPDATE ON phone_claims FROM user_core_app;
REVOKE INSERT (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
  ON phone_claims FROM user_core_app;
REVOKE UPDATE (status, revoke_reason) ON phone_claims FROM user_core_app;
