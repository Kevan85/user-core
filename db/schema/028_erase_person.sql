-- =============================================================================
-- 028 — LE GESTE : erase_person() et les portes contrôlées (LOT effacement,
-- étape 3). Les murs sont déjà debout (026 : registre + P0116 ; 027 : les
-- lectures déclarent ou se taisent) — cette migration ouvre les DEUX portes
-- qu'ils encadrent, et le chemin unique qui les emprunte.
--
-- LA CRYPTO-DESTRUCTION, les deux gestes et pourquoi les deux :
--   · le blob passe à NULL — cela retire le chiffré des dumps FUTURS ;
--   · le sel est remplacé par un tirage neuf — cela rend irrécupérable le
--     chiffré des dumps PASSÉS (ils portent l'ancien blob sous l'ancien sel,
--     dont plus rien de vivant ne permettra la re-dérivation après J+R).
--   AUCUN des deux seul ne suffit. La LIGNE et son historique restent (§3.10).
--
-- LES PORTES (CREATE OR REPLACE de guards FUSIONNÉS — patron 023) :
--   · persons : la destruction sel+blob, et elle SEULE, quand un effacement
--     est DÛ (REQUESTED, échéance passée) ;
--   · phone_claims : la neutralisation des deux colonnes de valeur, et elle
--     SEULE, sur une ligne REVOKED, quand un effacement est dû. L'ordre
--     doctrinal (révoquer PUIS neutraliser) est tenu par la porte elle-même,
--     et l'achèvement par le mur de 026 (COMPLETED refuse toute revendication
--     vivante). Hors contexte : P0101/P0103 mordent comme avant — un test le
--     prouve dans les deux sens.
--
-- ENUMS : phone_revoke_reason et responsibility_end_reason gagnent 'ERASED'.
-- Critère 023 vérifié : AUCUN mur ne lit une valeur de phone_revoke_reason
-- (tous les `= '...'` du dépôt sont des écritures) ; les deux seuls murs
-- lecteurs de end_reason (017:133, 021:363 repris en 027) testent
-- 'EMANCIPATED' — 'ERASED' y est inerte. Écrire 'ADMIN' à la place serait
-- une justification fausse dès l'écriture (leçon ⑤).
-- NOTE runner : les valeurs s'ajoutent dans la transaction de cette
-- migration et n'y sont jamais UTILISÉES (les corps plpgsql ne s'évaluent
-- pas à la création) — la contrainte Postgres est respectée.
--
-- P0114 À L'EXÉCUTION : erase_person() clôt les liens où la personne est
-- RESPONSABLE ; si elle est restée dernier responsable (l'état a pu changer
-- entre la demande et l'échéance), le COMMIT tombe — c'est le mur, la façade
-- SOLE_RESPONSIBLE de 026 n'était que le refus propre à la demande. Les
-- liens où elle est AYANT DROIT ne sont pas touchés (des UUID, aucun PII —
-- et les clore percuterait P0114 dans l'autre sens).
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

ALTER TYPE phone_revoke_reason ADD VALUE 'ERASED';
ALTER TYPE responsibility_end_reason ADD VALUE 'ERASED';

-- -----------------------------------------------------------------------------
-- 1) La porte de persons — corps de 014 repris à l'identique, la porte en
--    tête. Toute autre forme de changement du sel retombe sur P0101.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_person_update() RETURNS trigger AS $$
BEGIN
  -- LA PORTE D'EFFACEMENT (028) : la destruction sel+blob, et elle seule,
  -- quand un effacement est dû. Le sel neuf reste un bytea de 32 octets
  -- (CHECK de 014) ; birth_year ne bouge pas (résidu déclaré, 014).
  IF NEW.erasure_salt IS DISTINCT FROM OLD.erasure_salt THEN
    IF NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.public_identifier IS NOT DISTINCT FROM OLD.public_identifier
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.civil_identity_encrypted IS NULL
       AND NEW.enc_key_id IS NULL
       AND NEW.birth_year IS NOT DISTINCT FROM OLD.birth_year
       AND EXISTS (SELECT 1 FROM person_erasures e
                    WHERE e.person_id = OLD.id
                      AND e.status = 'REQUESTED'
                      AND now() >= e.effective_after) THEN
      NEW.updated_at := now();
      RETURN NEW;
    END IF;
    -- toute autre forme retombe sur le mur ci-dessous, inchangé.
  END IF;

  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.public_identifier IS DISTINCT FROM OLD.public_identifier
     OR NEW.erasure_salt IS DISTINCT FROM OLD.erasure_salt
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'persons : identité technique immuable (id, public_identifier, erasure_salt, created_at)'
      USING ERRCODE = 'P0101';
  END IF;

  -- birth_year est SET-ONCE : NULL -> valeur, une seule fois. Ni retouche ni
  -- retour à NULL : la borne d'âge est un registre, pas un champ de formulaire.
  -- Corriger une année erronée n'est pas une transition posée en V1 — si le
  -- besoin arrive, ce sera une migration signée (patron 002, réactivation).
  IF OLD.birth_year IS NOT NULL AND NEW.birth_year IS DISTINCT FROM OLD.birth_year THEN
    RAISE EXCEPTION 'persons : birth_year est posé une fois pour toutes — corriger = migration signée'
      USING ERRCODE = 'P0101';
  END IF;
  IF NEW.birth_year IS NOT NULL
     AND NEW.birth_year > EXTRACT(YEAR FROM now())::int THEN
    RAISE EXCEPTION 'persons : année de naissance dans le futur'
      USING ERRCODE = 'P0111';
  END IF;

  -- La base date chaque retouche elle-même ; toute valeur envoyée est écrasée.
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 2) La porte de phone_claims — corps de 018 repris à l'identique, la porte
--    en tête. La neutralisation ne change QUE les deux colonnes de valeur,
--    sur une ligne REVOKED, sous effacement dû ; les identifiants de clé
--    restent (ils disent sous quelle clé les ANCIENNES valeurs vivaient —
--    les nouvelles ne vivent sous aucune, et aucune lecture ne les sert :
--    027 a rendu les deux chemins sourds AVANT que cette porte n'existe).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_phone_claim_update() RETURNS trigger AS $$
BEGIN
  -- LA PORTE D'EFFACEMENT (028).
  IF (NEW.phone_hmac IS DISTINCT FROM OLD.phone_hmac
      OR NEW.phone_encrypted IS DISTINCT FROM OLD.phone_encrypted)
     AND OLD.status = 'REVOKED'
     AND NEW.id IS NOT DISTINCT FROM OLD.id
     AND NEW.person_id IS NOT DISTINCT FROM OLD.person_id
     AND NEW.hmac_key_id IS NOT DISTINCT FROM OLD.hmac_key_id
     AND NEW.enc_key_id IS NOT DISTINCT FROM OLD.enc_key_id
     AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
     AND NEW.status IS NOT DISTINCT FROM OLD.status
     AND NEW.assurance_level IS NOT DISTINCT FROM OLD.assurance_level
     AND NEW.verified_at IS NOT DISTINCT FROM OLD.verified_at
     AND NEW.revoked_at IS NOT DISTINCT FROM OLD.revoked_at
     AND NEW.revoke_reason IS NOT DISTINCT FROM OLD.revoke_reason
     AND EXISTS (SELECT 1 FROM person_erasures e
                  WHERE e.person_id = OLD.person_id
                    AND e.status = 'REQUESTED'
                    AND now() >= e.effective_after) THEN
    RETURN NEW;
  END IF;
  -- toute autre forme retombe sur les murs ci-dessous, inchangés.

  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.phone_hmac IS DISTINCT FROM OLD.phone_hmac
     OR NEW.hmac_key_id IS DISTINCT FROM OLD.hmac_key_id
     OR NEW.phone_encrypted IS DISTINCT FROM OLD.phone_encrypted
     OR NEW.enc_key_id IS DISTINCT FROM OLD.enc_key_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'phone_claims : contenu immuable — déclarer un autre numéro, révoquer celui-ci'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'phone_claims : une revendication révoquée est figée — elle ne revient jamais'
      USING ERRCODE = 'P0103';
  END IF;

  IF OLD.assurance_level = 'PROVEN' AND NEW.assurance_level = 'DECLARED' THEN
    RAISE EXCEPTION 'phone_claims : le niveau de preuve ne descend jamais (PROVEN -> DECLARED)'
      USING ERRCODE = 'P0102';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'ACTIVE' THEN
      IF NEW.assurance_level <> 'PROVEN' THEN
        RAISE EXCEPTION 'phone_claims : une revendication ne devient ACTIVE que PROUVÉE (SMS ou appel)'
          USING ERRCODE = 'P0102';
      END IF;
      IF NEW.hmac_key_id <> active_hmac_key_id() THEN
        RAISE EXCEPTION 'phone_claims : activation sous une clé d''empreinte périmée'
          USING ERRCODE = 'P0109';
      END IF;
      NEW.verified_at := now();
    ELSIF NEW.status = 'REVOKED' THEN
      IF NEW.revoke_reason IS NULL THEN
        RAISE EXCEPTION 'phone_claims : une révocation porte toujours son motif'
          USING ERRCODE = 'P0102';
      END IF;
      NEW.revoked_at := now();
    ELSE
      RAISE EXCEPTION 'phone_claims : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
  ELSE
    IF NEW.verified_at IS DISTINCT FROM OLD.verified_at
       OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason THEN
      RAISE EXCEPTION 'phone_claims : les horodatages de registre sont posés par la base, jamais réécrits'
        USING ERRCODE = 'P0104';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- 3) erase_person() — LE chemin unique du geste, une transaction, zéro appel
--    réseau (§3.13 : tout est local). L'ACTEUR a été prouvé À LA DEMANDE
--    (026 : le nom de la fonction est l'acteur) ; l'exécution, elle, est
--    neutre — elle n'obéit qu'au registre (demande due, ni rétractée ni déjà
--    accomplie), et chaque écriture passe sous les portes et les murs
--    ci-dessus. Idempotente pour le worker : rejouer rend un verdict, jamais
--    une exception.
--
--    La désactivation du compte (geste 6 du corps) est LE POINT où un fait
--    de publication (disponibilité de la personne pour l'écosystème) viendra
--    se greffer le jour où une surface de publication existera — dans la
--    MÊME transaction, là et nulle part ailleurs.
-- -----------------------------------------------------------------------------
CREATE FUNCTION erase_person(p_erasure_id uuid)
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

  -- 2. RÉVOQUER d'abord (l'ordre doctrinal, §3.14bis) : les revendications
  --    vivantes meurent avec leur vrai motif.
  UPDATE phone_claims
     SET status = 'REVOKED', revoke_reason = 'ERASED'
   WHERE person_id = er.person_id
     AND status IN ('PENDING', 'ACTIVE');

  -- 3. NEUTRALISER ensuite : les deux colonnes de valeur de TOUTES ses
  --    revendications (empreinte déterministe comprise — c'est elle qui
  --    permettrait de tester la présence d'un numéro dans un dump). Tirage
  --    non déterministe : jamais un HMAC valide, aucune collision possible.
  UPDATE phone_claims
     SET phone_hmac = 'ERASED:' || gen_random_uuid(),
         phone_encrypted = 'ERASED:' || gen_random_uuid()
   WHERE person_id = er.person_id;

  -- 4. La crypto-destruction : blob à NULL (les dumps FUTURS) ET sel neuf
  --    (les dumps PASSÉS) — aucun des deux seul ne suffit (en-tête).
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
  --    de publication — voir l'en-tête.)
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

REVOKE ALL ON FUNCTION erase_person(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_person(uuid) TO user_core_app;
