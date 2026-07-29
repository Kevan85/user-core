-- =============================================================================
-- 023 — LA PREUVE D'ACTEUR AU REGISTRE (LOT prod, étape 2 — dette /v1 ①).
--
-- LE DÉFAUT SOLDÉ ICI : granted_by, revoke_reason (program_grants) et
-- opened_by (person_responsibilities) étaient DÉCLARATIFS — le rôle
-- applicatif les écrivait par GRANT de colonne, sur sa seule parole. Or
-- revoke_reason = 'SELF' est LU PAR UN MUR (la matrice de réactivation,
-- 008/012/019/021 : « ce que la famille a fermé, ELLE SEULE le rouvre ») :
-- un service qui écrit cette valeur à tort FABRIQUE ou DÉTRUIT un droit
-- d'accès. Ce n'était pas une trace imprécise : c'était un invariant posé
-- sur une déclaration.
--
-- LA PARADE — le patron end_responsibility() (017), relu avant d'être copié :
-- une fonction SECURITY DEFINER PAR ACTEUR. LE NOM DE LA FONCTION EST
-- L'ACTEUR — l'acteur disparaît des signatures, il ne peut plus être un
-- mensonge de paramètre (attach_dependent portait p_opened_by : une fonction
-- SECURITY DEFINER qui demande l'acteur en argument ne prouve rien).
-- Ce que la base PEUT prouver, elle le prouve elle-même :
--   · l'acteur staff : role IN (PLATFORM_STAFF, PLATFORM_ADMIN) lu dans
--     accounts, compte ACTIF exigé (le contrôle app de service tombe — §3.1) ;
--   · l'acteur famille : la personne est RÉSOLUE du compte par la base,
--     jamais fournie par le service ;
--   · l'acteur responsable : le lien ACTIF de l'agissant sur l'ayant droit
--     est vérifié ICI, plus seulement dans le BOLA du service.
-- Ce qu'elle ne peut pas prouver (quel jeton a authentifié l'appel), aucun
-- étage ne le peut : la surface restante est le choix de la fonction, plus
-- jamais le contenu d'une colonne.
--
-- LE RÔLE APPLICATIF PERD SES DROITS D'ÉCRITURE sur les deux registres —
-- les deux formes, table ET colonne (piège vérifié en 011 : un REVOKE de
-- table ne retire pas un GRANT de colonne). Les triggers restent les murs
-- de FOND (immuabilité, matrice, différés P0113/P0114) : les fonctions
-- passent dessous comme tout le monde.
--
-- LE MUR E1 — un acte SELF exige un compte ACTIF de la personne du droit.
-- Trois chemins d'acte sur cinq le vérifiaient déjà (staff, co-responsable,
-- rattachement — via 017) ; les deux chemins famille ne le vérifiaient
-- nulle part, et revoke_reason = 'SELF' est l'entrée du mur de réactivation :
-- un compte mort pouvait verrouiller un programme contre le programme
-- lui-même. Le mur vit dans les TRIGGERS de garde (le test de §3.1 : un job,
-- un script, la v2) ; les fonctions SELF n'en sont que la façade propre.
-- ⚠️ Il ne porte QUE sur l'acteur SELF : une personne sans aucun compte (un
-- mineur) reçoit légitimement des droits — par PROGRAM ou PLATFORM_STAFF.
-- Vérifié avant de graver (les chemins SELF hors 023) : l'acceptation d'une
-- invitation (019/021) ne pose 'SELF' que pour la personne de l'ACCEPTANT —
-- jamais pour un ayant droit (son droit naît 'PROGRAM' au clic, 021) ; le
-- mur les traverse donc sans en casser aucun.
-- 📌 AMENDEMENT d'une prose de 019 (immuable, notée ici — leçon ⑤ adaptée) :
-- son en-tête dit « aucun contrôle de vitalité ne remplace » l'ancienne
-- garde de compte. Cela reste vrai pour le DROIT (il appartient à la
-- personne, il survit au compte) ; c'est amendé pour l'ACTE : agir en
-- famille exige d'exister comme compte actif.
--
-- HORS PÉRIMÈTRE, dette nommée (arbitrage C6) : sessions.revoke_reason et
-- phone_claims.revoke_reason restent déclaratifs — vérifié le 29/07/2026,
-- AUCUN mur ne les lit (recherche exhaustive db/ + src/ : uniquement des
-- écritures et des gardes d'immuabilité) ; conséquence bornée à une trace
-- d'audit. Le jour où un mur les lit, ils entrent dans ce patron.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- LE MUR E1, d'abord (le mur avant la porte — les fonctions suivent). Les
-- deux gardes de 019 sont reprises EN ENTIER, attributs re-déclarés (piège
-- CREATE OR REPLACE : un attribut omis retombe au défaut en silence) —
-- l'insertion reste SECURITY DEFINER (elle lisait déjà programs au-delà du
-- rôle), la mise à jour reste au rôle invoquant (accounts est lisible des
-- deux rôles), search_path épinglé sur les deux.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_program_grant_insert() RETURNS trigger AS $$
DECLARE
  p programs%ROWTYPE;
  last_grant program_grants%ROWTYPE;
BEGIN
  SELECT * INTO p FROM programs WHERE id = NEW.program_id FOR SHARE;
  IF p.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'program_grants : le programme n''est plus proposé (%)', p.status
      USING ERRCODE = 'P0108';
  END IF;

  IF NEW.granted_by = 'SELF' THEN
    -- E1 : agir en famille exige d'exister comme compte ACTIF — au présent.
    -- (FOR SHARE : sérialise avec une désactivation concurrente, patron 017.)
    IF NOT EXISTS (SELECT 1 FROM accounts a
                    WHERE a.person_id = NEW.person_id
                      AND a.status = 'ACTIVE'
                    FOR SHARE) THEN
      RAISE EXCEPTION 'program_grants : un acte de la famille exige un compte actif de la personne'
        USING ERRCODE = 'P0108';
    END IF;
  END IF;

  IF p.access_mode = 'GRANTED' AND NEW.granted_by = 'SELF' THEN
    SELECT * INTO last_grant FROM program_grants g
     WHERE g.person_id = NEW.person_id
       AND g.program_id = NEW.program_id
     ORDER BY g.seq DESC
     LIMIT 1;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'program_grants : un programme sur accès accordé ne s''ouvre pas soi-même'
        USING ERRCODE = 'P0110';
    END IF;

    IF last_grant.revoke_reason IS DISTINCT FROM 'SELF' THEN
      RAISE EXCEPTION 'program_grants : accès retiré par un tiers (motif %) — la famille ne peut pas le rouvrir',
        last_grant.revoke_reason
        USING ERRCODE = 'P0110';
    END IF;
  END IF;

  IF NEW.granted_by = 'PROGRAM' THEN
    IF p.access_mode <> 'GRANTED' THEN
      RAISE EXCEPTION 'program_grants : un programme n''ouvre un droit que sur le mode accordé (LOT 4)'
        USING ERRCODE = 'P0110';
    END IF;

    SELECT * INTO last_grant FROM program_grants g
     WHERE g.person_id = NEW.person_id
       AND g.program_id = NEW.program_id
     ORDER BY g.seq DESC
     LIMIT 1;

    IF FOUND AND last_grant.revoke_reason = 'SELF' THEN
      RAISE EXCEPTION 'program_grants : la famille a fermé ce programme — elle seule le rouvre'
        USING ERRCODE = 'P0110';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION guard_program_grant_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.program_id IS DISTINCT FROM OLD.program_id
     OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
     OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
    RAISE EXCEPTION 'program_grants : contenu immuable — réactiver = une NOUVELLE ligne'
      USING ERRCODE = 'P0101';
  END IF;

  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'program_grants : un droit révoqué est figé — réactiver = une NOUVELLE ligne'
      USING ERRCODE = 'P0103';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status <> 'REVOKED' THEN
      RAISE EXCEPTION 'program_grants : % -> % interdit', OLD.status, NEW.status
        USING ERRCODE = 'P0102';
    END IF;
    IF NEW.revoke_reason IS NULL THEN
      RAISE EXCEPTION 'program_grants : une révocation porte toujours son motif'
        USING ERRCODE = 'P0102';
    END IF;
    IF NEW.revoke_reason = 'SELF' THEN
      -- E1 : « la famille a fermé » est l'entrée du mur de réactivation —
      -- seul un compte ACTIF de la personne peut poser ce motif.
      IF NOT EXISTS (SELECT 1 FROM accounts a
                      WHERE a.person_id = NEW.person_id
                        AND a.status = 'ACTIVE'
                      FOR SHARE) THEN
        RAISE EXCEPTION 'program_grants : un acte de la famille exige un compte actif de la personne'
          USING ERRCODE = 'P0108';
      END IF;
    END IF;
    NEW.revoked_at := now();   -- la base horodate, jamais le client
  ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
     OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason THEN
    RAISE EXCEPTION 'program_grants : les horodatages de registre sont posés par la base'
      USING ERRCODE = 'P0104';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- LA FAMILLE, depuis son compte. La personne est résolue ICI : le service ne
-- peut plus poser un droit « SELF » sur la personne d'un autre.
-- Les murs de fond parlent ensuite : P0108 (programme mort), P0110 (matrice),
-- uq_program_grants_active (déjà actif) — le service les traduit, comme avant.
-- -----------------------------------------------------------------------------
CREATE FUNCTION grant_program_self(p_account_id uuid, p_program_id uuid)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  acting accounts%ROWTYPE;
BEGIN
  SELECT * INTO acting FROM accounts WHERE id = p_account_id FOR SHARE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;
  -- Façade du mur E1 (le mur est dans le trigger) : verdict propre.
  IF acting.status <> 'ACTIVE' THEN
    verdict := 'ACCOUNT_NOT_ACTIVE'; RETURN NEXT; RETURN;
  END IF;

  INSERT INTO program_grants (person_id, program_id, granted_by)
  VALUES (acting.person_id, p_program_id, 'SELF');
  verdict := 'ACTIVATED'; RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- LE STAFF. Le contrôle de rôle vit ICI, en base (patron end_responsibility) —
-- l'« if » de service qui le portait n'était qu'une façade, il tombe.
-- -----------------------------------------------------------------------------
CREATE FUNCTION grant_program_staff(
  p_actor_account_id  uuid,
  p_target_account_id uuid,
  p_program_id        uuid
) RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor accounts%ROWTYPE;
  v_person_id uuid;
BEGIN
  SELECT * INTO actor FROM accounts WHERE id = p_actor_account_id FOR SHARE;
  IF NOT FOUND
     OR actor.status <> 'ACTIVE'
     OR actor.role NOT IN ('PLATFORM_STAFF', 'PLATFORM_ADMIN') THEN
    verdict := 'FORBIDDEN'; RETURN NEXT; RETURN;
  END IF;

  SELECT a.person_id INTO v_person_id FROM accounts a
   WHERE a.id = p_target_account_id AND a.status = 'ACTIVE' FOR SHARE;
  IF v_person_id IS NULL THEN
    verdict := 'UNKNOWN_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;

  INSERT INTO program_grants (person_id, program_id, granted_by)
  VALUES (v_person_id, p_program_id, 'PLATFORM_STAFF');
  verdict := 'GRANTED'; RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- LE PROGRAMME, via son identité cliente. La base ne peut pas vérifier le
-- jeton du programme (c'est le contrôleur qui pose program_id du jeton — BOLA
-- au registre, inchangé) ; ce qu'elle garantit désormais : ce chemin ne peut
-- estampiller QUE 'PROGRAM' — jamais un faux « choix de la famille ».
-- -----------------------------------------------------------------------------
CREATE FUNCTION grant_program_as_program(p_person_id uuid, p_program_id uuid)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO program_grants (person_id, program_id, granted_by)
  VALUES (p_person_id, p_program_id, 'PROGRAM');
  verdict := 'GRANTED'; RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- Les révocations, mêmes acteurs. C'est ICI que la dette C12 se paie :
-- revoke_reason = 'SELF' (l'entrée du mur de réactivation) ne peut plus être
-- écrit que par le chemin famille, résolu du compte par la base.
-- -----------------------------------------------------------------------------
CREATE FUNCTION revoke_program_grant_self(p_account_id uuid, p_program_id uuid)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  acting accounts%ROWTYPE;
BEGIN
  SELECT * INTO acting FROM accounts WHERE id = p_account_id FOR SHARE;
  IF NOT FOUND THEN
    verdict := 'UNKNOWN_ACCOUNT'; RETURN NEXT; RETURN;
  END IF;
  -- Façade du mur E1 (le mur est dans le trigger) : un compte mort ne pose
  -- pas « la famille a fermé » — l'entrée du mur de réactivation.
  IF acting.status <> 'ACTIVE' THEN
    verdict := 'ACCOUNT_NOT_ACTIVE'; RETURN NEXT; RETURN;
  END IF;

  UPDATE program_grants g
     SET status = 'REVOKED', revoke_reason = 'SELF'
   WHERE g.person_id = acting.person_id
     AND g.program_id = p_program_id
     AND g.status = 'ACTIVE';
  IF FOUND THEN
    verdict := 'DEACTIVATED';
  ELSE
    verdict := 'NOT_ACTIVE';
  END IF;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION revoke_program_grant_as_program(p_person_id uuid, p_program_id uuid)
RETURNS TABLE (verdict text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE program_grants g
     SET status = 'REVOKED', revoke_reason = 'PROGRAM'
   WHERE g.person_id = p_person_id
     AND g.program_id = p_program_id
     AND g.status = 'ACTIVE';
  IF FOUND THEN
    verdict := 'REVOKED';
  ELSE
    verdict := 'NOT_ACTIVE';
  END IF;
  RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- LE CO-RESPONSABLE : « un responsable en place l'ajoute ». La preuve —
-- l'agissant détient un lien ACTIF sur l'ayant droit — se lit ICI, dans le
-- registre ; le BOLA du service n'en est plus que l'écho. Les murs de fond
-- parlent ensuite : P0108 (le co-responsable n'a pas de compte actif), P0113
-- (personne autonome), uq_person_responsibilities_active (déjà responsable).
-- -----------------------------------------------------------------------------
CREATE FUNCTION open_responsibility_by_responsible(
  p_acting_account_id        uuid,
  p_co_responsible_person_id uuid,
  p_dependent_person_id      uuid
) RETURNS TABLE (verdict text, responsibility_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor accounts%ROWTYPE;
  v_link_id uuid;
BEGIN
  SELECT * INTO actor FROM accounts WHERE id = p_acting_account_id FOR SHARE;
  IF NOT FOUND OR actor.status <> 'ACTIVE' THEN
    verdict := 'FORBIDDEN'; RETURN NEXT; RETURN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM person_responsibilities r
                  WHERE r.responsible_person_id = actor.person_id
                    AND r.dependent_person_id = p_dependent_person_id
                    AND r.status = 'ACTIVE') THEN
    verdict := 'NOT_RESPONSIBLE'; RETURN NEXT; RETURN;
  END IF;

  INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
  VALUES (p_co_responsible_person_id, p_dependent_person_id, 'RESPONSIBLE')
  RETURNING id INTO v_link_id;

  verdict := 'OPENED'; responsibility_id := v_link_id; RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- attach_dependent(), refondu SANS p_opened_by (le paramètre était l'acteur
-- déclaré — la fonction ne prouvait rien) : le rattachement est l'acte du
-- RESPONSABLE, la fonction l'estampille elle-même. Et elle part désormais du
-- COMPTE agissant : la personne responsable est résolue par la base, plus
-- fournie par le service. (DROP + CREATE : patron 016 pour un changement de
-- signature — l'ancienne forme ne doit plus exister, pas seulement être
-- interdite.) Le trigger d'insertion (017) reste le mur : compte ACTIF du
-- responsable (P0108), minorité (P0111), coupure (P0113).
-- -----------------------------------------------------------------------------
DROP FUNCTION attach_dependent(uuid, text, bytea, text, text, integer, responsibility_actor);

CREATE FUNCTION attach_dependent(
  p_responsible_account_id       uuid,
  p_dependent_public_identifier  text,
  p_dependent_erasure_salt       bytea,
  p_dependent_identity_encrypted text,
  p_dependent_enc_key_id         text,
  p_dependent_birth_year         integer
) RETURNS TABLE (dependent_person_id uuid, responsibility_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_responsible_person_id uuid;
  new_person_id uuid;
  new_link_id uuid;
BEGIN
  IF p_dependent_identity_encrypted IS NULL
     OR p_dependent_enc_key_id IS NULL
     OR p_dependent_birth_year IS NULL THEN
    RAISE EXCEPTION 'attach_dependent : un ayant droit naît identifié (blob, clé, année exigés)'
      USING ERRCODE = 'P0111';
  END IF;

  SELECT a.person_id INTO v_responsible_person_id FROM accounts a
   WHERE a.id = p_responsible_account_id FOR SHARE;
  IF v_responsible_person_id IS NULL THEN
    RAISE EXCEPTION 'attach_dependent : le compte agissant est inconnu'
      USING ERRCODE = 'P0108';
  END IF;

  new_person_id := create_person(p_dependent_public_identifier, p_dependent_erasure_salt,
                                 p_dependent_identity_encrypted, p_dependent_enc_key_id,
                                 p_dependent_birth_year);

  INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
  VALUES (v_responsible_person_id, new_person_id, 'RESPONSIBLE')
  RETURNING id INTO new_link_id;

  dependent_person_id := new_person_id;
  responsibility_id := new_link_id;
  RETURN NEXT;
END;
$$;

-- -----------------------------------------------------------------------------
-- Droits. Le rôle applicatif perd l'écriture directe des deux registres —
-- les DEUX formes, table et colonne. La lecture ne bouge pas.
-- -----------------------------------------------------------------------------
REVOKE INSERT ON program_grants FROM user_core_app;
REVOKE INSERT (person_id, program_id, granted_by) ON program_grants FROM user_core_app;
REVOKE UPDATE ON program_grants FROM user_core_app;
REVOKE UPDATE (status, revoke_reason) ON program_grants FROM user_core_app;

REVOKE INSERT ON person_responsibilities FROM user_core_app;
REVOKE INSERT (responsible_person_id, dependent_person_id, opened_by)
  ON person_responsibilities FROM user_core_app;

REVOKE ALL ON FUNCTION grant_program_self(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_program_staff(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_program_as_program(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_program_grant_self(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_program_grant_as_program(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION open_responsibility_by_responsible(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attach_dependent(uuid, text, bytea, text, text, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION grant_program_self(uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION grant_program_staff(uuid, uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION grant_program_as_program(uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION revoke_program_grant_self(uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION revoke_program_grant_as_program(uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION open_responsibility_by_responsible(uuid, uuid, uuid) TO user_core_app;
GRANT EXECUTE ON FUNCTION attach_dependent(uuid, text, bytea, text, text, integer) TO user_core_app;
