-- =============================================================================
-- 029 — LE PRÉAVIS DE 48 H (LOT effacement, étape 4). AUCUNE PLOMBERIE NEUVE
-- (CDC §10 n°14) : un event_type de plus, une ligne de DONNÉES dans
-- event_channel_policy, et une fonction qui écrit l'outbox — le publisher
-- existant fait tout le reste (résolution du compte au moment de publier,
-- dépôt idempotent par outbox_id, silence tracé si aucun canal). Toute
-- couture supplémentaire serait la 4ᵉ (§3.9), refusée d'avance.
--
-- L'IDEMPOTENCE DU PRÉAVIS EST EN BASE, à deux étages :
--   · notified_at est SET-ONCE (026) — il LÈVE (P0104) sur un second passage,
--     il ne no-ope pas : le worker filtre (WHERE notified_at IS NULL) et
--     cette fonction re-vérifie SOUS VERROU — le rejeu rend un verdict
--     (ALREADY_NOTICED), jamais une deuxième ligne d'outbox ;
--   · l'écriture outbox + le marquage vivent dans LA MÊME transaction : pas
--     de préavis marqué sans événement, pas d'événement sans marquage.
-- =============================================================================

-- La politique de canal : une DONNÉE, révisable par migration signée, jamais
-- du code. Aucun canal externe en V1, et la raison DÉCISIVE n'est pas la
-- prudence : un SMS « votre effacement est imminent », envoyé sur une ligne
-- entre-temps RECYCLÉE, apprendrait à un inconnu qu'un compte de
-- l'écosystème était rattaché à ce numéro — la faute exacte que
-- PHONE_LINE_SUPERSEDED ferme (009). La prudence se discute ; ce risque-là,
-- non. Le préavis se lit donc dans le compte (la demande y est née, le
-- compte est ACTIF pendant toute la fenêtre — C1). Ouvrir un canal externe,
-- si Kevin le décide, sera UNE ligne de données.
INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note) VALUES
  ('PERSON_ERASURE_IMMINENT', '{}', true,
   'Préavis : l''effacement demandé s''exécutera à l''échéance. Déposé dans le compte du demandeur — aucun canal externe en V1 (prudence par défaut, révisable par migration). La rétractation reste possible jusqu''à l''échéance.');

-- Le SEUL écrivain du préavis. Le worker le découvre par balayage
-- (person_erasures, SELECT accordé à 026) et l'appelle ; l'API n'y touche
-- jamais. Verdicts idempotents : rejouer est un fait normal du worker.
CREATE FUNCTION record_erasure_notice(p_erasure_id uuid)
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
  -- Close (COMPLETED, RETRACTED) : rien à annoncer. IMMEDIATE : la personne
  -- a choisi « tout de suite », l'irréversibilité lui a été énoncée AVANT de
  -- valider (CDC §10 n°14) — un préavis n'existe pas sur ce chemin.
  IF er.status <> 'REQUESTED' OR er.mode <> 'DELAYED' THEN
    verdict := 'NOT_APPLICABLE'; RETURN NEXT; RETURN;
  END IF;
  IF er.notified_at IS NOT NULL THEN
    verdict := 'ALREADY_NOTICED'; RETURN NEXT; RETURN;
  END IF;
  IF now() < er.effective_after
             - make_interval(hours => erasure_notification_lead_hours()) THEN
    verdict := 'NOT_YET'; RETURN NEXT; RETURN;
  END IF;

  INSERT INTO outbox (event_type, person_id)
  VALUES ('PERSON_ERASURE_IMMINENT', er.person_id);

  -- Le guard de 026 écrase toute valeur par now() et refuse un second
  -- passage : le set-once est le mur, ce verdict n'est que la façade.
  UPDATE person_erasures SET notified_at = now() WHERE id = er.id;

  verdict := 'NOTICED'; RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION record_erasure_notice(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_erasure_notice(uuid) TO user_core_app;
