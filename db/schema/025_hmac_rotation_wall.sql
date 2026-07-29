-- =============================================================================
-- 025 — LE MUR DE LA ROTATION D'EMPREINTE : la référence ne bascule pas tant
-- qu'une revendication ACTIVE vit sous une autre clé (LOT prod, étape 4e —
-- exigence C1 : le mur AVANT le script).
--
-- LE TROU QUE CE MUR FERME : l'unicité mondiale d'une ligne porte sur le
-- COUPLE (hmac_key_id, phone_hmac) WHERE status = 'ACTIVE' (006). Une
-- rotation qui bascule hmac_key_reference AVANT d'avoir re-haché toutes les
-- lignes ACTIVE laisse les anciennes sous H1 pendant que les neuves entrent
-- sous H2 : l'index ne voit AUCUNE collision, et deux revendications ACTIVES
-- coexistent sur la même ligne physique — l'invariant n°1 du dépôt, tombé en
-- silence. Le script de rotation (scripts/rotate-phone-hmac.ts) fait les
-- choses dans l'ordre ; ce trigger rend le désordre NON REPRÉSENTABLE — un
-- script interrompu, une v2 pressée, un geste manuel : personne ne bascule
-- une référence qui mentirait.
--
-- ERRCODE : cette migration ajoute P0115 (rotation incomplète — la référence
-- ne bascule pas tant que le re-hachage n'est pas terminé).
--
-- CE QUE LE MUR NE COUVRE PAS, et pourquoi (conséquences bornées, assumées) :
--   · les revendications PENDING sous l'ancienne clé : elles ne peuvent PLUS
--     s'activer (P0109 exige la clé active à l'activation, 006) — refus
--     propre, la personne re-déclare sa ligne ;
--   · les invitations en attente : elles ne portent AUCUN chiffré (012,
--     délibéré — rien à re-hacher) ; après rotation leur acceptation rend
--     LINE_NOT_PROVEN, puis elles expirent. Ré-inviter est sans coût (021).
-- Aucune de ces deux issues ne corrompt un registre : elles refusent.
--
-- La FENÊTRE D'INDISPONIBILITÉ est structurelle : pendant la rotation, la
-- clé active du service diverge de la référence — le boot refuse
-- (assertFingerprintKeyAligned). Elle se PLANIFIE (docs/ops/ROTATION.md),
-- elle ne se découvre pas.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE FUNCTION guard_hmac_reference_switch() RETURNS trigger AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM phone_claims c
              WHERE c.status = 'ACTIVE'
                AND c.hmac_key_id <> NEW.hmac_key_id) THEN
    RAISE EXCEPTION 'hmac_key_reference : des revendications ACTIVES vivent encore sous une autre clé — le re-hachage se termine AVANT la bascule'
      USING ERRCODE = 'P0115';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_hmac_reference_guard_switch
  BEFORE UPDATE ON hmac_key_reference
  FOR EACH ROW EXECUTE FUNCTION guard_hmac_reference_switch();

-- La référence ne disparaît jamais : sa lecture échoue déjà FERMÉ (P0112,
-- 015) si elle venait à manquer — on rend la disparition non représentable
-- plutôt que de compter sur le filet.
CREATE TRIGGER trg_hmac_reference_no_delete
  BEFORE DELETE ON hmac_key_reference
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();
