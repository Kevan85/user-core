-- =============================================================================
-- 015 — active_hmac_key_id() échoue FERMÉ (correction C5, Auditeur 16/07/2026).
--
-- LE DÉFAUT (006:47-49, forme d'origine) : « SELECT hmac_key_id FROM
-- hmac_key_reference WHERE singleton » rend NULL si la ligne de référence
-- manque. Or la garde qui protège l'invariant n°1 du dépôt (006:133) s'écrit
-- « IF NEW.hmac_key_id <> active_hmac_key_id() THEN RAISE » — et en SQL,
-- 'H1' <> NULL vaut NULL : le IF ne lève pas, la garde S'OUVRE. Une
-- revendication entrerait alors sous une clé d'empreinte arbitraire, et
-- l'unicité mondiale — qui porte sur le COUPLE (clé, empreinte), 006:108 —
-- laisserait coexister deux revendications ACTIVES sur la même ligne
-- physique. Exactement le piège Q2 que 006 dit fermer.
--
-- Périmètre honnête : atteindre cet état exige une action owner (aucun chemin
-- applicatif ne vide la référence — REVOKE en place). Mais un mur qui ne
-- tient que si personne ne trébuche en amont n'est pas un mur : la
-- consultation échoue désormais FERMÉ (P0112), et plus aucun invariant en
-- aval n'a de NULL à oublier. C'est le patron du verdict appliqué à une
-- lecture de référence : on ne demande plus au prochain auteur d'y penser.
--
-- 006 est FUSIONNÉE, donc immuable (le runner refuse un checksum divergent) :
-- correction par CREATE OR REPLACE dans une migration signée, patron 005.
-- La signature et la volatilité (STABLE) ne changent pas ; 014 a posé la même
-- forme pour emancipation_minimum_age() dès sa naissance.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE OR REPLACE FUNCTION active_hmac_key_id() RETURNS text AS $$
DECLARE
  key_id text;
BEGIN
  SELECT hmac_key_id INTO key_id FROM hmac_key_reference WHERE singleton;
  IF key_id IS NULL THEN
    RAISE EXCEPTION 'hmac_key_reference : table de référence vide — le socle est absent, aucune garde ne doit s''ouvrir'
      USING ERRCODE = 'P0112';
  END IF;
  RETURN key_id;
END;
$$ LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, public;
