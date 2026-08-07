-- =============================================================================
-- 032 — UNE PERSONNE EFFACÉE NE REÇOIT PLUS DE DROIT D'ACCÈS (dette E-1,
-- étape 1 sur 2 : LE MUR. Aucun droit n'est coupé ici — voir « inerte » plus bas).
--
-- ⚠️ CETTE MIGRATION AMENDE UN COMMENTAIRE DE 026 QU'ELLE NE PEUT PAS ÉDITER.
-- 026:33-35 déclare : « PÉRIMÈTRE DU MUR : la RÉ-IDENTIFICATION (écritures de
-- PII), jamais les actes de registre en UUID (liens de responsabilité, droits
-- d'accès) — le devenir des droits d'une personne effacée est un arbitrage
-- produit ouvert. » **CET ARBITRAGE EST FERMÉ** : les droits d'accès sont
-- révoqués dans le même geste que l'effacement (arbitrage produit, 04/08/2026).
-- Le fichier 026 ne peut pas être corrigé sur place : son checksum est
-- enregistré et le runner refuse net toute migration modifiée après
-- application (scripts/migrate.ts:21-24) — la correction en CI passerait
-- (base neuve) et casserait en production, ce qui est le pire des deux. Elle
-- vit donc ICI, à l'endroit où le prochain lecteur arrivera en suivant le mur.
-- ⚠️ **CE QUI RESTE VRAI DE 026:33-35** : les LIENS DE RESPONSABILITÉ ne sont
-- PAS tranchés. La décision ne porte que sur les droits d'accès, et **une
-- décision ne s'étend jamais au-delà de ce qu'elle tranche.**
--
-- POURQUOI UN TRIGGER PLUTÔT QU'UNE GARDE DANS LES FONCTIONS — mesuré dans
-- pg_proc, pas déduit de db/ (où quinze écritures traînent, la plupart
-- remplacées) : **SEPT fonctions vivantes écrivent program_grants, dont CINQ
-- en POSENT un** — accept_program_invitation, grant_program_self,
-- grant_program_staff, grant_program_as_program, open_dependent_access — et
-- toutes sont exécutables par le rôle applicatif. Cinq gardes applicatives
-- seraient cinq occasions d'en oublier une : c'est la forme exacte du défaut
-- fondateur (§3.1). Un seul mur, au niveau de la ligne.
--
-- ⚠️ LE PIÈGE QUI REND CE MUR NON NÉGOCIABLE. accept_program_invitation appelle
-- DÉJÀ person_is_erased (027:231) et paraît donc protégée. **Elle ne l'est
-- pas** : ce garde-fou vit dans la boucle de RATTACHEMENT (SKIPPED_ERASED) et
-- protège les liens de responsabilité ; sa branche ELSE (027:267-285) pose un
-- droit pour la personne du compte acceptant **sans aucun contrôle**. Une
-- protection armée qui établit autre chose que ce qu'on lui prête (§11 ⑬).
--
-- LE SEUL VECTEUR EST L'INSERT, et c'est vérifié : guard_program_grant_update
-- (023:152-156) interdit déjà toute transition vers autre chose que REVOKED —
-- un droit coupé ne peut pas être réactivé, et l'unicité partielle interdit
-- deux ACTIFS. BEFORE INSERT suffit donc, et couvre les cinq chemins d'un coup.
--
-- CE QUE CETTE MIGRATION NE FAIT PAS : elle ne coupe RIEN. Aucun droit existant
-- n'est touché, erase_person() est inchangée. **Le lot reste INERTE en
-- production tant que l'étape 2 n'est pas livrée** — le mur précède la porte
-- (§11 ④), exactement comme au LOT effacement.
--
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) Le motif de révocation que l'étape 2 posera.
--
-- 🔴 ERASED EST UNE ÉTIQUETTE VÉRIDIQUE, PAS UNE PROTECTION. Le mur est le
--    trigger ci-dessous, qui lit l'ÉTAT EFFACÉ DE LA PERSONNE — aucun mur ne
--    lit ce motif. Ne pas lui prêter une garde qu'il n'exerce pas : par le
--    critère de 023 (une valeur entre dans le patron d'acteur si elle est
--    l'ENTRÉE D'UN INVARIANT), ERASED est DESCRIPTIF, comme la dette
--    sessions.revoke_reason.
--    Elle est ajoutée quand même parce que les trois autres valeurs sont
--    fausses ou dangereuses : SELF falsifierait l'acteur ET lèverait P0108
--    (023:161-171 exige un compte ACTIF, or l'effacement désactive le compte
--    dans la même transaction, 028:286) ; ADMIN est OUVRANT (le mur de
--    réouverture ne bloque que 'SELF' — le clic suivant rouvrirait le droit) ;
--    PROGRAM mentirait sur l'auteur du retrait.
--
-- ⚠️ CE QUE CETTE VALEUR COÛTE EN LISIBILITÉ POUR UN PROGRAME EXTÉRIEUR, et la
--    condition qui doit rester vraie : la façade n'expose jamais le motif
--    (status, grantedAt, revokedAt seuls) ; un programme voit donc REVOKED sans
--    savoir pourquoi. **Cette ambiguïté repose sur DEUX valeurs atteignables —
--    SELF et ERASED. Le jour où l'une cesse de l'être, ce n'est plus une
--    ambiguïté, c'est un oracle d'effacement.** Mesuré au moment d'écrire :
--    ADMIN et ACCOUNT_DEACTIVATED ne sont plus posés par aucune fonction
--    vivante sur cette table. Un test tient cette condition en vie.
--
-- NOTE RUNNER (patron 027:168-170) : la valeur s'ajoute dans la transaction de
-- cette migration et n'y est JAMAIS utilisée — les corps plpgsql ne s'évaluent
-- pas à la création. La contrainte Postgres est respectée.
-- -----------------------------------------------------------------------------
ALTER TYPE program_grant_revoke_reason ADD VALUE 'ERASED';

-- -----------------------------------------------------------------------------
-- 2) LE MUR. Jumeau exact de wall_erased_person_claim (026:298-312), relu
--    plutôt que recopié : mêmes attributs re-déclarés (SECURITY DEFINER,
--    search_path), même ERRCODE, même forme de message.
--
--    SECURITY DEFINER : person_is_erased est STABLE et SECURITY DEFINER ; le
--    trigger l'est aussi pour que la lecture du registre ne dépende jamais des
--    droits de celui qui écrit.
--
--    ⚠️ IL S'APPLIQUE AUSSI À L'OWNER — c'est voulu, et c'est mesuré : aucune
--    fonction n'a de raison légitime de poser un droit sur une personne
--    effacée. Les SEPT écrivains sont ceux nommés en tête ; erase_person() ne
--    fait qu'un UPDATE (la révocation de l'étape 2), jamais un INSERT, donc ce
--    mur ne la gênera pas. Et aucun script d'exploitation n'écrit cette table
--    (zéro occurrence dans src/ et scripts/).
-- -----------------------------------------------------------------------------
CREATE FUNCTION wall_erased_person_grant() RETURNS trigger AS $$
BEGIN
  IF person_is_erased(NEW.person_id) THEN
    RAISE EXCEPTION 'program_grants : personne effacée — aucun droit d''accès neuf (P0116)'
      USING ERRCODE = 'P0116';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_program_grants_erasure_wall
  BEFORE INSERT ON program_grants
  FOR EACH ROW EXECUTE FUNCTION wall_erased_person_grant();
