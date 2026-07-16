-- =============================================================================
-- 014 — persons : la PERSONNE, distincte du COMPTE (CDC §2.1, arbitrage Kevin
-- du 15/07/2026). Une personne est une identité humaine transverse de
-- l'écosystème ; un compte est le MOYEN D'AGIR. Une personne peut exister
-- SANS compte (un mineur) : elle est représentée par ses responsables.
-- Le rattachement des comptes (015), le lien de responsabilité (016) et
-- l'émancipation (019) arrivent aux migrations suivantes du LOT 5.
--
-- LE NOM — motif G, le cœur est agnostique du PAYS : AUCUNE colonne de
-- composante de nom n'existe ici. L'identité d'état civil (composantes de nom
-- GÉNÉRIQUES, nom d'affichage FOURNI, date de naissance complète) vit dans UN
-- blob chiffré AES-256-GCM (src/crypto/person-identity.ts, le SEUL écrivain).
-- Le cœur STOCKE, il n'INTERPRÈTE pas : il ne décide ni du nombre de
-- composantes, ni de leur agencement, ni de laquelle est « le vrai nom ».
-- Le post-nom est une composante parmi d'autres ; Brazzaville en a une de
-- moins : zéro migration dans les deux cas.
--
-- LA DATE DE NAISSANCE — finalité écrite : « identité d'état civil, source
-- unique pour tous les programmes » (CDC §2.1.1.5). Elle vit dans le blob
-- chiffré — protection maximale, comme le numéro de téléphone : jamais en
-- clair en base, jamais dans un log, jamais dans un jeton.
--
-- birth_year — LA SEULE dérivée en clair (finalité écrite : « borne d'âge en
-- base », arbitrage Auditeur du 16/07/2026) :
--   · MINIMISATION (§3.14) : le seuil d'émancipation est exprimé en ANNÉES ;
--     il exige une granularité d'année, rien de plus. LE JOUR ET LE MOIS
--     N'ENTRENT JAMAIS DANS CETTE COLONNE, NI DANS AUCUNE AUTRE.
--   · RÉSIDU ASSUMÉ ± 1 an : le mur d'âge en base protège l'ORDRE DE GRANDEUR
--     (émanciper un enfant de 5 ans est non représentable, quel que soit le
--     bug du service) — pas la précision d'un seuil qui est lui-même un
--     chiffre de config sans force de loi (16 ans, Kevin l'assume, aucun
--     cadre juridique RDC). La précision au jour près est la FAÇADE (§3.1) :
--     le service lit la date complète par le chemin contrôlé et rend l'erreur
--     propre. NE PAS « CORRIGER » CE RÉSIDU EN AJOUTANT LE MOIS : une date
--     plus fine en clair rouvrirait la brèche d'effacement par la petite
--     porte (une date complète en clair survivrait à la crypto-destruction
--     et ferait de « effaçable » un mensonge).
--   · RÉSIDU D'EFFACEMENT DÉCLARÉ : birth_year SURVIT à la destruction de la
--     clé (§3.14). Une année nue, détachée d'un nom devenu illisible, est le
--     résidu accepté et DÉCLARÉ — et aucune autre composante de date ne le
--     rejoint jamais.
--
-- erasure_salt — le crochet d'effacement PAR PERSONNE (§3.14) : la PII de la
-- personne est chiffrée sous une clé DÉRIVÉE (HKDF) de la clé du trousseau ET
-- de ce sel. Effacer une personne = détruire SON sel (procédure du lot dédié,
-- avec sa politique de rétention des sauvegardes) : ses données deviennent
-- illisibles, celles des autres restent lisibles, les registres techniques
-- restent intacts. Le sel est du matériel de clé : hors du SELECT du rôle
-- applicatif, immuable, 32 octets exigés.
--
-- CHEMIN UNIQUE dès le premier jour (leçon F5, patron 011) : le rôle
-- applicatif n'a JAMAIS eu le droit d'INSERT sur persons — toute personne
-- naît par create_person(). Aucun deuxième chemin de création ne peut naître,
-- il n'y a rien à retirer plus tard.
--
-- ERRCODE : cette migration ajoute P0111 = « valeur de registre hors bornes »
-- (année de naissance future). Les familles P0101…P0110 restent celles de
-- 005/006/008.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TABLE persons (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  public_identifier        text NOT NULL,
  civil_identity_encrypted text,        -- blob AES-256-GCM ; hors SELECT du rôle applicatif
  enc_key_id               text,        -- clé du trousseau sous laquelle la dérivée a chiffré
  birth_year               smallint,    -- borne d'âge en base — voir l'en-tête, rien de plus fin
  erasure_salt             bytea NOT NULL,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_persons_public_identifier UNIQUE (public_identifier),
  -- 10 chiffres sans zéro de tête (patron 002) : dictable au guichet. Espace
  -- distinct de celui des comptes : deux registres, deux tirages CSPRNG.
  CONSTRAINT chk_persons_identifier_shape CHECK (public_identifier ~ '^[1-9][0-9]{9}$'),
  -- Le blob et l'identifiant de sa clé vivent et meurent ensemble.
  CONSTRAINT chk_persons_identity_pair
    CHECK ((civil_identity_encrypted IS NULL) = (enc_key_id IS NULL)),
  -- Garde statique large ; la borne dynamique (année future) est au trigger.
  CONSTRAINT chk_persons_birth_year_range
    CHECK (birth_year IS NULL OR birth_year BETWEEN 1900 AND 2100),
  CONSTRAINT chk_persons_erasure_salt_size CHECK (octet_length(erasure_salt) = 32)
);

-- -----------------------------------------------------------------------------
-- Gardes
-- -----------------------------------------------------------------------------
CREATE FUNCTION guard_person_insert() RETURNS trigger AS $$
BEGIN
  -- Une année future rendrait l'âge négatif. Sens conservateur noté : une
  -- année trop GRANDE rajeunit la personne et durcit le mur d'émancipation —
  -- la falsification dangereuse (se vieillir) exige une année passée,
  -- qu'aucune base ne peut réfuter : c'est la confiance dans le déclarant,
  -- tracée au rattachement (016).
  IF NEW.birth_year IS NOT NULL
     AND NEW.birth_year > EXTRACT(YEAR FROM now())::int THEN
    RAISE EXCEPTION 'persons : année de naissance dans le futur'
      USING ERRCODE = 'P0111';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_persons_guard_insert
  BEFORE INSERT ON persons
  FOR EACH ROW EXECUTE FUNCTION guard_person_insert();

CREATE FUNCTION guard_person_update() RETURNS trigger AS $$
BEGIN
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

CREATE TRIGGER trg_persons_guard_update
  BEFORE UPDATE ON persons
  FOR EACH ROW EXECUTE FUNCTION guard_person_update();

CREATE TRIGGER trg_persons_no_delete
  BEFORE DELETE ON persons
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- -----------------------------------------------------------------------------
-- La politique d'émancipation : UNE ligne, écrite par migration, jamais par le
-- service (patron hmac_key_reference, 006). 16 ans par défaut : décision
-- ASSUMÉE par Kevin (15-16/07/2026, aucun cadre juridique RDC) — paramétrable
-- par migration signée, jamais figée dans du code. Les bornes du CHECK sont
-- une garde de saisie (un 160 ne passe pas), pas une doctrine.
-- -----------------------------------------------------------------------------
CREATE TABLE emancipation_policy (
  singleton         boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  minimum_age_years integer NOT NULL CHECK (minimum_age_years BETWEEN 10 AND 30),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

INSERT INTO emancipation_policy (minimum_age_years) VALUES (16);

GRANT SELECT ON emancipation_policy TO user_core_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON emancipation_policy FROM user_core_app;

-- Le seuil, lisible par les triggers des migrations suivantes (mur d'âge) et
-- par le service (façade). Patron active_hmac_key_id (006).
CREATE FUNCTION emancipation_minimum_age() RETURNS integer AS $$
  SELECT minimum_age_years FROM emancipation_policy WHERE singleton;
$$ LANGUAGE sql STABLE
SET search_path = pg_catalog, public;

-- -----------------------------------------------------------------------------
-- create_person() : LE chemin unique de création d'une personne.
-- SECURITY DEFINER : le rôle applicatif n'a que EXECUTE — le droit d'INSERT
-- direct n'existe pas et n'a jamais existé. L'identité civile est optionnelle
-- à la naissance (une personne issue d'une inscription minimale la fournit
-- plus tard) ; quand elle est fournie, la paire blob/clé et la borne d'année
-- s'appliquent (CHECK + trigger, à l'intérieur de la fonction comme partout).
-- -----------------------------------------------------------------------------
CREATE FUNCTION create_person(
  p_public_identifier        text,
  p_erasure_salt             bytea,
  p_civil_identity_encrypted text,
  p_enc_key_id               text,
  p_birth_year               integer
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  new_person_id uuid;
BEGIN
  INSERT INTO persons (public_identifier, erasure_salt, civil_identity_encrypted,
                       enc_key_id, birth_year)
  VALUES (p_public_identifier, p_erasure_salt, p_civil_identity_encrypted,
          p_enc_key_id, p_birth_year::smallint)
  RETURNING id INTO new_person_id;

  RETURN new_person_id;
END;
$$;

REVOKE ALL ON FUNCTION create_person(text, bytea, text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_person(text, bytea, text, text, integer)
  TO user_core_app;

-- -----------------------------------------------------------------------------
-- read_person_identity() : l'UNIQUE chemin vers le blob chiffré et le sel
-- (patron C9/C10, read_phone_encrypted de 007). Le service ne lit une identité
-- que pour la SERVIR — jamais « au cas où », jamais en masse. La base ne
-- déchiffre rien (elle n'a pas les clés — c'est délibéré) : elle remet le
-- jeton chiffré et le sel à qui a le droit de les demander. Le déchiffrement
-- lui-même n'existe que dans src/crypto/person-identity.ts (motif F).
-- -----------------------------------------------------------------------------
CREATE FUNCTION read_person_identity(p_person_id uuid)
RETURNS TABLE (civil_identity_encrypted text, enc_key_id text, erasure_salt bytea)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT p.civil_identity_encrypted, p.enc_key_id, p.erasure_salt
    FROM persons p
   WHERE p.id = p_person_id;
$$;

REVOKE ALL ON FUNCTION read_person_identity(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION read_person_identity(uuid) TO user_core_app;

-- -----------------------------------------------------------------------------
-- Droits (patron 002/006 : colonne par colonne ; ce que la base pose n'est
-- jamais accordé au client). civil_identity_encrypted et erasure_salt sont
-- HORS du SELECT : lecture par read_person_identity() uniquement. Le rôle
-- applicatif peut RETOUCHER le blob (corriger une faute de frappe dans un nom
-- n'est pas falsifier une preuve — patron account_profiles, 011) sans jamais
-- pouvoir le lire en direct, et poser birth_year UNE fois (trigger set-once).
-- -----------------------------------------------------------------------------
GRANT SELECT (id, public_identifier, enc_key_id, birth_year, created_at, updated_at)
  ON persons TO user_core_app;
GRANT UPDATE (civil_identity_encrypted, enc_key_id, birth_year)
  ON persons TO user_core_app;
REVOKE INSERT, DELETE, TRUNCATE ON persons FROM user_core_app;
