-- =============================================================================
-- 011 — create_account() : LE chemin unique de création d'un compte — et le
-- profil de base.
--
-- LA RÉPONSE DÉFINITIVE AU DÉFAUT F5 DE SCOLARIA (deux chemins de création,
-- deux populations de parents : une garde posée dans UN chemin, absente de
-- l'autre) : le rôle applicatif PERD le droit d'insérer dans accounts. Un
-- import en masse, un endpoint d'admin, la v2 de l'inscription : aucun ne
-- pourra fabriquer un compte incomplet — il n'aura pas le droit d'insérer.
-- create_account() (SECURITY DEFINER) devient le SEUL chemin, et il crée le
-- compte ET son premier secret DANS LA MÊME TRANSACTION : un compte sans
-- secret est NON REPRÉSENTABLE, pas interdit par une convention.
--
-- ⚠️ Piège Postgres, vérifié : un REVOKE de niveau TABLE ne retire PAS un
-- GRANT de niveau COLONNE (002 a posé « GRANT INSERT (public_identifier,
-- role) »). Le retrait doit viser LES COLONNES. Les deux formes sont jouées
-- ci-dessous, et le test le prouve sous le rôle bridé.
--
-- LE PROFIL DE BASE (display_name, locale — optionnels, CDC §2) : la seule
-- table MUTABLE du dépôt, et c'est voulu — un nom d'affichage n'est pas un
-- registre, corriger une faute de frappe n'est pas falsifier une preuve.
-- Ce qui reste non négociable : jamais loggé, jamais dans un jeton, et les
-- horodatages restent posés par la base.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) Le chemin unique. SECURITY DEFINER : la fonction insère avec les droits
--    de son propriétaire ; le rôle bridé n'a que EXECUTE. Toutes les gardes
--    existantes s'appliquent à l'intérieur : forme de l'identifiant (002),
--    forme argon2id du secret (003), unicité écosystème, paire provisoire /
--    échéance (003). Une violation ANNULE TOUT : aucun compte orphelin.
-- -----------------------------------------------------------------------------
CREATE FUNCTION create_account(
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
  INSERT INTO accounts (public_identifier, role)
  VALUES (p_public_identifier, p_role)
  RETURNING id INTO new_account_id;

  INSERT INTO account_secrets (account_id, secret_hash, is_temporary, expires_at)
  VALUES (new_account_id, p_secret_hash, p_is_temporary, p_expires_at);

  RETURN new_account_id;
END;
$$;

REVOKE ALL ON FUNCTION create_account(text, account_role, text, boolean, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_account(text, account_role, text, boolean, timestamptz)
  TO user_core_app;

-- -----------------------------------------------------------------------------
-- 2) Le retrait du droit d'insertion directe : niveau table ET niveau colonne
--    (le second est l'opérant — cf. l'en-tête).
-- -----------------------------------------------------------------------------
REVOKE INSERT ON accounts FROM user_core_app;
REVOKE INSERT (public_identifier, role) ON accounts FROM user_core_app;

-- -----------------------------------------------------------------------------
-- 3) Le profil de base : optionnel, mutable, jamais loggé, jamais dans un
--    jeton. Au plus UN profil par compte (PK = account_id).
-- -----------------------------------------------------------------------------
CREATE TABLE account_profiles (
  account_id   uuid PRIMARY KEY REFERENCES accounts(id),
  display_name text,
  locale       text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  -- Un nom d'affichage se dit au guichet : borné, jamais vide s'il existe.
  CONSTRAINT chk_account_profiles_display_name
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 80),
  -- BCP 47 minimal : « fr », « fr-CD », « sw »… — une DONNÉE, jamais un enum.
  CONSTRAINT chk_account_profiles_locale
    CHECK (locale IS NULL OR locale ~ '^[a-z]{2,3}(-[A-Z]{2})?$')
);

-- Un profil ne naît que sous un compte ACTIVE (P0108). FOR SHARE : sérialise
-- avec une désactivation concurrente (patron 004/008/010).
CREATE FUNCTION guard_account_profile_insert() RETURNS trigger AS $$
DECLARE
  acct_status account_status;
BEGIN
  SELECT status INTO acct_status FROM accounts WHERE id = NEW.account_id FOR SHARE;
  IF acct_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'account_profiles : aucun profil ne naît sous un compte % (P0108)',
      acct_status USING ERRCODE = 'P0108';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_account_profiles_guard_insert
  BEFORE INSERT ON account_profiles
  FOR EACH ROW EXECUTE FUNCTION guard_account_profile_insert();

-- Mutable ne veut pas dire sans loi : le rattachement (account_id) et la date
-- de naissance sont immuables, et c'est la BASE qui date chaque retouche —
-- updated_at fourni par un client est écrasé.
CREATE FUNCTION guard_account_profile_update() RETURNS trigger AS $$
BEGIN
  IF NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'account_profiles : rattachement et date de naissance immuables'
      USING ERRCODE = 'P0101';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_account_profiles_guard_update
  BEFORE UPDATE ON account_profiles
  FOR EACH ROW EXECUTE FUNCTION guard_account_profile_update();

CREATE TRIGGER trg_account_profiles_no_delete
  BEFORE DELETE ON account_profiles
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- Standard 002 : ce que la base pose (created_at, updated_at) n'est jamais
-- accordé au client.
GRANT SELECT ON account_profiles TO user_core_app;
GRANT INSERT (account_id, display_name, locale) ON account_profiles TO user_core_app;
GRANT UPDATE (display_name, locale) ON account_profiles TO user_core_app;
REVOKE DELETE, TRUNCATE ON account_profiles FROM user_core_app;
