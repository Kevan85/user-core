-- =============================================================================
-- 002 — accounts : le compte, unique au niveau de l'ÉCOSYSTÈME (CDC §4).
-- Jamais « un compte par programme » : c'est le défaut de Scolaria qu'on ne
-- reconduit pas. Identifiant public opaque à 10 chiffres, GÉNÉRÉ côté service
-- par un CSPRNG (src/accounts/public-identifier.ts) — jamais un email, jamais
-- un téléphone, jamais une séquence (un identifiant énumérable rendrait
-- l'anti-énumération du login gratuite à contourner).
--
-- Rôles TRANSVERSES uniquement (CLAUDE.md §3.7) : le jour où User-Core sait
-- ce qu'est un enseignant, il est mort.
--
-- La désactivation est un STATUT (§3.10), jamais un DELETE. La transition
-- inverse (réactivation) n'est pas encore justifiée par un besoin réel : elle
-- N'ENTRE PAS — si le besoin arrive, ce sera une migration signée, pas un
-- UPDATE de réflexe.
--
-- AUCUNE colonne téléphone, AUCUNE colonne profil : le chiffrement PII arrive
-- au LOT 2 avec sa gestion de clés — on ne pose pas une colonne « en
-- attendant ».
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

CREATE TYPE account_role AS ENUM (
  'ACCOUNT_HOLDER',
  'PLATFORM_STAFF',
  'PLATFORM_ADMIN'
);

CREATE TYPE account_status AS ENUM (
  'ACTIVE',
  'DEACTIVATED'   -- un statut, jamais une suppression (§3.10)
);

CREATE TABLE accounts (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  public_identifier text NOT NULL,
  role              account_role NOT NULL,
  status            account_status NOT NULL DEFAULT 'ACTIVE',
  deactivated_at    timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_accounts_public_identifier UNIQUE (public_identifier),
  -- 10 chiffres exactement, sans zéro de tête (lisible et dictable au guichet).
  CONSTRAINT chk_accounts_identifier_shape CHECK (public_identifier ~ '^[1-9][0-9]{9}$'),
  -- Le statut et son horodatage vivent et meurent ensemble.
  CONSTRAINT chk_accounts_deactivation_pair
    CHECK ((status = 'DEACTIVATED') = (deactivated_at IS NOT NULL))
);

-- Interdiction générique de DELETE, réutilisée par les tables des lots
-- suivants : on corrige par statut, jamais par suppression (§3.10).
CREATE FUNCTION forbid_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% : suppression interdite — corriger par statut (§3.10)', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

-- L'identité d'un compte est IMMUABLE (id, identifiant public, rôle, date de
-- création). Un changement de rôle n'est pas une transition posée en V1 : si
-- le besoin arrive (promotion staff), ce sera une migration signée qui ouvre
-- la transition — jamais un UPDATE qui passe parce que personne ne regardait.
CREATE FUNCTION guard_account_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.public_identifier IS DISTINCT FROM OLD.public_identifier
     OR NEW.role IS DISTINCT FROM OLD.role
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'accounts : identité immuable (id, public_identifier, role, created_at)';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT (OLD.status = 'ACTIVE' AND NEW.status = 'DEACTIVATED') THEN
    RAISE EXCEPTION 'accounts : % -> % interdit — la réactivation n''est pas une transition posée en V1',
      OLD.status, NEW.status;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_accounts_guard
  BEFORE UPDATE ON accounts
  FOR EACH ROW EXECUTE FUNCTION guard_account_update();

CREATE TRIGGER trg_accounts_no_delete
  BEFORE DELETE ON accounts
  FOR EACH ROW EXECUTE FUNCTION forbid_delete();

-- Le strict nécessaire (patron 001 : chaque table apporte SES droits dans SA
-- migration). L'UPDATE est accordé COLONNE PAR COLONNE : le service peut
-- désactiver, jamais toucher l'identité — même sans le trigger.
GRANT SELECT, INSERT ON accounts TO user_core_app;
GRANT UPDATE (status, deactivated_at) ON accounts TO user_core_app;
REVOKE DELETE, TRUNCATE ON accounts FROM user_core_app;
