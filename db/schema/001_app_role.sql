-- =============================================================================
-- 001 — Rôle applicatif user_core_app : bridé dès le premier jour.
-- Le service se connecte TOUJOURS avec ce rôle, jamais en owner : les REVOKE
-- au niveau du rôle sont la ceinture des triggers append-only à venir (un
-- trigger row-level ne bloque pas TRUNCATE — le REVOKE si).
--
-- Chaque future table apporte SES GRANT/REVOKE dans SA propre migration
-- (patron payment-core 003_app_role_grants.sql) — jamais un fichier de grants
-- de fin de série qu'on oublie de mettre à jour.
--
-- Aucun mot de passe ici : il se pose hors migration — dev/CI : ALTER ROLE
-- dans le harnais de test ; prod : Vault. Une migration est committée, un
-- secret jamais.
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

-- CREATE ROLE n'a pas de IF NOT EXISTS : bloc DO idempotent.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'user_core_app') THEN
    CREATE ROLE user_core_app LOGIN;
  END IF;
END
$$;

-- Le nom de la base varie selon l'environnement : GRANT dynamique.
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO user_core_app', current_database());
END
$$;

GRANT USAGE ON SCHEMA public TO user_core_app;

-- La table du runner n'appartient qu'au rôle d'administration : aucun droit.
REVOKE ALL ON schema_migrations FROM user_core_app;
