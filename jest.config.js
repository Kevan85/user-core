/**
 * Les tests d'invariants tournent contre un VRAI Postgres migré — jamais de
 * mock de la base (CLAUDE.md §5). Ils partagent une seule base et se nettoient
 * par TRUNCATE : exécution sérialisée obligatoire (maxWorkers: 1).
 */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  globalSetup: '<rootDir>/tests/global-setup.ts',
  setupFiles: ['dotenv/config'],
  testTimeout: 30000,
  maxWorkers: 1,
};
