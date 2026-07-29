import { randomBytes } from 'crypto';
import { ConfigViolations, productionWallsArmed } from '../../src/bootstrap/assembly';
import {
  assertProductionSecretsNotPublic,
  readEnvExample,
} from '../../src/bootstrap/production-secrets';

/**
 * Le mur anti-secrets-publics (étape 3, arbitrage C8) : tout secret présent
 * dans .env.example est public par construction — en production, s'en servir
 * refuse le boot. Tests unitaires, lecteur injecté ; le DERNIER test joue
 * contre le VRAI fichier du dépôt (le mur et sa liste vivent ensemble).
 */
const EXAMPLE = [
  'DATABASE_URL=postgres://user_core_app:mot_de_passe_dev_publie@localhost:5435/user_core',
  'PORT=3000',
  'USER_CORE_APP_PASSWORD=mot_de_passe_dev_publie',
  'AUTH_ACCESS_TOKEN_TTL_SECONDS=900',
  'USER_CORE_REF_HMAC_KEYS={"R1":"VALEUR_EXEMPLE_PUBLIEE_BASE64"}',
  'USER_CORE_REF_HMAC_ACTIVE_KEY_ID=R1',
].join('\n');

const readFake = (): string => EXAMPLE;

function freshSecret(): string {
  return randomBytes(24).toString('base64');
}

describe('productionWallsArmed — F1 : le mode permissif se déclare', () => {
  test('seuls development et test relâchent les murs', () => {
    expect(productionWallsArmed({ NODE_ENV: 'development' })).toBe(false);
    expect(productionWallsArmed({ NODE_ENV: 'test' })).toBe(false);
  });

  test('absent, vide, faute de frappe, staging, production : les murs s\'ARMENT', () => {
    expect(productionWallsArmed({})).toBe(true);
    expect(productionWallsArmed({ NODE_ENV: '' })).toBe(true);
    expect(productionWallsArmed({ NODE_ENV: 'produciton' })).toBe(true); // la faute de frappe du manifeste
    expect(productionWallsArmed({ NODE_ENV: 'staging' })).toBe(true);
    expect(productionWallsArmed({ NODE_ENV: 'production' })).toBe(true);
  });
});

describe('assertProductionSecretsNotPublic — C8', () => {
  test('mode permissif DÉCLARÉ : aucun contrôle — le dev boote avec les valeurs publiées', () => {
    expect(() =>
      assertProductionSecretsNotPublic(
        { NODE_ENV: 'test', USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      ),
    ).not.toThrow();
    expect(() =>
      assertProductionSecretsNotPublic(
        { NODE_ENV: 'development', USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      ),
    ).not.toThrow();
  });

  test('F1 : NODE_ENV absent ou mal orthographié → le mur JOUE (jamais désarmé en silence)', () => {
    expect(() =>
      assertProductionSecretsNotPublic(
        { USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      ),
    ).toThrow(ConfigViolations);
    expect(() =>
      assertProductionSecretsNotPublic(
        { NODE_ENV: 'produciton', USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      ),
    ).toThrow(ConfigViolations);
  });

  test('production + valeur publiée sur un nom à signature de secret → refus', () => {
    expect(() =>
      assertProductionSecretsNotPublic(
        { NODE_ENV: 'production', USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      ),
    ).toThrow(ConfigViolations);
    expect(() =>
      assertProductionSecretsNotPublic(
        { NODE_ENV: 'production', USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      ),
    ).toThrow(/public par construction/);
  });

  test('production + URL remaniée mais mot de passe publié GARDÉ → refus (la sous-chaîne, pas l\'égalité)', () => {
    expect(() =>
      assertProductionSecretsNotPublic(
        {
          NODE_ENV: 'production',
          DATABASE_URL:
            'postgres://user_core_app:mot_de_passe_dev_publie@db.interne.example:5432/user_core',
        },
        readFake,
      ),
    ).toThrow(/mot de passe de l'URL/);
  });

  test('production + valeurs fraîches → boote', () => {
    expect(() =>
      assertProductionSecretsNotPublic(
        {
          NODE_ENV: 'production',
          DATABASE_URL: `postgres://user_core_app:${freshSecret().replace(/[/+=]/g, 'x')}@db.interne.example:5432/user_core`,
          USER_CORE_APP_PASSWORD: freshSecret(),
        },
        readFake,
      ),
    ).not.toThrow();
  });

  test('les valeurs publiées NON secrètes ne mordent pas : un réglage identique (PORT, TTL) et un identifiant de clé (R1) bootent', () => {
    expect(() =>
      assertProductionSecretsNotPublic(
        {
          NODE_ENV: 'production',
          PORT: '3000',
          AUTH_ACCESS_TOKEN_TTL_SECONDS: '900',
          USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
        },
        readFake,
      ),
    ).not.toThrow();
  });

  test('production + .env.example illisible → refus FAIL-CLOSED, jamais « rien à vérifier »', () => {
    expect(() =>
      assertProductionSecretsNotPublic({ NODE_ENV: 'production' }, () => null),
    ).toThrow(/ne peut pas rendre son verdict/);
  });

  test('le message d\'une violation porte le NOM de la variable, jamais la valeur', () => {
    try {
      assertProductionSecretsNotPublic(
        { NODE_ENV: 'production', USER_CORE_APP_PASSWORD: 'mot_de_passe_dev_publie' },
        readFake,
      );
      throw new Error('un refus était attendu');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain('USER_CORE_APP_PASSWORD');
      expect(message).not.toContain('mot_de_passe_dev_publie');
    }
  });

  test('CONTRE LE VRAI FICHIER : les valeurs de dev du dépôt refusent de booter en production', () => {
    const example = readEnvExample();
    expect(example).not.toBeNull(); // le fichier est versionné avec le service

    // Le .env.example réel publie le mot de passe du rôle applicatif de dev :
    // l'employer en production — même dans une URL remaniée — refuse.
    expect(() =>
      assertProductionSecretsNotPublic({
        NODE_ENV: 'production',
        DATABASE_URL: 'postgres://user_core_app:user_core_app_dev_only@db.prod.interne:5432/user_core',
      }),
    ).toThrow(/public par construction|mot de passe de l'URL/);

    // Et des valeurs fraîches passent le mur du vrai fichier.
    expect(() =>
      assertProductionSecretsNotPublic({
        NODE_ENV: 'production',
        DATABASE_URL: `postgres://user_core_app:${freshSecret().replace(/[/+=]/g, 'x')}@db.prod.interne:5432/user_core`,
      }),
    ).not.toThrow();
  });
});
