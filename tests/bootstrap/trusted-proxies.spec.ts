import { ConfigViolations } from '../../src/bootstrap/assembly';
import {
  NO_TRUSTED_PROXY,
  TRUSTED_PROXIES_VARIABLE,
  assembleTrustedProxiesFromEnv,
} from '../../src/bootstrap/trusted-proxies';

/**
 * LE MUR DE L'AIGUILLEUR — et les tests qui le prouvent POUR LUI-MÊME (leçon ⑮).
 * Quel test rougirait si l'on retirait le mur ce soir ? Ceux-ci : les 572 autres
 * tournent sous murs relâchés, où l'absence vaut NONE.
 */
const ARMED = { NODE_ENV: 'production' };

function declare(value: string, base: NodeJS.ProcessEnv = ARMED): NodeJS.ProcessEnv {
  return { ...base, [TRUSTED_PROXIES_VARIABLE]: value };
}

function refusalOf(env: NodeJS.ProcessEnv): string {
  try {
    assembleTrustedProxiesFromEnv(env);
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigViolations);
    return err instanceof Error ? err.message : String(err);
  }
  return '(aucun refus)';
}

describe('sous murs armés, aucun des deux défauts n’est sûr : le défaut est le REFUS', () => {
  test('variable absente ⇒ refus qui nomme la variable, NONE, et les deux façons d’échouer', () => {
    const message = refusalOf(ARMED);
    expect(message).toContain(TRUSTED_PROXIES_VARIABLE);
    expect(message).toContain(NO_TRUSTED_PROXY);
    expect(message).toContain('plafond global');
    expect(message).toContain('contourne');
  });

  test.each(['', '   ', ',', ' , ,'])('valeur « %s » ⇒ refus : une valeur oubliée s’écrit pareil', (value) => {
    expect(refusalOf(declare(value))).toContain(TRUSTED_PROXIES_VARIABLE);
  });

  test('NONE ⇒ aucun aiguilleur, DÉCLARÉ : la socket fait foi', () => {
    const proxies = assembleTrustedProxiesFromEnv(declare(NO_TRUSTED_PROXY));
    expect(proxies.declared).toEqual([]);
    expect(proxies.trust('127.0.0.1', 0)).toBe(false);
    expect(proxies.trust('::ffff:127.0.0.1', 0)).toBe(false);
    expect(proxies.armed).toBe(true);
  });

  test('NONE mêlé à des adresses ⇒ refus : contradiction', () => {
    expect(refusalOf(declare(`${NO_TRUSTED_PROXY},127.0.0.1`))).toContain('contradiction');
  });

  test('« none » en minuscules n’est pas NONE ⇒ refus', () => {
    expect(refusalOf(declare('none'))).toContain('« none »');
  });

  test('une liste valide ⇒ compilée, et l’aiguilleur local est reconnu sous sa forme double pile', () => {
    const proxies = assembleTrustedProxiesFromEnv(declare(' 127.0.0.1 , ::1 '));
    expect(proxies.declared).toEqual(['127.0.0.1', '::1']);
    expect(proxies.trust('::ffff:127.0.0.1', 0)).toBe(true);
    expect(proxies.trust('203.0.113.7', 0)).toBe(false);
  });

  test('les violations du point unique arrivent d’un bloc, préfixées du nom de la variable', () => {
    const message = refusalOf(declare('1,true'));
    expect(message).toContain(`${TRUSTED_PROXIES_VARIABLE} : « 1 »`);
    expect(message).toContain(`${TRUSTED_PROXIES_VARIABLE} : « true »`);
  });

  test('une liste trop large est refusée par le détecteur de fumée', () => {
    expect(refusalOf(declare('0.0.0.0/1,128.0.0.0/1'))).toContain('trop large');
  });
});

describe('F1 — le mode permissif se DÉCLARE : NODE_ENV absent, vide ou mal écrit arme le mur', () => {
  test.each([[{}], [{ NODE_ENV: '' }], [{ NODE_ENV: 'produciton' }], [{ NODE_ENV: 'staging' }]])(
    '%j sans la variable ⇒ refus',
    (env) => {
      expect(refusalOf(env)).toContain(TRUSTED_PROXIES_VARIABLE);
    },
  );
});

describe('CONTRÔLE NÉGATIF — murs relâchés', () => {
  test.each(['development', 'test'])('%s : variable absente ⇒ aucun aiguilleur, en silence', (NODE_ENV) => {
    const proxies = assembleTrustedProxiesFromEnv({ NODE_ENV });
    expect(proxies.declared).toEqual([]);
    expect(proxies.armed).toBe(false);
    expect(proxies.trust('127.0.0.1', 0)).toBe(false);
  });

  test('une valeur DÉCLARÉE est validée dans tous les modes : une faute de frappe se dit tout de suite', () => {
    expect(refusalOf(declare('1', { NODE_ENV: 'development' }))).toContain('« 1 »');
  });
});
