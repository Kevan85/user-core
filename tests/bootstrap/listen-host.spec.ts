import { ConfigViolations } from '../../src/bootstrap/assembly';
import { LISTEN_HOST_VARIABLE, assembleListenHostFromEnv } from '../../src/bootstrap/listen-host';

/**
 * LE MUR DE L'ÉCOUTE — et les tests qui le prouvent POUR LUI-MÊME (leçon ⑮) : toutes
 * les autres suites tournent sous murs relâchés, où l'absence garde l'écoute d'avant.
 * Que main.ts l'APPELLE et BRANCHE sa valeur, c'est main-boot.spec.ts qui le prouve.
 */
const ARMED = { NODE_ENV: 'production' };

function declare(value: string, base: NodeJS.ProcessEnv = ARMED): NodeJS.ProcessEnv {
  return { ...base, [LISTEN_HOST_VARIABLE]: value };
}

function refusalOf(env: NodeJS.ProcessEnv): string {
  try {
    assembleListenHostFromEnv(env);
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigViolations);
    return err instanceof Error ? err.message : String(err);
  }
  return '(aucun refus)';
}

describe('sous murs armés, l’écoute se DÉCLARE', () => {
  test('variable absente ⇒ refus qui nomme la variable et la conséquence', () => {
    const message = refusalOf(ARMED);
    expect(message).toContain(LISTEN_HOST_VARIABLE);
    expect(message).toContain('exposerait le port');
  });

  test.each(['', '   '])('valeur « %s » ⇒ refus : une valeur oubliée s’écrit pareil', (value) => {
    expect(refusalOf(declare(value))).toContain(LISTEN_HOST_VARIABLE);
  });

  test.each(['127.0.0.1', '::1', '0.0.0.0', '::'])('« %s » ⇒ écoute déclarée', (value) => {
    expect(assembleListenHostFromEnv(declare(value))).toEqual({ host: value });
  });
});

describe('dans tous les modes, seul un littéral IP passe', () => {
  test.each(['localhost', 'example.org', '1', '127.1', '[::1]', '127.0.0.1:3000', '127.0.0.1,::1'])(
    '« %s » ⇒ refus, en murs armés comme relâchés',
    (value) => {
      expect(refusalOf(declare(value))).toContain(`« ${value} »`);
      expect(refusalOf(declare(value, { NODE_ENV: 'development' }))).toContain(LISTEN_HOST_VARIABLE);
    },
  );
});

describe('F1 — le mode permissif se DÉCLARE : NODE_ENV absent, vide ou mal écrit arme le mur', () => {
  test.each([[{}], [{ NODE_ENV: '' }], [{ NODE_ENV: 'produciton' }], [{ NODE_ENV: 'staging' }]])(
    '%j sans la variable ⇒ refus',
    (env) => {
      expect(refusalOf(env)).toContain(LISTEN_HOST_VARIABLE);
    },
  );
});

describe('CONTRÔLE NÉGATIF — murs relâchés', () => {
  test.each(['development', 'test'])('%s : variable absente ⇒ toutes les interfaces, l’écoute d’avant', (NODE_ENV) => {
    expect(assembleListenHostFromEnv({ NODE_ENV })).toEqual({ host: undefined });
  });
});
