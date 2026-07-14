import { createHash } from 'crypto';
import { Pool } from 'pg';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Le login de bout en bout, SERVICE SOUS RÔLE BRIDÉ, Postgres réel. Les
// propriétés C3/C8/C9 sont prouvées par COMPTAGE D'APPELS (espion), jamais
// par mesure de latence (CLAUDE.md §5).
describe('AuthService.login', () => {
  const config = testAuthAssembly(); // lockThreshold = 2
  let app: Pool;
  let owner: Pool;
  let provider: LocalAuthenticationProvider;
  let service: AuthService;
  let verifySpy: jest.SpyInstance;
  let accountSeq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    provider = new LocalAuthenticationProvider(config);
    await provider.init();
    service = new AuthService(app, provider, provider, config, new LoginThrottle(1000, 60));
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts');
  });

  beforeEach(() => {
    verifySpy = jest.spyOn(provider, 'verifySecret');
  });
  afterEach(() => {
    verifySpy.mockRestore();
  });

  afterAll(async () => {
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts');
    await app.end();
    await owner.end();
  });

  interface Fixture {
    accountId: string;
    identifier: string;
    secretId: string;
  }

  async function createAccountWithSecret(
    secret: string,
    options: { temporary?: boolean; expired?: boolean; deactivated?: boolean } = {},
  ): Promise<Fixture> {
    accountSeq += 1;
    const identifier = String(4000000000 + accountSeq);
    const temporary = options.temporary ?? false;
    // Chemin unique (011) : compte + premier secret naissent ensemble — la
    // fixture emprunte exactement le chemin du service.
    const accountId = await createAccountFixture(app, identifier, {
      secretHash: await provider.hashSecret(secret),
      isTemporary: temporary,
      expiresAt: temporary
        ? new Date(Date.now() + (options.expired ? -3600 : 3600) * 1000)
        : null,
    });
    const secretRow = firstRow(
      await app.query<{ id: string }>(
        "SELECT id FROM account_secrets WHERE account_id = $1",
        [accountId],
      ),
    );
    if (options.deactivated) {
      await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    }
    return { accountId, identifier, secretId: secretRow.id };
  }

  test('login OK → jetons émis, refresh HACHÉ en base (jamais la valeur), session ouverte', async () => {
    const f = await createAccountWithSecret('S3cret!');
    const result = await service.login(f.identifier, 'S3cret!', '10.0.0.1');
    if (result.outcome !== 'OK') {
      throw new Error(`OK attendu, reçu ${result.outcome}`);
    }
    expect(result.mustChangeSecret).toBe(false);

    // La valeur brute du refresh est INTROUVABLE en base ; son SHA-256 y est.
    const raw = await owner.query(
      'SELECT id FROM session_refresh_tokens WHERE token_hash = $1',
      [result.refreshToken],
    );
    expect(raw.rows).toHaveLength(0);
    const hashed = await owner.query<{ session_id: string }>(
      'SELECT session_id FROM session_refresh_tokens WHERE token_hash = $1',
      [createHash('sha256').update(result.refreshToken, 'utf8').digest('hex')],
    );
    expect(hashed.rows).toHaveLength(1);

    // Le jeton d'accès porte sub = uuid du compte et sid = la session créée.
    const claims = await provider.verifyAccessToken(result.accessToken);
    expect(claims?.sub).toBe(f.accountId);
    expect(claims?.sid).toBe(hashed.rows[0]?.session_id);

    const session = firstRow(
      await app.query<{ status: string; account_id: string }>(
        'SELECT status, account_id FROM sessions WHERE id = $1',
        [claims?.sid],
      ),
    );
    expect(session.status).toBe('ACTIVE');
    expect(session.account_id).toBe(f.accountId);
  });

  test('C3 — EXACTEMENT UNE vérification par tentative, sur TOUS les chemins', async () => {
    const f = await createAccountWithSecret('S3cret!');

    // Chemin « mauvais secret » : 1 appel, contre le vrai hash.
    await service.login(f.identifier, 'faux', '10.0.0.2');
    expect(verifySpy).toHaveBeenCalledTimes(1);

    // Chemin « compte inconnu » : 1 appel, contre le hash de référence.
    verifySpy.mockClear();
    const unknown = await service.login('9999999999', 'faux', '10.0.0.2');
    expect(unknown.outcome).toBe('FAILED');
    expect(verifySpy).toHaveBeenCalledTimes(1);
    expect(verifySpy).toHaveBeenCalledWith(provider.getReferenceHash(), 'faux');

    // Chemin « compte désactivé » : 1 appel, référence.
    verifySpy.mockClear();
    const off = await createAccountWithSecret('S3cret!', { deactivated: true });
    await service.login(off.identifier, 'S3cret!', '10.0.0.2');
    expect(verifySpy).toHaveBeenCalledTimes(1);
    expect(verifySpy).toHaveBeenCalledWith(provider.getReferenceHash(), 'S3cret!');

    // Chemin « succès » : 1 appel aussi.
    verifySpy.mockClear();
    await service.login(f.identifier, 'S3cret!', '10.0.0.2');
    expect(verifySpy).toHaveBeenCalledTimes(1);
  });

  test('C8/C9 — verrouillage au seuil ; verrouillé, le hash réel n\'est plus JAMAIS lu', async () => {
    const f = await createAccountWithSecret('S3cret!');

    // lockThreshold = 2 : deux échecs déclenchent le verrou.
    await service.login(f.identifier, 'faux', '10.0.0.3');
    await service.login(f.identifier, 'faux', '10.0.0.3');

    const locked = firstRow(
      await app.query<{ failed_attempts: number; lock_seconds: number }>(
        `SELECT failed_attempts,
                EXTRACT(EPOCH FROM (locked_until - now()))::float AS lock_seconds
         FROM account_secrets WHERE id = $1`,
        [f.secretId],
      ),
    );
    expect(locked.failed_attempts).toBe(2);
    expect(locked.lock_seconds).toBeGreaterThan(0);
    expect(locked.lock_seconds).toBeLessThanOrEqual(config.lockBaseSeconds);

    // Verrouillé + BON secret → échec quand même, et l'unique vérification
    // est contre la RÉFÉRENCE : la vue C9 a caché le vrai hash. Structurel.
    verifySpy.mockClear();
    const attempt = await service.login(f.identifier, 'S3cret!', '10.0.0.3');
    expect(attempt.outcome).toBe('FAILED');
    expect(verifySpy).toHaveBeenCalledTimes(1);
    expect(verifySpy).toHaveBeenCalledWith(provider.getReferenceHash(), 'S3cret!');
  });

  test('succès → le compteur d\'échecs retombe à 0 (C8 : la seule décrue permise)', async () => {
    const f = await createAccountWithSecret('S3cret!');
    await service.login(f.identifier, 'faux', '10.0.0.4');
    const success = await service.login(f.identifier, 'S3cret!', '10.0.0.4');
    expect(success.outcome).toBe('OK');
    const row = firstRow(
      await app.query<{ failed_attempts: number }>(
        'SELECT failed_attempts FROM account_secrets WHERE id = $1',
        [f.secretId],
      ),
    );
    expect(row.failed_attempts).toBe(0);
  });

  test('secret provisoire : valide → OK avec mustChangeSecret ; expiré → échec par la référence', async () => {
    const valid = await createAccountWithSecret('Temp0raire', { temporary: true });
    const ok = await service.login(valid.identifier, 'Temp0raire', '10.0.0.5');
    if (ok.outcome !== 'OK') {
      throw new Error(`OK attendu, reçu ${ok.outcome}`);
    }
    expect(ok.mustChangeSecret).toBe(true);

    const expired = await createAccountWithSecret('Temp0raire', { temporary: true, expired: true });
    verifySpy.mockClear();
    const ko = await service.login(expired.identifier, 'Temp0raire', '10.0.0.5');
    expect(ko.outcome).toBe('FAILED');
    expect(verifySpy).toHaveBeenCalledWith(provider.getReferenceHash(), 'Temp0raire');
  });

  test('throttle : au plafond → THROTTLED et ZÉRO vérification (le coût argon2 est plafonné)', async () => {
    const throttled = new AuthService(app, provider, provider, config, new LoginThrottle(2, 60));
    const f = await createAccountWithSecret('S3cret!');
    await throttled.login(f.identifier, 'faux', '10.9.9.9');
    await throttled.login(f.identifier, 'faux', '10.9.9.9');
    verifySpy.mockClear();
    const result = await throttled.login(f.identifier, 'faux', '10.9.9.9');
    expect(result.outcome).toBe('THROTTLED');
    expect(verifySpy).toHaveBeenCalledTimes(0);
  });

  test('zéro PII — aucune console n\'est touchée, ni identifiant ni secret nulle part', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const f = await createAccountWithSecret('S3cretPII!');
      await service.login(f.identifier, 'faux', '10.0.0.6');
      await service.login(f.identifier, 'S3cretPII!', '10.0.0.6');
      await service.login('0000000000', 'S3cretPII!', '10.0.0.6');
      const allCalls = [...logSpy.mock.calls, ...errorSpy.mock.calls, ...warnSpy.mock.calls]
        .flat()
        .map(String)
        .join(' ');
      expect(allCalls).not.toContain(f.identifier);
      expect(allCalls).not.toContain('S3cretPII!');
    } finally {
      logSpy.mockRestore();
      errorSpy.mockRestore();
      warnSpy.mockRestore();
    }
  });
});
