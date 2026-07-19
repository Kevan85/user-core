import { Pool } from 'pg';
import { RegistrationService } from '../../src/accounts/registration.service';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// L'inscription publique, SOUS RÔLE BRIDÉ, contre le vrai Postgres : le
// compte naît par create_account() (le chemin unique), la première session
// par le chemin du login, et rien ne s'invente en cas de collision — on
// re-tire, la base tranche.
describe('RegistrationService', () => {
  const config = testAuthAssembly();
  let app: Pool;
  let owner: Pool;
  let provider: LocalAuthenticationProvider;
  let auth: AuthService;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    provider = new LocalAuthenticationProvider(config);
    await provider.init();
    auth = new AuthService(app, provider, provider, config, new LoginThrottle(1000, 60));
  });

  beforeEach(async () => {
    await truncateTables(
      owner,
      'session_refresh_tokens',
      'sessions',
      'account_secrets',
      'accounts',
      'persons',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  function service(
    throttle = new LoginThrottle(1000, 60),
    generator?: () => string,
    personGenerator?: () => string,
  ): RegistrationService {
    return new RegistrationService(
      app,
      provider,
      auth,
      config,
      throttle,
      generator,
      personGenerator,
    );
  }

  async function accountCount(): Promise<number> {
    return Number(
      firstRow(await owner.query<{ n: string }>('SELECT count(*) AS n FROM accounts')).n,
    );
  }

  test('inscription → compte + secret + session nés, et le LOGIN fonctionne avec ce qui est rendu', async () => {
    const result = await service().register('S3cretChoisi!', '10.1.0.1');
    if (result.outcome !== 'OK') {
      throw new Error(`OK attendu, reçu ${result.outcome}`);
    }
    expect(result.identifier).toMatch(/^[1-9][0-9]{9}$/);

    // Compte + secret nés ensemble (le chemin unique de 011).
    const account = firstRow(
      await owner.query<{ status: string; role: string }>(
        'SELECT status, role FROM accounts WHERE id = $1',
        [result.accountId],
      ),
    );
    expect(account).toEqual({ status: 'ACTIVE', role: 'ACCOUNT_HOLDER' });
    const secrets = await owner.query(
      "SELECT id FROM account_secrets WHERE account_id = $1 AND status = 'ACTIVE'",
      [result.accountId],
    );
    expect(secrets.rows).toHaveLength(1);

    // Depuis 016 : la PERSONNE est née avec le compte — nue (minimisation),
    // avec son sel d'effacement, rattachée de façon immuable.
    const person = firstRow(
      await owner.query<{ id: string; enc_key_id: string | null; birth_year: number | null }>(
        `SELECT p.id, p.enc_key_id, p.birth_year FROM persons p
          JOIN accounts a ON a.person_id = p.id WHERE a.id = $1`,
        [result.accountId],
      ),
    );
    expect(person.id).toBe(result.personId);
    expect(person.enc_key_id).toBeNull();
    expect(person.birth_year).toBeNull();

    // La session rendue est réelle et ACTIVE.
    const claims = await provider.verifyAccessToken(result.accessToken);
    expect(claims?.sub).toBe(result.accountId);
    const session = firstRow(
      await owner.query<{ status: string }>('SELECT status FROM sessions WHERE id = $1', [
        claims?.sid,
      ]),
    );
    expect(session.status).toBe('ACTIVE');

    // Et la boucle se ferme : login avec l'identifiant généré + le secret choisi.
    const login = await auth.login(result.identifier, 'S3cretChoisi!', '10.1.0.2');
    expect(login.outcome).toBe('OK');
  });

  test('secret trop court → refus PROPRE avant tout coût, AUCUN compte créé', async () => {
    const result = await service().register('court', '10.1.0.3');
    expect(result).toEqual({ outcome: 'SECRET_TOO_SHORT', minLength: config.secretMinLength });
    expect(await accountCount()).toBe(0);
  });

  test('throttle par IP SEULE : la 3e tentative de la même IP tombe, une AUTRE IP passe', async () => {
    const throttled = service(new LoginThrottle(2, 60));
    expect((await throttled.register('S3cretChoisi!', '10.1.0.4')).outcome).toBe('OK');
    expect((await throttled.register('S3cretChoisi!', '10.1.0.4')).outcome).toBe('OK');
    expect((await throttled.register('S3cretChoisi!', '10.1.0.4')).outcome).toBe('THROTTLED');
    // Pas un plafond GLOBAL : une autre IP garde son budget.
    expect((await throttled.register('S3cretChoisi!', '10.1.0.5')).outcome).toBe('OK');
    expect(await accountCount()).toBe(3);
  });

  test('collision d\'identifiant → re-tirage silencieux, la base tranche l\'unicité', async () => {
    const first = await service().register('S3cretChoisi!', '10.1.0.6');
    if (first.outcome !== 'OK') throw new Error('OK attendu');

    // Générateur piégé : rend D'ABORD l'identifiant déjà pris, puis un libre.
    const draws = [first.identifier, '9999999999'];
    let calls = 0;
    const collided = await service(undefined, () => {
      const value = draws[Math.min(calls, draws.length - 1)]!;
      calls += 1;
      return value;
    }).register('AutreS3cret!', '10.1.0.7');

    if (collided.outcome !== 'OK') throw new Error('OK attendu après re-tirage');
    expect(calls).toBe(2);
    expect(collided.identifier).toBe('9999999999');
    expect(await accountCount()).toBe(2);
  });

  test("collision de l'identifiant de PERSONNE → seul l'identifiant de personne est re-tiré", async () => {
    const first = await service().register('S3cretChoisi!', '10.1.0.10');
    if (first.outcome !== 'OK') throw new Error('OK attendu');
    const taken = firstRow(
      await owner.query<{ public_identifier: string }>(
        'SELECT public_identifier FROM persons WHERE id = $1',
        [first.personId],
      ),
    ).public_identifier;

    const personDraws = [taken, '9999999998'];
    let personCalls = 0;
    let accountCalls = 0;
    const collided = await service(
      undefined,
      () => {
        accountCalls += 1;
        return String(9_100_000_000 + accountCalls);
      },
      () => {
        const value = personDraws[Math.min(personCalls, personDraws.length - 1)]!;
        personCalls += 1;
        return value;
      },
    ).register('AutreS3cret!', '10.1.0.11');

    if (collided.outcome !== 'OK') throw new Error('OK attendu après re-tirage');
    expect(personCalls).toBe(2); // le tirage en collision, puis le libre
    expect(accountCalls).toBe(1); // l'identifiant de COMPTE n'est pas re-tiré
  });

  test('tirages épuisés (générateur cassé) → échec BRUYANT, aucun compte fantôme', async () => {
    const first = await service().register('S3cretChoisi!', '10.1.0.8');
    if (first.outcome !== 'OK') throw new Error('OK attendu');

    await expect(
      service(undefined, () => first.identifier).register('AutreS3cret!', '10.1.0.9'),
    ).rejects.toThrow(/identifiant unique introuvable/);
    expect(await accountCount()).toBe(1);
  });
});
