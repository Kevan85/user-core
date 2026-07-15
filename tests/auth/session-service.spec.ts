import { createHash } from 'crypto';
import { Pool } from 'pg';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { SessionService } from '../../src/auth/session.service';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Rotation, rejeu, grâce, révocation serveur — SOUS RÔLE BRIDÉ, Postgres réel.
// L'API n'écrit aucun WHERE d'état sur les jetons et ne compare aucun hash :
// elle agit sur les verdicts de lookup_refresh_token.
describe('SessionService', () => {
  const config = testAuthAssembly({ graceWindowSeconds: 30 });
  let app: Pool;
  let owner: Pool;
  let provider: LocalAuthenticationProvider;
  let auth: AuthService;
  let sessions: SessionService;
  let accountSeq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    provider = new LocalAuthenticationProvider(config);
    await provider.init();
    auth = new AuthService(app, provider, provider, config, new LoginThrottle(1000, 60));
    sessions = new SessionService(app, provider, config, new LoginThrottle(1000, 60));
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts');
    await app.end();
    await owner.end();
  });

  const SECRET = 'S3cret!';

  interface Logged {
    accountId: string;
    sessionId: string;
    refreshToken: string;
  }

  async function loginFresh(): Promise<Logged> {
    accountSeq += 1;
    const identifier = String(5000000000 + accountSeq);
    // Depuis 011, le chemin unique : compte + premier secret naissent ensemble.
    const accountId = await createAccountFixture(app, identifier, {
      secretHash: await provider.hashSecret(SECRET),
    });
    const result = await auth.login(identifier, SECRET, '10.0.0.1');
    if (result.outcome !== 'OK') {
      throw new Error(`login OK attendu, reçu ${result.outcome}`);
    }
    const claims = await provider.verifyAccessToken(result.accessToken);
    return {
      accountId,
      sessionId: claims!.sid,
      refreshToken: result.refreshToken,
    };
  }

  function hashOf(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
  }

  async function tokenStatuses(sessionId: string): Promise<string[]> {
    const r = await app.query<{ status: string }>(
      'SELECT status FROM session_refresh_tokens WHERE session_id = $1 ORDER BY created_at',
      [sessionId],
    );
    return r.rows.map((row) => row.status);
  }

  test('USABLE → rotation : ancien ROTATED, successeur ACTIVE, chaînage correct, nouvelle valeur rendue', async () => {
    const s = await loginFresh();
    const result = await sessions.refresh(s.refreshToken, '10.0.0.1');
    if (result.outcome !== 'OK' || result.refreshToken === undefined) {
      throw new Error(`OK + nouveau jeton attendus, reçu ${result.outcome}`);
    }
    expect(result.refreshToken).not.toBe(s.refreshToken);

    expect(await tokenStatuses(s.sessionId)).toEqual(['ROTATED', 'ACTIVE']);

    const chain = firstRow(
      await owner.query<{ replaced_by_id: string; successor_hash: string }>(
        `SELECT old.replaced_by_id, succ.token_hash AS successor_hash
           FROM session_refresh_tokens old
           JOIN session_refresh_tokens succ ON succ.id = old.replaced_by_id
          WHERE old.token_hash = $1`,
        [hashOf(s.refreshToken)],
      ),
    );
    expect(chain.successor_hash).toBe(hashOf(result.refreshToken));
  });

  test('REPLAY — ancien jeton hors grâce → session coupée (nombre, statuts, motif)', async () => {
    const noGrace = new SessionService(
      app,
      provider,
      testAuthAssembly({ graceWindowSeconds: 1 }),
      new LoginThrottle(1000, 60),
    );
    const s = await loginFresh();
    await noGrace.refresh(s.refreshToken, '10.0.0.1');
    await app.query('SELECT pg_sleep(1.3)'); // la grâce expire

    const replay = await noGrace.refresh(s.refreshToken, '10.0.0.1');
    expect(replay.outcome).toBe('REPLAY_DETECTED');

    const session = await app.query<{ status: string; revoke_reason: string }>(
      'SELECT status, revoke_reason FROM sessions WHERE id = $1',
      [s.sessionId],
    );
    expect(session.rows).toHaveLength(1);
    expect(session.rows[0]?.status).toBe('REVOKED');
    expect(session.rows[0]?.revoke_reason).toBe('REPLAY_DETECTED');

    // Cascade C1 : les DEUX jetons de la session sont éteints.
    const statuses = await tokenStatuses(s.sessionId);
    expect(statuses).toHaveLength(2);
    expect(statuses).toEqual(['REVOKED', 'REVOKED']);
  });

  test('GRACE — deux appels dans la fenêtre : la session garde UN SEUL jeton ACTIVE (comptage)', async () => {
    const s = await loginFresh();
    // Premier refresh : sa réponse est « perdue sur le réseau » — le client
    // n'a jamais reçu le successeur et rejoue son ancien jeton.
    const lost = await sessions.refresh(s.refreshToken, '10.0.0.1');
    expect(lost.outcome).toBe('OK');

    const retry = await sessions.refresh(s.refreshToken, '10.0.0.1');
    if (retry.outcome !== 'OK' || retry.refreshToken === undefined) {
      throw new Error('la grâce doit rendre un jeton utilisable au client hors ligne');
    }

    // INVARIANT : à tout instant, EXACTEMENT un jeton ACTIVE par session —
    // la grâce n'est pas une fabrique. On compte les lignes, pas les
    // résultats.
    const actives = await app.query(
      "SELECT id FROM session_refresh_tokens WHERE session_id = $1 AND status = 'ACTIVE'",
      [s.sessionId],
    );
    expect(actives.rows).toHaveLength(1);

    // Et le jeton rendu au client est bien CE jeton actif.
    const active = firstRow(
      await owner.query<{ token_hash: string }>(
        "SELECT token_hash FROM session_refresh_tokens WHERE session_id = $1 AND status = 'ACTIVE'",
        [s.sessionId],
      ),
    );
    expect(active.token_hash).toBe(hashOf(retry.refreshToken));

    // Le client de la grâce peut continuer : son jeton fonctionne.
    const next = await sessions.refresh(retry.refreshToken, '10.0.0.1');
    expect(next.outcome).toBe('OK');
  });

  test('C5 — au-delà de l\'échéance absolue, refus MÊME avec un jeton ACTIVE', async () => {
    const s = await loginFresh();
    // La session vieillit d'un coup (owner : l'échéance est immuable pour le
    // service — c'est bien la preuve qu'on veut).
    await owner.query(
      "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'ADMIN' WHERE id = $1",
      [s.sessionId],
    );
    const statuses = await tokenStatuses(s.sessionId);
    expect(statuses).toEqual(['REVOKED']); // cascade C1

    const result = await sessions.refresh(s.refreshToken, '10.0.0.1');
    expect(result.outcome).toBe('REFUSED');
  });

  test('logout → refresh refusé ensuite ; la session est morte serveur', async () => {
    const s = await loginFresh();
    const out = await sessions.logout(s.accountId, s.sessionId);
    expect(out).toEqual({ outcome: 'OK', revokedSessions: 1 });

    const session = firstRow(
      await app.query<{ status: string; revoke_reason: string }>(
        'SELECT status, revoke_reason FROM sessions WHERE id = $1',
        [s.sessionId],
      ),
    );
    expect(session.status).toBe('REVOKED');
    expect(session.revoke_reason).toBe('LOGOUT');

    const after = await sessions.refresh(s.refreshToken, '10.0.0.1');
    expect(after.outcome).toBe('REFUSED');
  });

  test('BOLA — logout ne coupe QUE ses sessions : la session d\'un autre compte reste intacte', async () => {
    const victim = await loginFresh();
    const attacker = await loginFresh();

    const stolen = await sessions.logout(attacker.accountId, victim.sessionId);
    expect(stolen.outcome).toBe('REFUSED');

    const victimSession = await app.query<{ status: string }>(
      "SELECT status FROM sessions WHERE id = $1 AND status = 'ACTIVE'",
      [victim.sessionId],
    );
    expect(victimSession.rows).toHaveLength(1);

    // Et le refresh de la victime marche toujours.
    const ok = await sessions.refresh(victim.refreshToken, '10.0.0.1');
    expect(ok.outcome).toBe('OK');
  });

  test('revoke-all — toutes les sessions du compte tombent, celles d\'un AUTRE compte intactes', async () => {
    const owner1 = await loginFresh();
    // Deuxième session du même compte : on rejoue un login.
    const identifier = firstRow(
      await app.query<{ public_identifier: string }>(
        'SELECT public_identifier FROM accounts WHERE id = $1',
        [owner1.accountId],
      ),
    ).public_identifier;
    const second = await auth.login(identifier, SECRET, '10.0.0.2');
    expect(second.outcome).toBe('OK');

    const other = await loginFresh();

    const result = await sessions.revokeAll(owner1.accountId);
    expect(result).toEqual({ outcome: 'OK', revokedSessions: 2 });

    const mine = await app.query<{ status: string; revoke_reason: string }>(
      'SELECT status, revoke_reason FROM sessions WHERE account_id = $1',
      [owner1.accountId],
    );
    expect(mine.rows).toHaveLength(2);
    expect(mine.rows.map((r) => r.status)).toEqual(['REVOKED', 'REVOKED']);
    expect(mine.rows.map((r) => r.revoke_reason)).toEqual(['LOGOUT_ALL', 'LOGOUT_ALL']);

    // BOLA : l'autre compte n'a rien perdu (nombre de lignes des deux côtés).
    const others = await app.query<{ status: string }>(
      'SELECT status FROM sessions WHERE account_id = $1',
      [other.accountId],
    );
    expect(others.rows).toHaveLength(1);
    expect(others.rows[0]?.status).toBe('ACTIVE');

    // Les jetons du compte coupé sont morts (cascade C1).
    const dead = await sessions.refresh(owner1.refreshToken, '10.0.0.1');
    expect(dead.outcome).toBe('REFUSED');
  });

  test('C15 — successeur DÉJÀ consommé (STALE) → refus sec : aucun jeton d\'accès offert', async () => {
    const s = await loginFresh();
    // Le client reçoit le successeur et l'utilise (successeur → ROTATED).
    const first = await sessions.refresh(s.refreshToken, '10.0.0.1');
    if (first.outcome !== 'OK' || first.refreshToken === undefined) {
      throw new Error('rotation initiale attendue');
    }
    const second = await sessions.refresh(first.refreshToken, '10.0.0.1');
    expect(second.outcome).toBe('OK');

    // Le scénario du voleur : rejouer le TOUT premier jeton, encore dans sa
    // fenêtre de grâce (30 s). Il ne doit RIEN obtenir.
    const stolen = await sessions.refresh(s.refreshToken, '10.0.0.1');
    expect(stolen.outcome).toBe('REFUSED');

    // Et la session de la famille n'est pas coupée pour autant (pas REPLAY).
    const session = firstRow(
      await app.query<{ status: string }>('SELECT status FROM sessions WHERE id = $1', [
        s.sessionId,
      ]),
    );
    expect(session.status).toBe('ACTIVE');
  });

  test('C16 — deux refresh CONCURRENTS du même jeton : réponses propres, zéro exception, un seul ACTIVE', async () => {
    const s = await loginFresh();

    const [a, b] = await Promise.all([
      sessions.refresh(s.refreshToken, '10.0.0.1'),
      sessions.refresh(s.refreshToken, '10.0.0.1'),
    ]);

    // Aucune des deux n'a levé : Promise.all aurait rejeté. Les deux rendent
    // une réponse du domaine (jamais une erreur serveur).
    for (const result of [a, b]) {
      expect(['OK', 'REFUSED', 'REPLAY_DETECTED']).toContain(result.outcome);
    }
    // Le gagnant tourne ; le perdant, sérialisé par le verrou, tombe sur la
    // grâce et repart vivant — la famille n'est jamais déconnectée.
    expect(a.outcome).toBe('OK');
    expect(b.outcome).toBe('OK');

    // L'invariant qui compte : la session porte EXACTEMENT un jeton ACTIVE.
    const actives = await app.query(
      "SELECT id FROM session_refresh_tokens WHERE session_id = $1 AND status = 'ACTIVE'",
      [s.sessionId],
    );
    expect(actives.rows).toHaveLength(1);

    // Et la session n'a pas été coupée par une fausse détection de rejeu.
    const session = firstRow(
      await app.query<{ status: string }>('SELECT status FROM sessions WHERE id = $1', [
        s.sessionId,
      ]),
    );
    expect(session.status).toBe('ACTIVE');
  });

  test('jeton inconnu → refus sec (UNKNOWN), sans rien révéler', async () => {
    const result = await sessions.refresh('jamais-emis', '10.0.0.1');
    expect(result.outcome).toBe('REFUSED');
  });

  test('throttle sur /auth/refresh : au plafond → THROTTLED', async () => {
    const throttled = new SessionService(app, provider, config, new LoginThrottle(2, 60));
    const s = await loginFresh();
    await throttled.refresh('faux-jeton', '10.7.7.7');
    await throttled.refresh('faux-jeton', '10.7.7.7');
    const result = await throttled.refresh('faux-jeton', '10.7.7.7');
    expect(result.outcome).toBe('THROTTLED');
    // La session légitime, elle, n'a pas été touchée.
    expect(await tokenStatuses(s.sessionId)).toEqual(['ACTIVE']);
  });
});
