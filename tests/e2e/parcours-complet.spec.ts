import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { SessionService } from '../../src/auth/session.service';
import { CatalogService } from '../../src/catalog/catalog.service';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { CountingDispatcher } from '../../src/dispatch/simulator/counting-dispatcher';
import { OutboxPublisher } from '../../src/outbox/publisher';
import { assemblePublisherConfig } from '../../src/outbox/publisher-config';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { generateProofCode } from '../../src/proving/proof-code';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

/**
 * LE PARCOURS D'UNE FAMILLE, DE BOUT EN BOUT, à travers les trois lots :
 * compte → session → numéro prouvé par la SIM → programme activé →
 * la SIM change de mains → l'ancien détenteur est prévenu SANS qu'un message
 * ne parte sur la ligne qu'il vient de perdre.
 *
 * C'est le test qui vérifie que les pièces tiennent ENSEMBLE — chaque lot a
 * ses invariants ; celui-ci vérifie la couture entre eux.
 */
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});
const codeKeyring = assembleProofCodeKeyring({
  USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1: randomBytes(32).toString('base64') }),
  USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
});

const LINE = '+243870000001';
const SECRET = 'S3cretFamille!';

describe('Parcours complet — trois lots, une famille', () => {
  let app: Pool;
  let owner: Pool;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'program_grants',
      'programs',
      'proof_dispatches',
      'possession_proof_refusals',
      'possession_proofs',
      'phone_claims',
      'session_refresh_tokens',
      'sessions',
      'account_secrets',
      'accounts',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  test('inscription → session → possession prouvée → programme → recyclage de la ligne', async () => {
    const authConfig = testAuthAssembly();
    const provider = new LocalAuthenticationProvider(authConfig);
    await provider.init();
    const auth = new AuthService(app, provider, provider, authConfig, new LoginThrottle(100, 60));
    const sessions = new SessionService(app, provider, authConfig, new LoginThrottle(100, 60));
    const prover = new LyingProver();
    const phone = new PhoneService(app, crypto, codeKeyring, prover, assemblePhoneConfig({}));
    const catalog = new CatalogService(app);
    const dispatcher = new CountingDispatcher();
    const publisher = new OutboxPublisher(app, dispatcher, crypto, assemblePublisherConfig({}));

    // --- 1. Un compte naît (identifiant opaque, secret argon2id).
    const identifier = '9100000001';
    const famille = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [identifier],
      ),
    ).id;
    await app.query('INSERT INTO account_secrets (account_id, secret_hash) VALUES ($1, $2)', [
      famille,
      await provider.hashSecret(SECRET),
    ]);

    // --- 2. Elle se connecte : session révocable, refresh haché.
    const login = await auth.login(identifier, SECRET, '10.0.0.1');
    if (login.outcome !== 'OK') throw new Error('login attendu');
    // Aucun code n'a été envoyé pour se connecter (jamais d'OTP de routine).
    expect(prover.deliveries).toBe(0);

    // --- 3. Elle déclare son numéro : TOUJOURS aucun envoi (paresseux).
    const declared = await phone.declare(famille, LINE);
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');
    expect(prover.deliveries).toBe(0);

    // --- 4. Elle veut payer : LÀ, on prouve la possession de la ligne.
    const sent = await phone.requestProof(famille, declared.claimId, 'CALL');
    expect(sent.outcome).toBe('SENT');
    expect(prover.deliveries).toBe(1);
    const code = prover.delivered[0]?.code ?? '';
    expect((await phone.verify(famille, declared.claimId, code)).outcome).toBe('PROVEN');

    // Un envoi facturable, et un seul.
    const dispatches = await app.query('SELECT id FROM proof_dispatches');
    expect(dispatches.rows).toHaveLength(1);

    // --- 5. Elle active un programme en libre-service.
    await owner.query(
      "INSERT INTO programs (code, label, access_mode) VALUES ('sante-famille', 'Santé', 'SELF_SERVICE')",
    );
    expect((await catalog.activate(famille, 'sante-famille')).outcome).toBe('ACTIVATED');
    const view = await catalog.list(famille);
    expect(view[0]).toMatchObject({ code: 'sante-famille', activated: true });

    // --- 6. La rotation de session fonctionne toujours (LOT 1 intact).
    const refreshed = await sessions.refresh(login.refreshToken, '10.0.0.1');
    expect(refreshed.outcome).toBe('OK');

    // --- 7. LA SIM CHANGE DE MAINS. Un inconnu — pardon : un NOUVEAU compte —
    //        prouve la même ligne.
    const inconnu = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ('9100000002', 'ACCOUNT_HOLDER') RETURNING id",
      ),
    ).id;
    const claim2 = await phone.declare(inconnu, LINE);
    if (claim2.outcome !== 'DECLARED') throw new Error('déclaration attendue');
    await phone.requestProof(inconnu, claim2.claimId, 'CALL');
    const code2 = prover.delivered[prover.delivered.length - 1]?.code ?? '';
    expect((await phone.verify(inconnu, claim2.claimId, code2)).outcome).toBe('PROVEN');

    // La preuve la plus récente a gagné : la famille a perdu SA ligne.
    const ancienne = firstRow(
      await app.query<{ status: string; revoke_reason: string }>(
        'SELECT status, revoke_reason FROM phone_claims WHERE id = $1',
        [declared.claimId],
      ),
    );
    expect(ancienne).toMatchObject({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });

    // --- 8. Le worker draine l'événement. LE POINT DE TOUT LE CHANTIER :
    //        aucun message ne part sur la ligne que la famille vient de perdre
    //        (elle est dans la main de quelqu'un d'autre), et la famille est
    //        prévenue dans SON COMPTE, qui lui reste à elle.
    const report = await publisher.drain();
    expect(report.published).toBe(1);
    expect(dispatcher.calls).toBe(0);
    expect(dispatcher.countTo(LINE)).toBe(0);

    const notification = firstRow(
      await app.query<{ account_id: string; event_type: string }>(
        'SELECT account_id, event_type FROM account_notifications',
      ),
    );
    expect(notification.account_id).toBe(famille);
    expect(notification.event_type).toBe('PHONE_LINE_SUPERSEDED');

    // --- 9. Et la famille garde tout le reste : son compte, sa session, son
    //        programme. Perdre une ligne téléphonique n'efface pas une vie
    //        numérique.
    const compte = firstRow(
      await app.query<{ status: string }>('SELECT status FROM accounts WHERE id = $1', [famille]),
    );
    expect(compte.status).toBe('ACTIVE');
    const programme = await catalog.list(famille);
    expect(programme[0]?.activated).toBe(true);
    const encore = await sessions.refresh(
      refreshed.outcome === 'OK' ? (refreshed.refreshToken ?? '') : '',
      '10.0.0.1',
    );
    expect(encore.outcome).toBe('OK');

    // --- 10. Le code de possession, lui, n'existe nulle part.
    const leak = await owner.query<{ hits: string }>(
      'SELECT count(*)::text AS hits FROM possession_proofs WHERE code_hmac LIKE $1',
      [`%${code}%`],
    );
    expect(Number(firstRow(leak).hits)).toBe(0);
    expect(generateProofCode(6)).toMatch(/^[0-9]{6}$/);
  });
});
