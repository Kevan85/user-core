import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { CountingDispatcher } from '../../src/dispatch/simulator/counting-dispatcher';
import { OutboxPublisher } from '../../src/outbox/publisher';
import { assemblePublisherConfig } from '../../src/outbox/publisher-config';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

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

const LINE = '+243861234567';

describe('OutboxPublisher — et LE PIÈGE du numéro recyclé', () => {
  let app: Pool;
  let owner: Pool;
  let prover: LyingProver;
  let phone: PhoneService;
  let dispatcher: CountingDispatcher;
  let publisher: OutboxPublisher;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  beforeEach(async () => {
    prover = new LyingProver();
    dispatcher = new CountingDispatcher();
    phone = new PhoneService(app, crypto, codeKeyring, prover, assemblePhoneConfig({}));
    publisher = new OutboxPublisher(
      app,
      dispatcher,
      crypto,
      assemblePublisherConfig({ OUTBOX_MAX_ATTEMPTS: '3', OUTBOX_BACKOFF_BASE_SECONDS: '1' }),
    );
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'proof_dispatches',
      'possession_proof_refusals',
      'possession_proofs',
      'phone_claims',
      'accounts',
    );
    // Les politiques ajoutées par un test ne débordent pas sur le suivant ;
    // celle du socle (PHONE_LINE_SUPERSEDED) est reposée par la migration.
    await owner.query("DELETE FROM event_channel_policy WHERE event_type LIKE 'TEST_%'");
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    return firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7800000000 + seq)],
      ),
    ).id;
  }

  /** Un compte prouve la ligne : c'est le chemin réel, de bout en bout. */
  async function proveLine(accountId: string, line = LINE): Promise<string> {
    const declared = await phone.declare(accountId, line);
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');
    const sent = await phone.requestProof(accountId, declared.claimId, 'CALL');
    if (sent.outcome !== 'SENT') throw new Error(`envoi attendu, reçu ${sent.outcome}`);
    const code = prover.delivered[prover.delivered.length - 1]?.code ?? '';
    const verified = await phone.verify(accountId, declared.claimId, code);
    if (verified.outcome !== 'PROVEN') throw new Error('preuve attendue');
    return declared.claimId;
  }

  test('🔴 LE PIÈGE — ZÉRO message sur la ligne reprise ; l\'ancien détenteur est prévenu DANS SON COMPTE', async () => {
    const ancien = await newAccount();
    await proveLine(ancien);

    // La SIM change de mains : le nouveau détenteur prouve la même ligne.
    const nouveau = await newAccount();
    await proveLine(nouveau);

    // L'événement de reprise attend d'être drainé.
    const pending = await app.query<{ event_type: string; account_id: string }>(
      "SELECT event_type, account_id FROM outbox WHERE status = 'PENDING'",
    );
    expect(pending.rows).toHaveLength(1);
    expect(pending.rows[0]?.event_type).toBe('PHONE_LINE_SUPERSEDED');
    expect(pending.rows[0]?.account_id).toBe(ancien);

    const report = await publisher.drain();
    expect(report.claimed).toBe(1);
    expect(report.published).toBe(1);

    // ===================================================================
    // LE POINT DE TOUT LE LOT : la ligne reprise n'a reçu AUCUN message.
    // Elle est dans la main d'un inconnu — lui écrire l'aurait prévenu
    // qu'un compte de l'écosystème était rattaché à ce numéro.
    // Prouvé par COMPTAGE d'appels, jamais déduit d'un résultat.
    // ===================================================================
    expect(dispatcher.calls).toBe(0);
    expect(dispatcher.sent).toHaveLength(0);
    expect(dispatcher.countTo(LINE)).toBe(0);

    // L'ancien détenteur, lui, EST prévenu — dans son compte, qu'il lira à sa
    // prochaine connexion. Son compte est toujours à lui.
    const notifications = await app.query<{ account_id: string; event_type: string }>(
      'SELECT account_id, event_type FROM account_notifications',
    );
    expect(notifications.rows).toHaveLength(1);
    expect(notifications.rows[0]?.account_id).toBe(ancien);
    expect(notifications.rows[0]?.event_type).toBe('PHONE_LINE_SUPERSEDED');
  });

  test('resolve_notification_address REFUSE une revendication non ACTIVE (par construction)', async () => {
    const ancien = await newAccount();
    const claimId = await proveLine(ancien, '+243862222222');

    // Tant qu'elle est ACTIVE : l'adresse se résout.
    const live = firstRow(
      await app.query<{ token: string | null }>(
        'SELECT resolve_notification_address($1) AS token',
        [claimId],
      ),
    );
    expect(live.token).not.toBeNull();

    // Une fois reprise (ou révoquée) : plus AUCUNE adresse. Jamais.
    const nouveau = await newAccount();
    await proveLine(nouveau, '+243862222222');
    const dead = firstRow(
      await app.query<{ token: string | null }>(
        'SELECT resolve_notification_address($1) AS token',
        [claimId],
      ),
    );
    expect(dead.token).toBeNull();
  });

  test('la politique de canal est en DONNÉES : aucun canal externe pour la reprise de ligne', async () => {
    const policy = firstRow(
      await app.query<{ allowed_channels: string[]; in_account: boolean }>(
        "SELECT allowed_channels::text[] AS allowed_channels, in_account FROM event_channel_policy WHERE event_type = 'PHONE_LINE_SUPERSEDED'",
      ),
    );
    // Casté en text[], le pilote décode enfin un vrai tableau : il est VIDE.
    expect(policy.allowed_channels).toEqual([]);
    expect(policy.in_account).toBe(true);
    // Et le service ne peut pas la changer pour « se faciliter la vie ».
    await expect(
      app.query(
        "UPDATE event_channel_policy SET allowed_channels = '{SMS}' WHERE event_type = 'PHONE_LINE_SUPERSEDED'",
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('publication idempotente : un événement publié n\'est JAMAIS rejoué', async () => {
    const ancien = await newAccount();
    await proveLine(ancien, '+243863333333');
    const nouveau = await newAccount();
    await proveLine(nouveau, '+243863333333');

    await publisher.drain();
    const second = await publisher.drain(); // second tour du worker
    expect(second.claimed).toBe(0); // plus rien à prendre

    // Une seule notification : l'ancien détenteur n'est pas prévenu en boucle
    // (et demain, chaque notification pourrait coûter un envoi).
    const notifications = await app.query('SELECT id FROM account_notifications');
    expect(notifications.rows).toHaveLength(1);
    const published = await app.query<{ status: string }>('SELECT status FROM outbox');
    expect(published.rows.map((r) => r.status)).toEqual(['PUBLISHED']);
  });

  test('F1 — un événement indélivrable meurt après N tentatives EXACTEMENT, puis plus rien', async () => {
    // Un événement dont la politique autorise un canal externe, mais dont
    // l'adresse est introuvable (revendication supprimée du contexte) :
    // il ne pourra JAMAIS être livré.
    const accountId = await newAccount();
    await owner.query(
      `INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note)
       VALUES ('TEST_EXTERNAL_ONLY', '{SMS}', false, 'test')`,
    );
    await owner.query(
      "INSERT INTO outbox (event_type, account_id) VALUES ('TEST_EXTERNAL_ONLY', $1)",
      [accountId],
    );

    // maxAttempts = 3 : trois tours, et il meurt. (Le backoff est rembobiné
    // entre les tours — on teste le compteur, pas l'horloge.)
    for (let i = 0; i < 3; i++) {
      await owner.query("UPDATE outbox SET next_attempt_at = now() WHERE status = 'PENDING'");
      await publisher.drain();
    }

    const row = firstRow(
      await app.query<{ status: string; attempts: number; last_error_code: string }>(
        "SELECT status, attempts, last_error_code FROM outbox WHERE event_type = 'TEST_EXTERNAL_ONLY'",
      ),
    );
    expect(row.status).toBe('FAILED');
    expect(row.attempts).toBe(3);
    expect(row.last_error_code).toBe('NOT_NOTIFIABLE');

    // Et PLUS AUCUNE tentative ensuite : l'événement mort ne tourne pas en
    // boucle sur un canal payant (CDC §6.6).
    await owner.query("UPDATE outbox SET next_attempt_at = now() WHERE status = 'PENDING'");
    const after = await publisher.drain();
    expect(after.claimed).toBe(0);
    expect(dispatcher.calls).toBe(0);
  });

  test('un événement à canal externe LIVRABLE part bien (le publisher n\'est pas muet par principe)', async () => {
    const accountId = await newAccount();
    const claimId = await proveLine(accountId, '+243864444444');
    await owner.query(
      `INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note)
       VALUES ('TEST_REACHABLE', '{SMS}', false, 'test')`,
    );
    await owner.query(
      "INSERT INTO outbox (event_type, account_id, claim_id) VALUES ('TEST_REACHABLE', $1, $2)",
      [accountId, claimId],
    );

    const report = await publisher.drain();
    expect(report.published).toBe(1);
    // La ligne est ACTIVE et lui appartient : le message part, sur son numéro.
    expect(dispatcher.countTo('+243864444444')).toBe(1);
    expect(dispatcher.sent[0]?.channel).toBe('SMS');
  });

  test('échec du fournisseur → retenté, puis mort ; jamais un abandon silencieux', async () => {
    const accountId = await newAccount();
    const claimId = await proveLine(accountId, '+243865555555');
    await owner.query(
      `INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note)
       VALUES ('TEST_FLAKY', '{SMS}', false, 'test')`,
    );
    await owner.query(
      "INSERT INTO outbox (event_type, account_id, claim_id) VALUES ('TEST_FLAKY', $1, $2)",
      [accountId, claimId],
    );

    dispatcher.willLie('PROVIDER_ERROR');
    const first = await publisher.drain();
    expect(first.retried).toBe(1);
    expect(dispatcher.calls).toBe(1);

    const row = firstRow(
      await app.query<{ attempts: number; last_error_code: string; status: string }>(
        "SELECT attempts, last_error_code, status FROM outbox WHERE event_type = 'TEST_FLAKY'",
      ),
    );
    expect(row.attempts).toBe(1);
    expect(row.last_error_code).toBe('DISPATCH_FAILED');
    expect(row.status).toBe('PENDING'); // il sera retenté, pas oublié
  });

  test('§3.13 — aucune transaction ouverte pendant l\'appel au dispatcher', async () => {
    const accountId = await newAccount();
    const claimId = await proveLine(accountId, '+243866666666');
    await owner.query(
      `INSERT INTO event_channel_policy (event_type, allowed_channels, in_account, note)
       VALUES ('TEST_TX', '{SMS}', false, 'test')`,
    );
    await owner.query(
      "INSERT INTO outbox (event_type, account_id, claim_id) VALUES ('TEST_TX', $1, $2)",
      [accountId, claimId],
    );

    let openDuringCall = -1;
    const spy = new CountingDispatcher();
    const original = spy.send.bind(spy);
    spy.send = async (message) => {
      const inspector = new Pool({ connectionString: adminUrl() });
      try {
        const r = await inspector.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM pg_stat_activity
            WHERE datname = current_database()
              AND state IN ('idle in transaction', 'idle in transaction (aborted)')`,
        );
        openDuringCall = Number(r.rows[0]?.count ?? -1);
      } finally {
        await inspector.end();
      }
      return original(message);
    };

    const worker = new OutboxPublisher(app, spy, crypto, assemblePublisherConfig({}));
    await worker.drain();
    expect(openDuringCall).toBe(0);
  });
});
