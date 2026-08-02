import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { CountingDispatcher } from '../../src/dispatch/simulator/counting-dispatcher';
import { OutboxPublisher } from '../../src/outbox/publisher';
import { assemblePublisherConfig } from '../../src/outbox/publisher-config';
import { ErasureScheduler } from '../../src/persons/erasure-scheduler';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

// Étape 4 du LOT effacement : le chemin DIFFÉRÉ, avec l'existant seul.
// Le rejeu se prouve en COMPTANT LES LIGNES d'outbox (jamais en lisant un
// verdict seul), l'absence d'envoi externe en COMPTANT LES APPELS du
// dispatcher, et un mur qui bloque l'exécution (P0114) devient un verdict
// compté — jamais une panne muette et répétée.
const crypto = assembleCryptoFromEnv(fullKeyringEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
}));

const YEAR = new Date().getUTCFullYear();
const TABLES = [
  'account_notifications',
  'outbox',
  'person_erasures',
  'account_profiles',
  'phone_claims',
  'person_responsibilities',
  'accounts',
  'persons',
];

describe('effacement — le chemin différé (029 + scheduler)', () => {
  let app: Pool;
  let owner: Pool;
  let scheduler: ErasureScheduler;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    scheduler = new ErasureScheduler(app);
    await truncateTables(owner, ...TABLES);
  });

  afterAll(async () => {
    await truncateTables(owner, ...TABLES);
    await app.end();
    await owner.end();
  });

  beforeEach(async () => {
    await truncateTables(owner, 'account_notifications', 'outbox', 'person_erasures');
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(7_300_000_000 + seq);
  }

  async function adult(): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await owner.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  async function requestSelf(accountId: string, mode: string): Promise<string> {
    const request = firstRow(
      await app.query<{ verdict: string; erasure_id: string | null }>(
        'SELECT * FROM request_erasure_self($1, $2)',
        [accountId, mode],
      ),
    );
    expect(request.verdict).toBe('REQUESTED');
    if (request.erasure_id === null) {
      throw new Error('REQUESTED sans identifiant de demande');
    }
    return request.erasure_id;
  }

  async function noticeVerdict(erasureId: string): Promise<string> {
    return firstRow(
      await app.query<{ verdict: string }>('SELECT * FROM record_erasure_notice($1)', [erasureId]),
    ).verdict;
  }

  async function outboxCount(personId: string): Promise<number> {
    const row = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM outbox
          WHERE person_id = $1 AND event_type = 'PERSON_ERASURE_IMMINENT'`,
        [personId],
      ),
    );
    return Number(row.n);
  }

  /**
   * Fenêtre de préavis OUVERTE dès la demande : préavis = toute la fenêtre
   * (168 h = 7 j × 24 — R2 à l'égalité). PLANCHER DE TEST, jamais une valeur
   * de production : la politique réelle reste celle semée par 026.
   */
  async function withOpenNoticeWindow<T>(run: () => Promise<T>): Promise<T> {
    const saved = firstRow(
      await owner.query<{ retraction_days: number; notification_lead_hours: number }>(
        'SELECT retraction_days, notification_lead_hours FROM erasure_policy WHERE singleton',
      ),
    );
    await owner.query(
      'UPDATE erasure_policy SET retraction_days = 7, notification_lead_hours = 168',
    );
    try {
      return await run();
    } finally {
      await owner.query(
        'UPDATE erasure_policy SET retraction_days = $1, notification_lead_hours = $2',
        [saved.retraction_days, saved.notification_lead_hours],
      );
    }
  }

  test('la politique de canal est une ligne de DONNÉES, semée : compte oui, canal externe non', async () => {
    const policy = firstRow(
      await app.query<{ allowed_channels: string[]; in_account: boolean }>(
        `SELECT allowed_channels::text[] AS allowed_channels, in_account
           FROM event_channel_policy WHERE event_type = 'PERSON_ERASURE_IMMINENT'`,
      ),
    );
    expect(policy.allowed_channels).toEqual([]);
    expect(policy.in_account).toBe(true);
  });

  describe('record_erasure_notice — verdicts idempotents, rejeu compté en LIGNES', () => {
    test('UNKNOWN · NOT_APPLICABLE (IMMEDIATE) · NOT_YET (fenêtre pas ouverte)', async () => {
      expect(await noticeVerdict('00000000-0000-4000-8000-000000000000')).toBe('UNKNOWN');

      const immediate = await adult();
      const immediateId = await requestSelf(immediate.accountId, 'IMMEDIATE');
      expect(await noticeVerdict(immediateId)).toBe('NOT_APPLICABLE');

      const delayed = await adult();
      const delayedId = await requestSelf(delayed.accountId, 'DELAYED'); // 7 j / 48 h : J-48 h est loin
      expect(await noticeVerdict(delayedId)).toBe('NOT_YET');
      expect(await outboxCount(delayed.personId)).toBe(0);
    });

    test('NOTICED une fois, ALREADY_NOTICED ensuite — UNE ligne d’outbox, pas deux', async () => {
      await withOpenNoticeWindow(async () => {
        const { accountId, personId } = await adult();
        const erasureId = await requestSelf(accountId, 'DELAYED');

        expect(await noticeVerdict(erasureId)).toBe('NOTICED');
        const stamped = firstRow(
          await owner.query<{ stamped: boolean }>(
            'SELECT notified_at IS NOT NULL AS stamped FROM person_erasures WHERE id = $1',
            [erasureId],
          ),
        );
        expect(stamped.stamped).toBe(true);
        expect(await outboxCount(personId)).toBe(1);

        expect(await noticeVerdict(erasureId)).toBe('ALREADY_NOTICED');
        expect(await outboxCount(personId)).toBe(1); // le rejeu se compte en lignes
      });
    });

    test('une demande rétractée n’annonce rien', async () => {
      await withOpenNoticeWindow(async () => {
        const { accountId, personId } = await adult();
        const erasureId = await requestSelf(accountId, 'DELAYED');
        await app.query('SELECT * FROM retract_erasure_self($1)', [accountId]);

        expect(await noticeVerdict(erasureId)).toBe('NOT_APPLICABLE');
        expect(await outboxCount(personId)).toBe(0);
      });
    });
  });

  describe('ErasureScheduler.tick — préavis, exécution, blocage : trois verdicts comptés', () => {
    test('un tour : 1 préavis, 1 exécution, 1 blocage P0114 — et le second tour ne rejoue rien', async () => {
      await withOpenNoticeWindow(async () => {
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
        try {
          // A — préavis dû (DELAYED, fenêtre ouverte, échéance dans 7 jours).
          const noticeCase = await adult();
          await requestSelf(noticeCase.accountId, 'DELAYED');

          // B — exécution due (IMMEDIATE).
          const executeCase = await adult();
          await requestSelf(executeCase.accountId, 'IMMEDIATE');

          // C — bloquée : dernier responsable, façade contournée (owner), le
          // mur P0114 doit devenir un verdict compté, jamais une panne muette.
          const blockedCase = await adult();
          const salt = generateErasureSalt();
          const enc = encryptCivilIdentity(crypto.encryption, salt, {
            nameComponents: ['Composante'],
            displayName: 'Personne De Test',
            birthDate: `${YEAR - 12}-06-15`,
          });
          await app.query('SELECT dependent_person_id FROM attach_dependent($1, $2, $3, $4, $5, $6)', [
            blockedCase.accountId,
            nextIdentifier(),
            salt,
            enc.token,
            enc.encKeyId,
            enc.birthYear,
          ]);
          const blockedErasure = firstRow(
            await owner.query<{ id: string }>(
              `INSERT INTO person_erasures (person_id, mode, effective_after)
               VALUES ($1, 'IMMEDIATE', now()) RETURNING id`,
              [blockedCase.personId],
            ),
          ).id;

          const first = await scheduler.tick();
          expect(first).toEqual({ noticed: 1, executed: 1, blocked: 1 });

          expect(await outboxCount(noticeCase.personId)).toBe(1);
          const states = await owner.query<{ id: string; status: string }>(
            'SELECT id, status FROM person_erasures',
          );
          const byId = new Map(states.rows.map((r) => [r.id, r.status]));
          expect(byId.get(blockedErasure)).toBe('REQUESTED'); // rien de détruit, à un acte staff de trancher
          const blockedLogs = consoleSpy.mock.calls.filter((args) =>
            String(args[0]).includes('P0114'),
          );
          expect(blockedLogs.length).toBe(1);

          // Second tour : le préavis ne se rejoue pas (WHERE notified_at IS
          // NULL), l'exécuté est clos en base — seul le bloqué re-compte.
          const second = await scheduler.tick();
          expect(second).toEqual({ noticed: 0, executed: 0, blocked: 1 });
          expect(await outboxCount(noticeCase.personId)).toBe(1);
        } finally {
          consoleSpy.mockRestore();
        }
      });
    });
  });

  describe('du préavis au COMPTE — la plomberie existante, bout en bout', () => {
    test('le publisher dépose dans le compte du demandeur, et AUCUN envoi externe ne part (compté)', async () => {
      await withOpenNoticeWindow(async () => {
        const { accountId } = await adult();
        const erasureId = await requestSelf(accountId, 'DELAYED');
        expect(await noticeVerdict(erasureId)).toBe('NOTICED');

        const dispatcher = new CountingDispatcher();
        const publisher = new OutboxPublisher(
          app,
          dispatcher,
          crypto,
          assemblePublisherConfig({ OUTBOX_MAX_ATTEMPTS: '3', OUTBOX_BACKOFF_BASE_SECONDS: '1' }),
        );
        const report = await publisher.drain();
        expect(report.published).toBe(1);

        const deposited = await owner.query<{ account_id: string; event_type: string }>(
          'SELECT account_id, event_type FROM account_notifications',
        );
        expect(deposited.rowCount).toBe(1); // lignes ET contenu
        expect(deposited.rows[0]?.account_id).toBe(accountId);
        expect(deposited.rows[0]?.event_type).toBe('PERSON_ERASURE_IMMINENT');
        expect(dispatcher.calls).toBe(0); // l'absence d'envoi se COMPTE
      });
    });
  });
});
