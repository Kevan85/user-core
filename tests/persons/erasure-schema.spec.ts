import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

// Les murs de 026 : le registre d'effacement, les deux chemins de demande, la
// fenêtre de rétractation, et le mur de ré-identification (P0116) — sous rôle
// bridé (les fonctions SONT le chemin) ET sous owner (un mur tient au-delà
// des droits). C1 se prouve DANS LES DEUX SENS : pendant la fenêtre l'usage
// normal passe, après COMPLETED il est refusé.
const crypto = assembleCryptoFromEnv(fullKeyringEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
}));

const YEAR = new Date().getUTCFullYear();
const TABLES = [
  'outbox',
  'person_erasures',
  'account_profiles',
  'phone_claims',
  'person_responsibilities',
  'accounts',
  'persons',
];

interface RequestVerdict {
  verdict: string;
  erasure_id: string | null;
}

describe("effacement — le régime en base (026)", () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;
  let phoneSeq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, ...TABLES);
  });

  afterAll(async () => {
    await truncateTables(owner, ...TABLES);
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(7_700_000_000 + seq);
  }

  function nextPhone(): string {
    phoneSeq += 1;
    return `+099000${String(100_000 + phoneSeq)}`;
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : la garde n'a pas levé");
  }

  /** Compte adulte complet (personne + compte + secret, chemin unique 016). */
  async function adult(): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await owner.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  /** Mineur identifié, rattaché à son responsable par le chemin unique 023. */
  async function attachMinor(responsibleAccountId: string): Promise<string> {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: `${YEAR - 12}-06-15`,
    });
    return firstRow(
      await app.query<{ dependent_person_id: string }>(
        `SELECT dependent_person_id
           FROM attach_dependent($1, $2, $3, $4, $5, $6)`,
        [responsibleAccountId, nextIdentifier(), salt, enc.token, enc.encKeyId, enc.birthYear],
      ),
    ).dependent_person_id;
  }

  async function requestSelf(accountId: string, mode: string): Promise<RequestVerdict> {
    return firstRow(
      await app.query<RequestVerdict>('SELECT * FROM request_erasure_self($1, $2)', [
        accountId,
        mode,
      ]),
    );
  }

  /** Transition REQUESTED -> COMPLETED (owner) : l'exécuteur du lot ultérieur. */
  async function markCompleted(erasureId: string): Promise<void> {
    await owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [erasureId]);
  }

  /** Personne effacée : demande IMMEDIATE (due à l'instant) puis COMPLETED. */
  async function erased(): Promise<{ accountId: string; personId: string; erasureId: string }> {
    const { accountId, personId } = await adult();
    const request = await requestSelf(accountId, 'IMMEDIATE');
    expect(request.verdict).toBe('REQUESTED');
    if (request.erasure_id === null) {
      throw new Error('REQUESTED sans identifiant de demande');
    }
    await markCompleted(request.erasure_id);
    return { accountId, personId, erasureId: request.erasure_id };
  }

  describe('erasure_policy — la référence', () => {
    test('les lecteurs rendent les valeurs semées par la migration (7 jours, 48 h)', async () => {
      const row = firstRow(
        await app.query<{ days: number; hours: number }>(
          'SELECT erasure_retraction_days() AS days, erasure_notification_lead_hours() AS hours',
        ),
      );
      expect(row.days).toBe(7);
      expect(row.hours).toBe(48);
    });

    test('référence vide : la lecture échoue FERMÉ (P0112), jamais NULL', async () => {
      const saved = firstRow(
        await owner.query<{ retraction_days: number; notification_lead_hours: number }>(
          'SELECT retraction_days, notification_lead_hours FROM erasure_policy WHERE singleton',
        ),
      );
      await owner.query('DELETE FROM erasure_policy');
      try {
        await expect(codeOf(() => app.query('SELECT erasure_retraction_days()'))).resolves.toBe(
          DB_ERROR.EMPTY_REFERENCE,
        );
        await expect(
          codeOf(() => app.query('SELECT erasure_notification_lead_hours()')),
        ).resolves.toBe(DB_ERROR.EMPTY_REFERENCE);
      } finally {
        await owner.query(
          'INSERT INTO erasure_policy (retraction_days, notification_lead_hours) VALUES ($1, $2)',
          [saved.retraction_days, saved.notification_lead_hours],
        );
      }
    });

    test('le rôle applicatif ne touche pas la politique (écrite par migration seule)', async () => {
      await expect(
        app.query('UPDATE erasure_policy SET retraction_days = 0'),
      ).rejects.toMatchObject({ code: '42501' });
    });

    test('R1 — un DELAYED à 0 jour est non représentable : « pas de fenêtre » se dit IMMEDIATE', async () => {
      await expect(
        owner.query('UPDATE erasure_policy SET retraction_days = 0'),
      ).rejects.toMatchObject({ code: '23514' });
    });

    test('R2 — le préavis vit DANS la fenêtre : lead > retraction_days * 24 est non représentable', async () => {
      await expect(
        owner.query('UPDATE erasure_policy SET retraction_days = 1, notification_lead_hours = 168'),
      ).rejects.toMatchObject({ code: '23514' });
    });
  });

  describe('person_erasures — le registre append-only', () => {
    test('demande DELAYED : effective_after = requested_at + le délai de la politique, calculé en base', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');
      expect(request.verdict).toBe('REQUESTED');
      const row = firstRow(
        await owner.query<{ mode: string; delta: number }>(
          `SELECT mode, EXTRACT(EPOCH FROM (effective_after - requested_at))::float8 AS delta
             FROM person_erasures WHERE id = $1`,
          [request.erasure_id],
        ),
      );
      expect(row.mode).toBe('DELAYED');
      expect(row.delta).toBe(7 * 86_400);
    });

    test('demande IMMEDIATE : due à l’instant même (effective_after = requested_at)', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'IMMEDIATE');
      expect(request.verdict).toBe('REQUESTED');
      const row = firstRow(
        await owner.query<{ delta: number }>(
          `SELECT EXTRACT(EPOCH FROM (effective_after - requested_at))::float8 AS delta
             FROM person_erasures WHERE id = $1`,
          [request.erasure_id],
        ),
      );
      expect(row.delta).toBe(0);
    });

    test('contenu immuable, zéro DELETE, zéro écriture directe du rôle applicatif', async () => {
      const { accountId, personId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');

      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET effective_after = now() WHERE id = $1`, [
            request.erasure_id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.IMMUTABLE);
      await expect(
        codeOf(() => owner.query('DELETE FROM person_erasures WHERE id = $1', [request.erasure_id])),
      ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
      await expect(
        app.query(
          `INSERT INTO person_erasures (person_id, mode, effective_after) VALUES ($1, 'IMMEDIATE', now())`,
          [personId],
        ),
      ).rejects.toMatchObject({ code: '42501' });
    });

    test('les horodatages de clôture sont posés par la base, jamais par un client', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');
      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET completed_at = now() WHERE id = $1`, [
            request.erasure_id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.REGISTRY_TIMESTAMP);
    });

    test('notified_at : posé par la base, set-once — le préavis ne se re-signale pas (C3)', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');
      await owner.query(`UPDATE person_erasures SET notified_at = '2000-01-01' WHERE id = $1`, [
        request.erasure_id,
      ]);
      const row = firstRow(
        await owner.query<{ recent: boolean }>(
          `SELECT notified_at > now() - interval '1 minute' AS recent
             FROM person_erasures WHERE id = $1`,
          [request.erasure_id],
        ),
      );
      expect(row.recent).toBe(true); // la valeur du client a été écrasée par now()
      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET notified_at = now() WHERE id = $1`, [
            request.erasure_id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.REGISTRY_TIMESTAMP);
    });

    test('au plus UNE demande en cours par personne — l’index est le mur, le verdict la façade', async () => {
      const { accountId, personId } = await adult();
      const first = await requestSelf(accountId, 'DELAYED');
      expect(first.verdict).toBe('REQUESTED');

      const second = await requestSelf(accountId, 'DELAYED');
      expect(second.verdict).toBe('ALREADY_REQUESTED');
      expect(second.erasure_id).toBe(first.erasure_id);

      await expect(
        owner.query(
          `INSERT INTO person_erasures (person_id, mode, effective_after) VALUES ($1, 'DELAYED', now() + interval '7 days')`,
          [personId],
        ),
      ).rejects.toMatchObject({ code: '23505' });
    });

    test('exécuter AVANT l’échéance est refusé : la fenêtre de réflexion ne se contourne pas', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');
      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [
            request.erasure_id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);
    });

    test('une demande close est figée (P0103)', async () => {
      const { erasureId } = await erased();
      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET status = 'RETRACTED' WHERE id = $1`, [erasureId]),
        ),
      ).resolves.toBe(DB_ERROR.FROZEN_ROW);
    });
  });

  describe('les verdicts des chemins de demande', () => {
    test('self : compte inconnu ou non actif — verdict propre, rien n’est écrit', async () => {
      const ghost = await requestSelf('00000000-0000-4000-8000-000000000000', 'DELAYED');
      expect(ghost.verdict).toBe('UNKNOWN_ACCOUNT');

      const { accountId } = await adult();
      await owner.query(`UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1`, [accountId]);
      const deactivated = await requestSelf(accountId, 'DELAYED');
      expect(deactivated.verdict).toBe('ACCOUNT_NOT_ACTIVE');
    });

    test('staff : le contrôle de rôle vit en base — un titulaire de compte est FORBIDDEN', async () => {
      const holder = await adult();
      const { personId } = await adult();
      const verdict = firstRow(
        await app.query<RequestVerdict>('SELECT * FROM request_erasure_staff($1, $2)', [
          holder.accountId,
          personId,
        ]),
      );
      expect(verdict.verdict).toBe('FORBIDDEN');
    });

    test('staff : une personne au compte ACTIF s’efface elle-même — jamais par le guichet', async () => {
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const { personId } = await adult();
      const verdict = firstRow(
        await app.query<RequestVerdict>('SELECT * FROM request_erasure_staff($1, $2)', [
          staff,
          personId,
        ]),
      );
      expect(verdict.verdict).toBe('HAS_ACTIVE_ACCOUNT');
    });

    test('staff : un mineur s’efface par le staff, IMMEDIATE par défaut (ligne d’appel, pas migration)', async () => {
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const responsible = await adult();
      const minorId = await attachMinor(responsible.accountId);
      // Un co-responsable : le refus SOLE_RESPONSIBLE ne s'applique pas ici.
      const co = await adult();
      await app.query('SELECT * FROM open_responsibility_by_responsible($1, $2, $3)', [
        responsible.accountId,
        co.personId,
        minorId,
      ]);

      const verdict = firstRow(
        await app.query<RequestVerdict>('SELECT * FROM request_erasure_staff($1, $2)', [
          staff,
          minorId,
        ]),
      );
      expect(verdict.verdict).toBe('REQUESTED');
      const row = firstRow(
        await owner.query<{ mode: string }>('SELECT mode FROM person_erasures WHERE id = $1', [
          verdict.erasure_id,
        ]),
      );
      expect(row.mode).toBe('IMMEDIATE');
    });

    test('staff : personne inconnue — verdict propre', async () => {
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const verdict = firstRow(
        await app.query<RequestVerdict>('SELECT * FROM request_erasure_staff($1, $2)', [
          staff,
          '00000000-0000-4000-8000-000000000000',
        ]),
      );
      expect(verdict.verdict).toBe('UNKNOWN_PERSON');
    });

    test('une personne effacée ne reçoit plus de demande : verdict propre ET mur d’insertion (P0116)', async () => {
      const { accountId, personId } = await erased();
      const again = await requestSelf(accountId, 'IMMEDIATE');
      expect(again.verdict).toBe('ALREADY_ERASED');
      await expect(
        codeOf(() =>
          owner.query(
            `INSERT INTO person_erasures (person_id, mode, effective_after) VALUES ($1, 'IMMEDIATE', now())`,
            [personId],
          ),
        ),
      ).resolves.toBe(DB_ERROR.PERSON_ERASED);
    });
  });

  describe('C2 — le dernier responsable : refus à la DEMANDE, mur au COMMIT', () => {
    test('self : dernier responsable d’un mineur — SOLE_RESPONSIBLE, rien n’est écrit ; un co-responsable lève le refus', async () => {
      const responsible = await adult();
      const minorId = await attachMinor(responsible.accountId);

      const refused = await requestSelf(responsible.accountId, 'DELAYED');
      expect(refused.verdict).toBe('SOLE_RESPONSIBLE');
      const count = firstRow(
        await owner.query<{ n: string }>(
          'SELECT count(*) AS n FROM person_erasures WHERE person_id = $1',
          [responsible.personId],
        ),
      );
      expect(count.n).toBe('0');

      const co = await adult();
      await app.query('SELECT * FROM open_responsibility_by_responsible($1, $2, $3)', [
        responsible.accountId,
        co.personId,
        minorId,
      ]);
      const accepted = await requestSelf(responsible.accountId, 'DELAYED');
      expect(accepted.verdict).toBe('REQUESTED');
    });

    test('staff : un adulte au compte désactivé, dernier responsable — même refus propre', async () => {
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const responsible = await adult();
      await attachMinor(responsible.accountId);
      // Décision D-D (017) : la désactivation du compte ne touche pas le lien.
      await owner.query(`UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1`, [
        responsible.accountId,
      ]);

      const verdict = firstRow(
        await app.query<RequestVerdict>('SELECT * FROM request_erasure_staff($1, $2)', [
          staff,
          responsible.personId,
        ]),
      );
      expect(verdict.verdict).toBe('SOLE_RESPONSIBLE');
    });

    test('le MUR tient si on contourne la fonction : clore le dernier lien lève P0114 au commit réel', async () => {
      const responsible = await adult();
      const minorId = await attachMinor(responsible.accountId);
      const linkId = firstRow(
        await owner.query<{ id: string }>(
          `SELECT id FROM person_responsibilities WHERE dependent_person_id = $1 AND status = 'ACTIVE'`,
          [minorId],
        ),
      ).id;

      // Une seule instruction, autocommit : le différé parle AU COMMIT, pas
      // dans un BEGIN/ROLLBACK qui ne prouverait rien.
      await expect(
        codeOf(() =>
          owner.query(
            `UPDATE person_responsibilities SET status = 'ENDED', end_reason = 'ADMIN' WHERE id = $1`,
            [linkId],
          ),
        ),
      ).resolves.toBe(DB_ERROR.ORPHANED_DEPENDENT);
    });
  });

  describe('la rétractation — la fenêtre appartient à la personne', () => {
    test('dans la fenêtre : RETRACTED, horodaté par la base, figé ensuite — et une demande neuve reste possible', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');

      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM retract_erasure_self($1)', [accountId]),
      );
      expect(verdict.verdict).toBe('RETRACTED');
      const row = firstRow(
        await owner.query<{ status: string; stamped: boolean }>(
          `SELECT status, retracted_at IS NOT NULL AS stamped FROM person_erasures WHERE id = $1`,
          [request.erasure_id],
        ),
      );
      expect(row.status).toBe('RETRACTED');
      expect(row.stamped).toBe(true);

      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [
            request.erasure_id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.FROZEN_ROW);

      const again = await requestSelf(accountId, 'DELAYED');
      expect(again.verdict).toBe('REQUESTED');
      expect(again.erasure_id).not.toBe(request.erasure_id);
    });

    test('fenêtre close (IMMEDIATE) : verdict propre ET mur dans le trigger', async () => {
      const { accountId } = await adult();
      const request = await requestSelf(accountId, 'IMMEDIATE');

      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM retract_erasure_self($1)', [accountId]),
      );
      expect(verdict.verdict).toBe('WINDOW_CLOSED');

      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET status = 'RETRACTED' WHERE id = $1`, [
            request.erasure_id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);
    });

    test('rien à rétracter : verdict propre', async () => {
      const { accountId } = await adult();
      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM retract_erasure_self($1)', [accountId]),
      );
      expect(verdict.verdict).toBe('NOTHING_TO_RETRACT');
    });
  });

  describe('C1 — le mur de ré-identification mord sur COMPLETED, jamais pendant la fenêtre', () => {
    /** L'écriture d'identité que ferait provide() : blob chiffré sous le sel COURANT de la personne. */
    async function writeIdentity(pool: Pool, personId: string): Promise<void> {
      const salt = firstRow(
        await owner.query<{ erasure_salt: Buffer }>(
          'SELECT erasure_salt FROM persons WHERE id = $1',
          [personId],
        ),
      ).erasure_salt;
      const enc = encryptCivilIdentity(crypto.encryption, salt, {
        nameComponents: ['Composante'],
        displayName: 'Personne De Test',
        birthDate: `${YEAR - 30}-06-15`,
      });
      await pool.query(
        `UPDATE persons SET civil_identity_encrypted = $2, enc_key_id = $3, birth_year = $4 WHERE id = $1`,
        [personId, enc.token, enc.encKeyId, enc.birthYear],
      );
    }

    async function insertClaim(pool: Pool, personId: string): Promise<void> {
      const columns = buildPhoneColumns(crypto, nextPhone());
      await pool.query(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [personId, columns.phoneHmac, columns.hmacKeyId, columns.phoneEncrypted, columns.encKeyId],
      );
    }

    test('pendant la fenêtre (REQUESTED) : identité, ligne et profil fonctionnent — la fenêtre de Kevin n’est pas détruite', async () => {
      const { accountId, personId } = await adult();
      const request = await requestSelf(accountId, 'DELAYED');
      expect(request.verdict).toBe('REQUESTED');

      await writeIdentity(app, personId);
      await insertClaim(app, personId);
      await app.query(
        `INSERT INTO account_profiles (account_id, display_name) VALUES ($1, 'Nom Affiché')`,
        [accountId],
      );
      // Et la rétractation reste possible : c'est toute la raison de C1.
      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM retract_erasure_self($1)', [accountId]),
      );
      expect(verdict.verdict).toBe('RETRACTED');
    });

    test('après COMPLETED : l’écriture d’identité est refusée (P0116) — rôle bridé ET owner', async () => {
      const { personId } = await erased();
      await expect(codeOf(() => writeIdentity(app, personId))).resolves.toBe(
        DB_ERROR.PERSON_ERASED,
      );
      await expect(codeOf(() => writeIdentity(owner, personId))).resolves.toBe(
        DB_ERROR.PERSON_ERASED,
      );
    });

    test('après COMPLETED : aucune revendication de ligne neuve (P0116) — rôle bridé ET owner', async () => {
      const { personId } = await erased();
      await expect(codeOf(() => insertClaim(app, personId))).resolves.toBe(DB_ERROR.PERSON_ERASED);
      await expect(codeOf(() => insertClaim(owner, personId))).resolves.toBe(
        DB_ERROR.PERSON_ERASED,
      );
    });

    test('après COMPLETED : le profil (seule PII nominative en clair) ne naît ni ne se réécrit (P0116)', async () => {
      const withProfile = await adult();
      await app.query(
        `INSERT INTO account_profiles (account_id, display_name) VALUES ($1, 'Nom Affiché')`,
        [withProfile.accountId],
      );
      const request = await requestSelf(withProfile.accountId, 'IMMEDIATE');
      if (request.erasure_id === null) {
        throw new Error('REQUESTED sans identifiant de demande');
      }
      await markCompleted(request.erasure_id);

      await expect(
        codeOf(() =>
          app.query(`UPDATE account_profiles SET display_name = 'Encore Lui' WHERE account_id = $1`, [
            withProfile.accountId,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.PERSON_ERASED);

      const bare = await erased();
      await expect(
        codeOf(() =>
          owner.query(
            `INSERT INTO account_profiles (account_id, display_name) VALUES ($1, 'Renaissance')`,
            [bare.accountId],
          ),
        ),
      ).resolves.toBe(DB_ERROR.PERSON_ERASED);
    });
  });
});
