import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { ErasureService } from '../../src/persons/erasure.service';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

// Étape 5 du LOT effacement : la FAÇADE ne porte aucun invariant — ces tests
// prouvent qu'elle TRADUIT (verdicts de 026/028 → résultats propres), qu'elle
// borne le débit (throttle dédié), et que le BOLA est par construction :
// aucun paramètre de personne sur le chemin self.
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

describe('ErasureService — la façade traduit, les murs décident (étape 5)', () => {
  let app: Pool;
  let owner: Pool;
  let service: ErasureService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    // Budget large : les tests du throttle construisent le leur.
    service = new ErasureService(app, new LoginThrottle(1000, 3600));
    await truncateTables(owner, ...TABLES);
  });

  afterAll(async () => {
    await truncateTables(owner, ...TABLES);
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(7_200_000_000 + seq);
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

  async function attachMinor(responsibleAccountId: string): Promise<string> {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: `${YEAR - 12}-06-15`,
    });
    const dependentId = firstRow(
      await app.query<{ dependent_person_id: string }>(
        `SELECT dependent_person_id FROM attach_dependent($1, $2, $3, $4, $5, $6)`,
        [responsibleAccountId, nextIdentifier(), salt, enc.token, enc.encKeyId, enc.birthYear],
      ),
    ).dependent_person_id;
    return firstRow(
      await owner.query<{ public_identifier: string }>(
        'SELECT public_identifier FROM persons WHERE id = $1',
        [dependentId],
      ),
    ).public_identifier;
  }

  describe('le chemin self', () => {
    test('DELAYED : REQUESTED avec la fin de fenêtre ; le statut est retractable ; la rétractation ferme', async () => {
      const { accountId } = await adult();

      const requested = await service.requestSelf(accountId, 'DELAYED');
      if (requested.outcome !== 'REQUESTED') {
        throw new Error(`REQUESTED attendu, reçu ${requested.outcome}`);
      }
      const days = (requested.effectiveAfter.getTime() - Date.now()) / 86_400_000;
      expect(days).toBeGreaterThan(6.9);
      expect(days).toBeLessThan(7.1);

      const again = await service.requestSelf(accountId, 'DELAYED');
      expect(again.outcome).toBe('ALREADY_REQUESTED');

      const status = await service.status(accountId);
      expect(status.state).toBe('REQUESTED');
      expect(status.retractable).toBe(true);
      expect(status.effectiveAfter?.toISOString()).toBe(requested.effectiveAfter.toISOString());

      expect((await service.retractSelf(accountId)).outcome).toBe('RETRACTED');
      const after = await service.status(accountId);
      expect(after.state).toBe('RETRACTED');
      expect(after.retractable).toBe(false);

      expect((await service.retractSelf(accountId)).outcome).toBe('NOTHING_TO_RETRACT');
    });

    test('IMMEDIATE : exécuté DANS l’appel — COMPLETED, la personne est réellement détruite', async () => {
      const { accountId, personId } = await adult();
      const result = await service.requestSelf(accountId, 'IMMEDIATE');
      expect(result.outcome).toBe('COMPLETED');

      const registre = firstRow(
        await owner.query<{ status: string }>(
          'SELECT status FROM person_erasures WHERE person_id = $1',
          [personId],
        ),
      );
      expect(registre.status).toBe('COMPLETED');
      const account = firstRow(
        await owner.query<{ status: string }>('SELECT status FROM accounts WHERE id = $1', [
          accountId,
        ]),
      );
      expect(account.status).toBe('DEACTIVATED');

      const status = await service.status(accountId);
      expect(status.state).toBe('COMPLETED');
      expect(status.retractable).toBe(false);
    });

    test('dernier responsable : SOLE_RESPONSIBLE traduit, rien n’est écrit', async () => {
      const { accountId } = await adult();
      await attachMinor(accountId);
      const result = await service.requestSelf(accountId, 'DELAYED');
      expect(result.outcome).toBe('SOLE_RESPONSIBLE');
    });

    test('compte désactivé : ACCOUNT_NOT_ACTIVE ; aucune demande : status NONE', async () => {
      const { accountId } = await adult();
      expect((await service.status(accountId)).state).toBe('NONE');
      await owner.query(`UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1`, [accountId]);
      expect((await service.requestSelf(accountId, 'DELAYED')).outcome).toBe('ACCOUNT_NOT_ACTIVE');
      expect((await service.retractSelf(accountId)).outcome).toBe('ACCOUNT_NOT_ACTIVE');
    });

    test('le throttle borne les mutations — budget dédié, par compte', async () => {
      const throttled = new ErasureService(app, new LoginThrottle(1, 3600));
      const { accountId } = await adult();
      expect((await throttled.requestSelf(accountId, 'DELAYED')).outcome).toBe('REQUESTED');
      expect((await throttled.retractSelf(accountId)).outcome).toBe('THROTTLED');
    });
  });

  describe('le chemin staff', () => {
    test('le contrôle de rôle est EN BASE : un titulaire est FORBIDDEN, une personne inconnue NOT_FOUND', async () => {
      const holder = await adult();
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });

      expect((await service.eraseByStaff(holder.accountId, '9999999999')).outcome).toBe(
        'UNKNOWN_PERSON',
      );
      const target = await adult();
      const targetIdentifier = firstRow(
        await owner.query<{ public_identifier: string }>(
          'SELECT public_identifier FROM persons WHERE id = $1',
          [target.personId],
        ),
      ).public_identifier;
      expect((await service.eraseByStaff(holder.accountId, targetIdentifier)).outcome).toBe(
        'FORBIDDEN',
      );
      expect((await service.eraseByStaff(staff, targetIdentifier)).outcome).toBe(
        'HAS_ACTIVE_ACCOUNT',
      );
    });

    test('un mineur (avec co-responsable) : COMPLETED — demande + exécution dans l’appel', async () => {
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const responsible = await adult();
      const minorIdentifier = await attachMinor(responsible.accountId);
      const co = await adult();
      const minorId = firstRow(
        await owner.query<{ id: string }>('SELECT id FROM persons WHERE public_identifier = $1', [
          minorIdentifier,
        ]),
      ).id;
      await app.query('SELECT * FROM open_responsibility_by_responsible($1, $2, $3)', [
        responsible.accountId,
        co.personId,
        minorId,
      ]);

      const result = await service.eraseByStaff(staff, minorIdentifier);
      expect(result.outcome).toBe('COMPLETED');
      const person = firstRow(
        await owner.query<{ empty: boolean }>(
          'SELECT civil_identity_encrypted IS NULL AS empty FROM persons WHERE id = $1',
          [minorId],
        ),
      );
      expect(person.empty).toBe(true); // détruit, pas seulement enregistré

      expect((await service.eraseByStaff(staff, minorIdentifier)).outcome).toBe('ALREADY_ERASED');
    });

    test('dernier responsable sans co-responsable : SOLE_RESPONSIBLE traduit sur le chemin staff', async () => {
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const responsible = await adult();
      await attachMinor(responsible.accountId);
      await owner.query(`UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1`, [
        responsible.accountId,
      ]);
      const identifier = firstRow(
        await owner.query<{ public_identifier: string }>(
          'SELECT public_identifier FROM persons WHERE id = $1',
          [responsible.personId],
        ),
      ).public_identifier;

      expect((await service.eraseByStaff(staff, identifier)).outcome).toBe('SOLE_RESPONSIBLE');
    });
  });
});
