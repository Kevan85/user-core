import { Pool } from 'pg';
import { generatePublicIdentifier } from '../../src/accounts/public-identifier';
import { generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de 016 : un compte appartient à UNE personne, pour toujours,
// et une personne n'a jamais deux comptes ACTIFS — sous rôle bridé ET owner.
describe('accounts.person_id — invariants en base (016)', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'accounts', 'persons');
  });

  afterAll(async () => {
    await truncateTables(owner, 'accounts', 'persons');
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_300_000_000 + seq);
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : la garde n'a pas levé");
  }

  test('create_account crée la PERSONNE avec le compte : nés ensemble, liés, la personne est nue', async () => {
    const personIdentifier = nextIdentifier();
    const accountId = await createAccount(app, nextIdentifier(), { personIdentifier });

    const account = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    );
    const person = firstRow(
      await app.query<{
        public_identifier: string;
        enc_key_id: string | null;
        birth_year: number | null;
      }>('SELECT public_identifier, enc_key_id, birth_year FROM persons WHERE id = $1', [
        account.person_id,
      ]),
    );
    // Minimisation : l'inscription ne fournit AUCUNE identité civile.
    expect(person.public_identifier).toBe(personIdentifier);
    expect(person.enc_key_id).toBeNull();
    expect(person.birth_year).toBeNull();
  });

  test('le rattachement est IMMUABLE : un compte ne change jamais de personne — même pour owner', async () => {
    const accountId = await createAccount(app, nextIdentifier());
    const otherAccount = await createAccount(app, nextIdentifier());
    const other = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        otherAccount,
      ]),
    );
    await expect(
      codeOf(() =>
        owner.query('UPDATE accounts SET person_id = $2 WHERE id = $1', [
          accountId,
          other.person_id,
        ]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
  });

  test('au plus UN compte ACTIF par personne ; un compte désactivé ne verrouille pas la personne', async () => {
    const accountId = await createAccount(app, nextIdentifier());
    const { person_id } = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    );

    // Un deuxième compte ACTIF de la même personne : refusé par l'index
    // partiel — même en INSERT direct d'owner (l'index ne se contourne pas).
    await expect(
      owner.query(
        'INSERT INTO accounts (public_identifier, role, person_id) VALUES ($1, $2, $3)',
        [nextIdentifier(), 'ACCOUNT_HOLDER', person_id],
      ),
    ).rejects.toThrow(/uq_accounts_active_person/);

    // Le compte meurt (statut, jamais suppression) : la personne redevient
    // libre d'acquérir un nouveau moyen d'agir.
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    await expect(
      owner.query(
        'INSERT INTO accounts (public_identifier, role, person_id) VALUES ($1, $2, $3)',
        [nextIdentifier(), 'ACCOUNT_HOLDER', person_id],
      ),
    ).resolves.toBeDefined();
  });

  test("le chemin unique reste unique : l'INSERT direct du rôle applicatif n'existe toujours pas (F5)", async () => {
    const person = firstRow(
      await owner.query<{ id: string }>(
        'SELECT create_person($1, $2, NULL, NULL, NULL) AS id',
        [nextIdentifier(), generateErasureSalt()],
      ),
    );
    await expect(
      app.query('INSERT INTO accounts (public_identifier, role, person_id) VALUES ($1, $2, $3)', [
        generatePublicIdentifier(),
        'ACCOUNT_HOLDER',
        person.id,
      ]),
    ).rejects.toThrow(/permission denied/);
  });

  test('une violation dans la transaction ANNULE TOUT : ni compte ni personne orpheline', async () => {
    const before = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM persons'),
    ).n;
    // Secret difforme (CHECK argon2id de 003) → toute la transaction tombe.
    await expect(
      app.query(
        `SELECT account_id FROM create_account($1, 'ACCOUNT_HOLDER', 'pas-un-hash', false, NULL, $2, $3)`,
        [nextIdentifier(), nextIdentifier(), generateErasureSalt()],
      ),
    ).rejects.toThrow();
    const after = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM persons'),
    ).n;
    expect(after).toBe(before); // aucune personne née sans son compte
  });
});
