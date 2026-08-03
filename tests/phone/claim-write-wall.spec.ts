import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { generateErasureSalt } from '../../src/crypto/person-identity';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * 030 — LE MUR D'ÉCRITURE DES REVENDICATIONS DE LIGNE.
 *
 * Ce que ces tests prouvent, et qui a d'abord été MESURÉ sur le schéma d'avant
 * (le chemin ci-dessous créait réellement un compte sur la personne d'autrui) :
 * le rôle applicatif ne peut plus écrire phone_claims, donc il ne peut plus
 * désigner sa cible ; et la porte qui lui rend ce droit DÉRIVE la personne du
 * compte au lieu de la recevoir.
 *
 * Chaque test porte son contrôle négatif : sans le REVOKE de 030, l'écriture
 * réussirait et l'assertion tomberait — aucun de ces tests ne peut passer sur
 * le schéma qu'il condamne.
 *
 * Hors transaction, commit réel, sous rôle bridé ET owner (CLAUDE.md §5).
 */
const crypto = assembleCryptoFromEnv(fullKeyringEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
}));

const ARGON2ID = '$argon2id$v=19$m=65536,t=3,p=4$Zml4dHVyZQ$c2VjcmV0LWRlLWZpeHR1cmU';

describe('030 — le service ne désigne plus sa cible', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'persons', 'accounts', 'phone_claims', 'possession_proofs');
  });

  afterAll(async () => {
    await truncateTables(owner, 'persons', 'accounts', 'phone_claims', 'possession_proofs');
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(7300000000 + seq);
  }

  function phoneFields(phone: string): [string, string, string, string] {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    return [fp.value, fp.hmacKeyId, encrypt(crypto.encryption, phone), crypto.encryption.activeKeyId];
  }

  /** Une PERSONNE sans compte — la population que le défaut visait. */
  async function personWithoutAccount(birthYear: number): Promise<string> {
    return firstRow(
      await app.query<{ create_person: string }>(
        'SELECT create_person($1, $2, NULL, NULL, $3) AS create_person',
        [nextIdentifier(), generateErasureSalt(), birthYear],
      ),
    ).create_person;
  }

  async function countAccounts(): Promise<number> {
    return Number(
      firstRow(await owner.query<{ n: string }>('SELECT count(*) AS n FROM accounts')).n,
    );
  }

  test('le droit NU a disparu : le rôle applicatif ne peut plus INSÉRER une revendication', async () => {
    const victim = await personWithoutAccount(2000);
    await expect(
      app.query(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [victim, ...phoneFields('+243810000101')],
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('le droit NU a disparu : le rôle applicatif ne peut plus RÉVOQUER la revendication d\'un tiers', async () => {
    // La revendication légitime est posée sous OWNER : on reproduit l'état du
    // registre, pas le chemin applicatif (qui n'existe plus).
    const victim = await personWithoutAccount(2000);
    const claim = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [victim, ...phoneFields('+243810000102')],
      ),
    ).id;
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claim],
    );

    await expect(
      app.query(
        "UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'REPLACED' WHERE id = $1",
        [claim],
      ),
    ).rejects.toThrow(/permission denied/);

    // Contrôle négatif : la revendication de la victime est INTACTE.
    const after = firstRow(
      await owner.query<{ status: string }>('SELECT status FROM phone_claims WHERE id = $1', [
        claim,
      ]),
    );
    expect(after.status).toBe('ACTIVE');
  });

  test('LE CHEMIN DÉMONTRÉ est fermé à sa première marche — et aucun compte ne naît', async () => {
    const victim = await personWithoutAccount(2000);
    const before = await countAccounts();

    // Marche 1 — poser une revendication sur la personne d'autrui, avec SA
    // PROPRE empreinte. C'est ici que tout le reste devenait possible.
    await expect(
      app.query(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [victim, ...phoneFields('+243810000103')],
      ),
    ).rejects.toThrow(/permission denied/);

    // Marches 2 et 3 — sans revendication, il n'y a rien à prouver : la preuve
    // ne s'ouvre sur rien, et la personne n'a aucune ligne PROUVÉE.
    const opened = firstRow(
      await app.query<{ verdict: string }>(
        `SELECT verdict FROM open_possession_proof(gen_random_uuid(), 'SMS', $1, 'C1', 600, 5, 10, 86400)`,
        ['peu-importe'],
      ),
    );
    expect(opened.verdict).toBe('UNKNOWN');

    // Marche 4 — la prise de compte elle-même. Depuis 031 le rôle applicatif
    // ne peut PLUS L'EXÉCUTER DU TOUT : c'est un contrôle négatif plus fort que
    // le verdict LINE_NOT_PROVEN qu'il rendait avant (un verdict prouve que la
    // fonction a refusé ; ceci prouve qu'elle n'est plus atteignable).
    await expect(
      app.query('SELECT verdict FROM complete_emancipation($1, $2, $3)', [
        victim,
        nextIdentifier(),
        ARGON2ID,
      ]),
    ).rejects.toThrow(/permission denied/);
    expect(await countAccounts()).toBe(before);
  });

  test('la variante RECHARGEABLE est fermée : une revendication forgée ne se recharge plus', async () => {
    // L'état d'AVANT le mur : une revendication forgée survit sur une personne
    // trop jeune (UNDERAGE ajournait, il ne fermait pas). Posée sous owner.
    const minor = await personWithoutAccount(2018);
    const forged = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [minor, ...phoneFields('+243810000104')],
      ),
    ).id;
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [forged],
    );

    // Le rechargement tenait en deux gestes, tous deux retirés par 030 :
    // révoquer la sienne…
    await expect(
      app.query(
        "UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'REPLACED' WHERE id = $1",
        [forged],
      ),
    ).rejects.toThrow(/permission denied/);
    // …puis en reposer une fraîche pour renouveler la preuve.
    await expect(
      app.query(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [minor, ...phoneFields('+243810000105')],
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('LA PORTE : la personne ne peut pas être FOURNIE — elle est dérivée du compte', async () => {
    // Structurel d'abord : aucun paramètre de personne n'existe dans la
    // signature. Ce n'est pas une convention d'appel, c'est une impossibilité.
    const signature = firstRow(
      await owner.query<{ args: string }>(
        `SELECT pg_get_function_arguments(p.oid) AS args FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public' AND p.proname = 'declare_phone_self'`,
      ),
    ).args;
    expect(signature).not.toMatch(/person/i);

    // Comportemental ensuite : la revendication naît sur la personne DU COMPTE.
    const accountId = await createAccountFixture(app, nextIdentifier());
    const declared = firstRow(
      await app.query<{ claim_id: string; verdict: string }>(
        'SELECT * FROM declare_phone_self($1, $2, $3, $4, $5)',
        [accountId, ...phoneFields('+243810000106')],
      ),
    );
    expect(declared.verdict).toBe('DECLARED');

    const owned = firstRow(
      await owner.query<{ same: boolean }>(
        `SELECT (c.person_id = a.person_id) AS same
           FROM phone_claims c JOIN accounts a ON a.id = $2 WHERE c.id = $1`,
        [declared.claim_id, accountId],
      ),
    );
    expect(owned.same).toBe(true);
  });

  test('LA PORTE : verdicts de refus — compte inconnu, compte désactivé', async () => {
    const unknown = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM declare_phone_self($1, $2, $3, $4, $5)',
        ['00000000-0000-0000-0000-000000000000', ...phoneFields('+243810000107')],
      ),
    );
    expect(unknown.verdict).toBe('UNKNOWN_ACCOUNT');

    const accountId = await createAccountFixture(app, nextIdentifier());
    await owner.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    const dead = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM declare_phone_self($1, $2, $3, $4, $5)',
        [accountId, ...phoneFields('+243810000108')],
      ),
    );
    expect(dead.verdict).toBe('ACCOUNT_NOT_ACTIVE');

    // Contrôle négatif : le refus n'a rien écrit.
    const written = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM phone_claims c JOIN accounts a ON a.person_id = c.person_id
          WHERE a.id = $1`,
        [accountId],
      ),
    ).n;
    expect(Number(written)).toBe(0);
  });

  test('ISO-COMPORTEMENT : la revendication PENDING précédente tombe en REPLACED', async () => {
    const accountId = await createAccountFixture(app, nextIdentifier());
    const first = firstRow(
      await app.query<{ claim_id: string }>(
        'SELECT * FROM declare_phone_self($1, $2, $3, $4, $5)',
        [accountId, ...phoneFields('+243810000109')],
      ),
    ).claim_id;
    const second = firstRow(
      await app.query<{ claim_id: string; verdict: string }>(
        'SELECT * FROM declare_phone_self($1, $2, $3, $4, $5)',
        [accountId, ...phoneFields('+243810000110')],
      ),
    );
    expect(second.verdict).toBe('DECLARED');

    const rows = await owner.query<{ id: string; status: string; revoke_reason: string | null }>(
      'SELECT id, status, revoke_reason FROM phone_claims WHERE id = ANY($1)',
      [[first, second.claim_id]],
    );
    // Le nombre de lignes ET leur contenu (un count seul passerait à vide).
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows.find((r) => r.id === first)).toMatchObject({
      status: 'REVOKED',
      revoke_reason: 'REPLACED',
    });
    expect(rows.rows.find((r) => r.id === second.claim_id)).toMatchObject({
      status: 'PENDING',
      revoke_reason: null,
    });
  });
});
