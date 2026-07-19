import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Les murs de 020, sous rôle bridé (les fonctions SONT le chemin) et sous
// owner quand un mur doit tenir au-delà des droits.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const YEAR = new Date().getUTCFullYear();
const FIXTURE_ARGON2ID = '$argon2id$v=19$m=65536,t=3,p=4$Zml4dHVyZQ$c2VjcmV0LWRlLWZpeHR1cmU';

describe('émancipation — les murs en base (020)', () => {
  let app: Pool;
  let owner: Pool;
  let minimumAge: number;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(
      owner,
      'outbox',
      'phone_claims',
      'person_responsibilities',
      'accounts',
      'persons',
    );
    minimumAge = firstRow(
      await owner.query<{ age: number }>('SELECT emancipation_minimum_age() AS age'),
    ).age;
  });

  afterAll(async () => {
    await truncateTables(
      owner,
      'outbox',
      'phone_claims',
      'person_responsibilities',
      'accounts',
      'persons',
    );
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_800_000_000 + seq);
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : la garde n'a pas levé");
  }

  /** Personne identifiée, sans compte, née par le chemin unique. */
  async function person(birthYear: number | null): Promise<{ id: string; identifier: string }> {
    const identifier = nextIdentifier();
    if (birthYear === null) {
      const id = firstRow(
        await owner.query<{ id: string }>('SELECT create_person($1, $2, NULL, NULL, NULL) AS id', [
          identifier,
          generateErasureSalt(),
        ]),
      ).id;
      return { id, identifier };
    }
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: `${birthYear}-06-15`,
    });
    const id = firstRow(
      await owner.query<{ id: string }>('SELECT create_person($1, $2, $3, $4, $5) AS id', [
        identifier,
        salt,
        enc.token,
        enc.encKeyId,
        enc.birthYear,
      ]),
    ).id;
    return { id, identifier };
  }

  async function open(identifier: string, phone: string): Promise<{ claim_id: string | null; verdict: string }> {
    const columns = buildPhoneColumns(crypto, phone);
    return firstRow(
      await app.query<{ claim_id: string | null; verdict: string }>(
        'SELECT * FROM open_emancipation($1, $2, $3, $4, $5)',
        [identifier, columns.phoneHmac, columns.hmacKeyId, columns.phoneEncrypted, columns.encKeyId],
      ),
    );
  }

  /**
   * Forge (owner) l'état que verify_possession_code laisse derrière lui :
   * revendication ACTIVE + preuve SUCCEEDED fraîche (settled_at posé à
   * l'instant — le mur de fraîcheur C14 la voit comme le flux réel).
   */
  async function proveUnderOwner(claimId: string): Promise<void> {
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
    await owner.query(
      `INSERT INTO possession_proofs (claim_id, channel, code_hmac, proof_code_key_id,
                                      max_attempts, expires_at, status, settled_at)
       VALUES ($1, 'SMS', 'hmac-de-fixture', 'C1', 3,
               now() + interval '10 minutes', 'SUCCEEDED', now())`,
      [claimId],
    );
  }

  /**
   * Forge (owner) le scénario C14 : revendication ACTIVE dont la preuve a
   * réussi il y a LONGTEMPS. Aucun trigger d'INSERT sur possession_proofs
   * (007 ne garde que UPDATE/DELETE) : la forge est possible — c'est
   * exactement ce qu'un chemin owner ou un incident de données produirait.
   */
  async function proveUnderOwnerLongAgo(claimId: string, secondsAgo: number): Promise<void> {
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
    await owner.query(
      `INSERT INTO possession_proofs (claim_id, channel, code_hmac, proof_code_key_id,
                                      max_attempts, expires_at, status, settled_at, created_at)
       VALUES ($1, 'SMS', 'hmac-de-fixture', 'C1', 3,
               now() - make_interval(secs => $2::int) + interval '10 minutes',
               'SUCCEEDED',
               now() - make_interval(secs => $2::int) + interval '1 minute',
               now() - make_interval(secs => $2::int))`,
      [claimId, secondsAgo],
    );
  }

  async function complete(personId: string): Promise<{ account_id: string | null; verdict: string }> {
    return firstRow(
      await app.query<{ account_id: string | null; verdict: string }>(
        'SELECT * FROM complete_emancipation($1, $2, $3)',
        [personId, nextIdentifier(), FIXTURE_ARGON2ID],
      ),
    );
  }

  test('ouvrir : identifiant inconnu → UNKNOWN ; personne autonome → HAS_ACCOUNT (verdicts riches, réponse uniforme au service)', async () => {
    expect((await open('1234567890', '+243870000001')).verdict).toBe('UNKNOWN');

    const adultAccount = await createAccount(app, nextIdentifier());
    const adultIdentifier = firstRow(
      await app.query<{ public_identifier: string }>(
        'SELECT p.public_identifier FROM persons p JOIN accounts a ON a.person_id = p.id WHERE a.id = $1',
        [adultAccount],
      ),
    ).public_identifier;
    expect((await open(adultIdentifier, '+243870000002')).verdict).toBe('HAS_ACCOUNT');
  });

  test('LE MUR D\'ÂGE (piège n°2) : un enfant de 5 ans est non émancipable — sans année aussi ; la frontière passe (>=, jamais plus dur)', async () => {
    const child = await person(YEAR - 5);
    expect((await open(child.identifier, '+243870000003')).verdict).toBe('UNDERAGE');

    const unbounded = await person(null);
    expect((await open(unbounded.identifier, '+243870000004')).verdict).toBe('UNDERAGE');

    // diff == seuil : peut-être seize ans révolus, peut-être pas — le mur
    // LAISSE (D-C : il ne mord jamais sur le légitime), la façade du service
    // tranche au jour près.
    const boundary = await person(YEAR - minimumAge);
    const opened = await open(boundary.identifier, '+243870000005');
    expect(opened.verdict).toBe('OPENED');
    expect(opened.claim_id).not.toBeNull();
  });

  test('achever sans ligne PROUVÉE → LINE_NOT_PROVEN ; un enfant avec ligne prouvée reste UNDERAGE (le mur re-vérifie à l\'acte)', async () => {
    const eligible = await person(YEAR - minimumAge - 5);
    const opened = await open(eligible.identifier, '+243870000006');
    expect(opened.verdict).toBe('OPENED');
    expect((await complete(eligible.id)).verdict).toBe('LINE_NOT_PROVEN');

    // Un mineur dont on fabrique (owner) une ligne ACTIVE : le mur d'âge
    // parle QUAND MÊME — la preuve de ligne n'achète pas l'âge.
    const child = await person(YEAR - 5);
    const columns = buildPhoneColumns(crypto, '+243870000007');
    const forged = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [child.id, columns.phoneHmac, columns.hmacKeyId, columns.phoneEncrypted, columns.encKeyId],
      ),
    ).id;
    await proveUnderOwner(forged);
    expect((await complete(child.id)).verdict).toBe('UNDERAGE');
  });

  test('C14 : une revendication ACTIVE ancienne + appel DIRECT à complete_emancipation → PROOF_STALE, aucun compte créé', async () => {
    // Junior a une ligne prouvée il y a deux jours et pas de compte actif —
    // le scénario de la prise de compte : un appel direct (la « v2 de cet
    // endpoint », un job, un chemin admin) tente de poser SON secret sur sa
    // personne. Le service exigerait un code frais ; la BASE doit refuser
    // TOUTE SEULE.
    const junior = await person(YEAR - minimumAge - 2);
    const opened = await open(junior.identifier, '+243870000021');
    expect(opened.verdict).toBe('OPENED');
    await proveUnderOwnerLongAgo(opened.claim_id as string, 2 * 24 * 3600);

    const attacked = await complete(junior.id);
    expect(attacked.verdict).toBe('PROOF_STALE');
    expect(attacked.account_id).toBeNull();

    // L'absence se prouve en COMPTANT : zéro compte n'est pas « pas trouvé ».
    const born = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM accounts WHERE person_id = $1', [
        junior.id,
      ]),
    );
    expect(born.n).toBe('0');
  });

  test('C14 : la fenêtre est LUE de la politique, pas décorative — l\'élargir sous owner change le verdict', async () => {
    // Une preuve d'il y a deux heures : hors fenêtre par défaut (900 s),
    // dans la fenêtre si la politique s'élargit à un jour. Si un jour une
    // constante finit câblée à côté de la colonne, ce test rougit.
    const junior = await person(YEAR - minimumAge - 2);
    const opened = await open(junior.identifier, '+243870000022');
    expect(opened.verdict).toBe('OPENED');
    await proveUnderOwnerLongAgo(opened.claim_id as string, 2 * 3600);

    expect((await complete(junior.id)).verdict).toBe('PROOF_STALE');

    const saved = firstRow(
      await owner.query<{ proof_max_age_seconds: number }>(
        'SELECT proof_max_age_seconds FROM emancipation_policy WHERE singleton',
      ),
    ).proof_max_age_seconds;
    await owner.query('UPDATE emancipation_policy SET proof_max_age_seconds = 86400');
    try {
      const widened = await complete(junior.id);
      expect(widened.verdict).toBe('EMANCIPATED');
      expect(widened.account_id).not.toBeNull();
    } finally {
      await owner.query('UPDATE emancipation_policy SET proof_max_age_seconds = $1', [saved]);
    }
  });

  test('le PARCOURS du sommet : coupure nette au commit, même person_id, ex-responsables prévenus, irréversibilité armée', async () => {
    // Un responsable et son ayant droit (année frontière : attachable ET
    // émancipable — c'est exactement le résidu ± 1 an documenté en 014).
    const responsibleAccount = await createAccount(app, nextIdentifier());
    const responsiblePerson = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        responsibleAccount,
      ]),
    ).person_id;
    const junior = await person(YEAR - minimumAge);
    await owner.query(
      `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
       VALUES ($1, $2, 'RESPONSIBLE')`,
      [responsiblePerson, junior.id],
    );

    // Junior prouve SA ligne (la machinerie du LOT 2, fixture owner ici — le
    // chemin par code réel vit dans le parcours e2e).
    const opened = await open(junior.identifier, '+243870000008');
    expect(opened.verdict).toBe('OPENED');
    await proveUnderOwner(opened.claim_id as string);

    const done = await complete(junior.id);
    expect(done.verdict).toBe('EMANCIPATED');

    // MÊME person_id : l'identité est stable, rien n'a été ressaisi.
    const account = firstRow(
      await app.query<{ person_id: string; status: string }>(
        'SELECT person_id, status FROM accounts WHERE id = $1',
        [done.account_id],
      ),
    );
    expect(account).toEqual({ person_id: junior.id, status: 'ACTIVE' });

    // La coupure : le lien est clos EMANCIPATED — c'est LUI qui arme C11.
    const link = firstRow(
      await app.query<{ status: string; end_reason: string }>(
        'SELECT status, end_reason FROM person_responsibilities WHERE dependent_person_id = $1',
        [junior.id],
      ),
    );
    expect(link).toEqual({ status: 'ENDED', end_reason: 'EMANCIPATED' });

    // L'ex-responsable est prévenu — vers SA personne, dans son compte.
    const event = firstRow(
      await app.query<{ event_type: string; status: string }>(
        'SELECT event_type, status FROM outbox WHERE person_id = $1',
        [responsiblePerson],
      ),
    );
    expect(event).toEqual({ event_type: 'DEPENDENT_EMANCIPATED', status: 'PENDING' });

    // L'IRRÉVERSIBILITÉ (C11, armée par EMANCIPATED) : même compte désactivé,
    // même sous owner, aucun responsable ne revient JAMAIS.
    await owner.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [
      done.account_id,
    ]);
    await expect(
      codeOf(() =>
        owner.query(
          `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
           VALUES ($1, $2, 'RESPONSIBLE')`,
          [responsiblePerson, junior.id],
        ),
      ),
    ).resolves.toBe(DB_ERROR.EMANCIPATION_CUT);

    // Ré-acquisition d'un moyen d'agir : la personne au compte mort et à la
    // ligne toujours PROUVÉE peut recevoir un compte neuf par la même porte
    // (l'unique partiel de 016 n'interdit que la coexistence de deux comptes
    // ACTIFS). Au niveau SERVICE, un code frais reste toujours exigé — la
    // fonction, elle, est gardée par la possession de ligne prouvée
    // FRAÎCHEMENT (C14 : la preuve de cette fixture vient d'être posée, elle
    // est dans la fenêtre — six mois plus tard elle ne le serait plus).
    const reacquired = await complete(junior.id);
    expect(reacquired.verdict).toBe('EMANCIPATED');
    expect(
      firstRow(
        await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
          reacquired.account_id,
        ]),
      ).person_id,
    ).toBe(junior.id);
  });

  test('la porte de naissance n\'est PAS un droit du rôle applicatif (attach_account_to_person sans GRANT)', async () => {
    const somebody = await person(YEAR - 30);
    await expect(
      app.query(
        `SELECT attach_account_to_person($1, $2, 'ACCOUNT_HOLDER', $3, false, NULL)`,
        [somebody.id, nextIdentifier(), FIXTURE_ARGON2ID],
      ),
    ).rejects.toThrow(/permission denied/);
  });
});
