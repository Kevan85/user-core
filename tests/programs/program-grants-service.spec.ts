import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { ProgramGrantsService } from '../../src/programs/program-grants.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// L'ouverture sur personne connue : les murs de 019 rendus en réponses
// propres — adulte à compte, ayant droit né du clic, matrice de réactivation.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});
const references = assembleReferenceKeyring({
  USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1: randomBytes(32).toString('base64') }),
  USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
});

const YEAR = new Date().getUTCFullYear();

describe('/v1/grants — ProgramGrantsService (étape 3)', () => {
  let app: Pool;
  let owner: Pool;
  let service: ProgramGrantsService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    service = new ProgramGrantsService(app);
    await truncateTables(
      owner,
      'program_invitation_dependents',
      'program_idempotency_keys',
      'program_invitations',
      'program_grants',
      'programs',
      'account_secrets',
      'accounts',
      'persons',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function program(mode: 'GRANTED' | 'SELF_SERVICE'): Promise<string> {
    seq += 1;
    return firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', $2) RETURNING id`,
        [`prog-grants-${seq}`, mode],
      ),
    ).id;
  }

  async function adultIdentifier(): Promise<string> {
    seq += 1;
    const accountId = await createAccount(app, String(7_500_000_000 + seq));
    return firstRow(
      await app.query<{ public_identifier: string }>(
        `SELECT p.public_identifier FROM persons p
          JOIN accounts a ON a.person_id = p.id WHERE a.id = $1`,
        [accountId],
      ),
    ).public_identifier;
  }

  test('adulte à compte : GRANTED par le programme, puis ALREADY_ACTIVE — jamais deux droits', async () => {
    const programId = await program('GRANTED');
    const identifier = await adultIdentifier();

    expect((await service.openForKnownPerson(programId, identifier)).outcome).toBe('GRANTED');
    expect((await service.openForKnownPerson(programId, identifier)).outcome).toBe('ALREADY_ACTIVE');

    const rows = firstRow(
      await owner.query<{ n: string; granted_by: string }>(
        `SELECT count(*) AS n, min(granted_by::text) AS granted_by FROM program_grants g
          JOIN persons p ON p.id = g.person_id WHERE p.public_identifier = $1`,
        [identifier],
      ),
    );
    expect(rows).toEqual({ n: '1', granted_by: 'PROGRAM' });
  });

  test('l\'ayant droit né du clic est une personne CONNUE : un deuxième programme s\'ouvre sans compte', async () => {
    const first = await program('GRANTED');
    const second = await program('GRANTED');
    const click = new DependentAccessService(app, crypto, references, {
      dependentInvitationTtlSeconds: 3600,
      inviteClientCap: 1000,
      inviteClientCapWindowSeconds: 3600,
      inviteLineCap: 1000,
      inviteLineCapWindowSeconds: 3600,
    });
    const born = await click.open(first, 'ref-connu', {
      nameComponents: ['Composante'],
      displayName: 'Ayant Droit',
      birthDate: `${YEAR - 9}-06-15`,
    }, '+243850000101');
    if (born.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');

    // Le droit appartient à la PERSONNE : aucun compte exigé (019, délibéré).
    expect((await service.openForKnownPerson(second, born.dependentIdentifier)).outcome).toBe('GRANTED');
  });

  test('la matrice tient : ce que la famille a fermé, elle seule le rouvre (P0110 → CLOSED_BY_FAMILY)', async () => {
    const programId = await program('GRANTED');
    const identifier = await adultIdentifier();
    expect((await service.openForKnownPerson(programId, identifier)).outcome).toBe('GRANTED');

    // La famille ferme (revoke SELF — le geste de son app, droit du rôle).
    await app.query(
      `UPDATE program_grants g SET status = 'REVOKED', revoke_reason = 'SELF'
        FROM persons p
       WHERE p.id = g.person_id AND p.public_identifier = $1 AND g.program_id = $2 AND g.status = 'ACTIVE'`,
      [identifier, programId],
    );

    expect((await service.openForKnownPerson(programId, identifier)).outcome).toBe('CLOSED_BY_FAMILY');
  });

  test('refus propres : personne inconnue, libre-service, programme retiré', async () => {
    const programId = await program('GRANTED');
    expect((await service.openForKnownPerson(programId, '1234567890')).outcome).toBe('NOT_FOUND');

    const selfService = await program('SELF_SERVICE');
    const identifier = await adultIdentifier();
    expect((await service.openForKnownPerson(selfService, identifier)).outcome).toBe('NOT_GRANTED_MODE');

    const retired = await program('GRANTED');
    await owner.query(
      `UPDATE programs SET status = 'RETIRED', retired_at = now() WHERE id = $1`,
      [retired],
    );
    expect((await service.openForKnownPerson(retired, identifier)).outcome).toBe('FORBIDDEN');
  });
});
