import { randomBytes, randomUUID } from 'crypto';
import { Pool } from 'pg';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de la migration 012 : LE PIÈGE (l'invitation ne dit jamais si le
// numéro est connu), les deux plafonds (ligne = silence journalisé, client =
// refus franc), le rattachement (la preuve de ligne est le seul sésame), et
// la règle de Kevin (ce que la famille a fermé, elle seule le rouvre).
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const TTL = 3600;
const WINDOW = 86400;

interface OpenResult {
  invitation_id: string | null;
  verdict: string;
}

describe('program_invitations — invariants en base', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  beforeEach(async () => {
    await truncateTables(
      owner,
      'program_invitation_refusals',
      'program_invitations',
      'program_grants',
      'programs',
      'phone_claims',
      'accounts',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newProgram(
    code: string,
    mode: 'SELF_SERVICE' | 'GRANTED' = 'GRANTED',
  ): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        'INSERT INTO programs (code, label, access_mode) VALUES ($1, $1, $2) RETURNING id',
        [code, mode],
      ),
    ).id;
  }

  async function newAccount(): Promise<string> {
    seq += 1;
    return createAccountFixture(app, String(8300000000 + seq));
  }

  /** Revendication ACTIVE (prouvée) — fixture sous owner : seul le chemin de
   *  vérification (007) peut activer en réel, hors de propos ici. */
  async function proveLine(accountId: string, phone: string): Promise<string> {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    const claimId = firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [accountId, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, phone), 'E1'],
      ),
    ).id;
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
    return claimId;
  }

  async function open(
    programId: string,
    phone: string,
    caps: { clientCap?: number; lineCap?: number; ttl?: number } = {},
  ): Promise<OpenResult> {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    return firstRow(
      await app.query<OpenResult>(
        'SELECT * FROM open_program_invitation($1, $2, $3, $4, $5, $6, $7, $8)',
        [
          programId,
          fp.value,
          fp.hmacKeyId,
          caps.ttl ?? TTL,
          caps.clientCap ?? 100,
          WINDOW,
          caps.lineCap ?? 3,
          WINDOW,
        ],
      ),
    );
  }

  async function accept(invitationId: string, accountId: string): Promise<string> {
    return firstRow(
      await app.query<{ accept_program_invitation: string }>(
        'SELECT accept_program_invitation($1, $2)',
        [invitationId, accountId],
      ),
    ).accept_program_invitation;
  }

  async function decline(invitationId: string, accountId: string): Promise<string> {
    return firstRow(
      await app.query<{ decline_program_invitation: string }>(
        'SELECT decline_program_invitation($1, $2)',
        [invitationId, accountId],
      ),
    ).decline_program_invitation;
  }

  // ---------------------------------------------------------------------------
  // LE PIÈGE : l'invitation ne dit JAMAIS si le numéro est connu
  // ---------------------------------------------------------------------------

  test('numéro CONNU et numéro INCONNU → verdict et FORME strictement identiques', async () => {
    const programId = await newProgram('prog-piege');
    const holder = await newAccount();
    await proveLine(holder, '+243890000001'); // celui-ci est connu de l'écosystème

    const known = await open(programId, '+243890000001');
    const unknown = await open(programId, '+243890000002');

    expect(known.verdict).toBe('RECEIVED');
    expect(unknown.verdict).toBe('RECEIVED');
    // La forme close, comparée clé à clé : rien ne distingue les deux mondes.
    expect(Object.keys(known)).toEqual(Object.keys(unknown));
    expect(typeof known.invitation_id).toBe('string');
    expect(typeof unknown.invitation_id).toBe('string');
  });

  test('idempotence : ré-inviter la même ligne → LA MÊME invitation, une seule ligne', async () => {
    const programId = await newProgram('prog-idem');
    const first = await open(programId, '+243890000010');
    const second = await open(programId, '+243890000010');
    expect(second.verdict).toBe('RECEIVED_EXISTING');
    expect(second.invitation_id).toBe(first.invitation_id);
    const count = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_invitations'),
    );
    expect(Number(count.n)).toBe(1);
  });

  test('deux programmes, même ligne → deux invitations indépendantes', async () => {
    const p1 = await newProgram('prog-un');
    const p2 = await newProgram('prog-deux');
    const a = await open(p1, '+243890000011');
    const b = await open(p2, '+243890000011');
    expect(a.verdict).toBe('RECEIVED');
    expect(b.verdict).toBe('RECEIVED');
    expect(a.invitation_id).not.toBe(b.invitation_id);
  });

  test('clôture paresseuse : une PENDING expirée cède la place à une neuve', async () => {
    const programId = await newProgram('prog-lazy');
    const fp = fingerprintOf(crypto.fingerprint, '+243890000012');
    const staleId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at, created_at)
         VALUES ($1, $2, $3, now() - interval '1 day', now() - interval '2 days') RETURNING id`,
        [programId, fp.value, fp.hmacKeyId],
      ),
    ).id;

    const reopened = await open(programId, '+243890000012');
    expect(reopened.verdict).toBe('RECEIVED');
    expect(reopened.invitation_id).not.toBe(staleId);
    const stale = firstRow(
      await owner.query<{ status: string }>(
        'SELECT status FROM program_invitations WHERE id = $1',
        [staleId],
      ),
    );
    expect(stale.status).toBe('EXPIRED');
  });

  // ---------------------------------------------------------------------------
  // Les plafonds : ligne = silence journalisé, client = refus franc
  // ---------------------------------------------------------------------------

  test('plafond PAR CLIENT → refus FRANC, journalisé, aucune invitation créée', async () => {
    const programId = await newProgram('prog-capc');
    await open(programId, '+243890000020', { clientCap: 2 });
    await open(programId, '+243890000021', { clientCap: 2 });
    const third = await open(programId, '+243890000022', { clientCap: 2 });

    expect(third.verdict).toBe('REFUSED_CLIENT_CAP');
    expect(third.invitation_id).toBeNull();

    const invitations = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_invitations'),
    );
    expect(Number(invitations.n)).toBe(2);
    const refusals = await owner.query<{ reason: string }>(
      'SELECT reason FROM program_invitation_refusals',
    );
    expect(refusals.rows).toHaveLength(1);
    expect(refusals.rows[0]?.reason).toBe('CLIENT_INVITE_CAP');
  });

  test('plafond PAR LIGNE → refus SILENCIEUX : accusé indiscernable, ligne suppressed, sondage journalisé', async () => {
    const line = '+243890000030';
    const p1 = await newProgram('prog-la');
    const p2 = await newProgram('prog-lb');
    const p3 = await newProgram('prog-lc');
    const visible = await open(p1, line, { lineCap: 2 });
    await open(p2, line, { lineCap: 2 });
    const silenced = await open(p3, line, { lineCap: 2 });

    // Verdict INTERNE distinct (or du support), mais tout ce qui est visible
    // du client — la forme, le type de l'id — est identique.
    expect(silenced.verdict).toBe('SUPPRESSED');
    expect(Object.keys(silenced)).toEqual(Object.keys(visible));
    expect(typeof silenced.invitation_id).toBe('string');

    const row = firstRow(
      await owner.query<{ suppressed: boolean; status: string }>(
        'SELECT suppressed, status FROM program_invitations WHERE id = $1',
        [silenced.invitation_id],
      ),
    );
    expect(row).toEqual({ suppressed: true, status: 'PENDING' });

    const refusals = await owner.query<{ reason: string }>(
      'SELECT reason FROM program_invitation_refusals',
    );
    expect(refusals.rows).toHaveLength(1);
    expect(refusals.rows[0]?.reason).toBe('LINE_INVITE_CAP');
  });

  test('idempotence sous silence : ré-inviter rend LE MÊME id — l\'oracle du plafond est fermé', async () => {
    const line = '+243890000031';
    const p1 = await newProgram('prog-oa');
    const p2 = await newProgram('prog-ob');
    const p3 = await newProgram('prog-oc');
    await open(p1, line, { lineCap: 2 });
    await open(p2, line, { lineCap: 2 });
    const first = await open(p3, line, { lineCap: 2 });
    const again = await open(p3, line, { lineCap: 2 });
    // Même id sur le chemin réel ET sur le chemin silencieux : comparer deux
    // réponses n'apprend rien.
    expect(again.verdict).toBe('RECEIVED_EXISTING');
    expect(again.invitation_id).toBe(first.invitation_id);
  });

  test('une invitation suppressed est INACCEPTABLE, même par le détenteur légitime de la ligne', async () => {
    const line = '+243890000032';
    const p1 = await newProgram('prog-sa');
    const p2 = await newProgram('prog-sb');
    const p3 = await newProgram('prog-sc');
    await open(p1, line, { lineCap: 2 });
    await open(p2, line, { lineCap: 2 });
    const silenced = await open(p3, line, { lineCap: 2 });

    const holder = await newAccount();
    await proveLine(holder, line);
    expect(await accept(silenced.invitation_id!, holder)).toBe('UNKNOWN');

    const grants = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_grants'),
    );
    expect(Number(grants.n)).toBe(0);
  });

  test('levée du silence : quand le plafond se libère, ré-inviter rend l\'invitation VISIBLE', async () => {
    const line = '+243890000033';
    const p1 = await newProgram('prog-va');
    const p2 = await newProgram('prog-vb');
    const p3 = await newProgram('prog-vc');
    await open(p1, line, { lineCap: 2 });
    await open(p2, line, { lineCap: 2 });
    const silenced = await open(p3, line, { lineCap: 2 });

    // Le plafond monte (config) : la ré-invitation promeut la ligne existante
    // — le programme n'attend pas l'expiration du TTL pour être vu.
    const promoted = await open(p3, line, { lineCap: 10 });
    expect(promoted.invitation_id).toBe(silenced.invitation_id);
    const row = firstRow(
      await owner.query<{ suppressed: boolean }>(
        'SELECT suppressed FROM program_invitations WHERE id = $1',
        [silenced.invitation_id],
      ),
    );
    expect(row.suppressed).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // Le rattachement : la preuve de ligne est le seul sésame
  // ---------------------------------------------------------------------------

  test('ligne DÉJÀ prouvée : le compte voit l\'invitation par SA ligne, accepte, le droit naît', async () => {
    const line = '+243890000040';
    const programId = await newProgram('prog-ratt');
    const holder = await newAccount();
    await proveLine(holder, line);

    const invited = await open(programId, line);

    // La découverte est un SELECT par l'empreinte de la ligne prouvée du
    // compte — aucun état de « nouage » à maintenir nulle part.
    const fp = fingerprintOf(crypto.fingerprint, line);
    const visible = await app.query<{ id: string }>(
      `SELECT i.id FROM program_invitations i
        WHERE i.hmac_key_id = $1 AND i.phone_hmac = $2
          AND i.status = 'PENDING' AND NOT i.suppressed AND i.expires_at > now()`,
      [fp.hmacKeyId, fp.value],
    );
    expect(visible.rows).toHaveLength(1);
    expect(visible.rows[0]?.id).toBe(invited.invitation_id);

    expect(await accept(invited.invitation_id!, holder)).toBe('ACCEPTED');

    const grant = firstRow(
      await owner.query<{ granted_by: string; status: string }>(
        'SELECT granted_by, status FROM program_grants WHERE account_id = $1',
        [holder],
      ),
    );
    expect(grant).toEqual({ granted_by: 'PROGRAM', status: 'ACTIVE' });

    const inv = firstRow(
      await owner.query<{ status: string; accepted_account_id: string; age_seconds: number }>(
        `SELECT status, accepted_account_id,
                EXTRACT(EPOCH FROM (now() - settled_at))::float AS age_seconds
           FROM program_invitations WHERE id = $1`,
        [invited.invitation_id],
      ),
    );
    expect(inv.status).toBe('ACCEPTED');
    expect(inv.accepted_account_id).toBe(holder);
    expect(inv.age_seconds).toBeLessThan(60);
  });

  test('ligne INCONNUE : l\'invitation attend ; elle se noue À LA PREUVE, jamais avant', async () => {
    const line = '+243890000041';
    const programId = await newProgram('prog-noue');
    const invited = await open(programId, line);

    const person = await newAccount();
    // Pas de revendication du tout → rien.
    expect(await accept(invited.invitation_id!, person)).toBe('LINE_NOT_PROVEN');

    // Revendication DÉCLARÉE (PENDING) → toujours rien : déclarer n'est pas prouver.
    const fp = fingerprintOf(crypto.fingerprint, line);
    const claimId = firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, 'E1') RETURNING id`,
        [person, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, line)],
      ),
    ).id;
    expect(await accept(invited.invitation_id!, person)).toBe('LINE_NOT_PROVEN');

    // La SIM répond (fixture owner) → l'invitation devient acceptable.
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
    expect(await accept(invited.invitation_id!, person)).toBe('ACCEPTED');
  });

  test('BOLA en base : un compte qui a prouvé une AUTRE ligne n\'accepte pas, même avec l\'uuid', async () => {
    const programId = await newProgram('prog-bola');
    const invited = await open(programId, '+243890000042');
    const stranger = await newAccount();
    await proveLine(stranger, '+243890000043');

    expect(await accept(invited.invitation_id!, stranger)).toBe('LINE_NOT_PROVEN');
    const inv = firstRow(
      await owner.query<{ status: string }>(
        'SELECT status FROM program_invitations WHERE id = $1',
        [invited.invitation_id],
      ),
    );
    expect(inv.status).toBe('PENDING');
  });

  test('décliner : aucune trace côté programme qu\'un refus a eu lieu, aucun droit, clôture datée', async () => {
    const line = '+243890000044';
    const programId = await newProgram('prog-decl');
    const holder = await newAccount();
    await proveLine(holder, line);
    const invited = await open(programId, line);

    expect(await decline(invited.invitation_id!, holder)).toBe('DECLINED');
    expect(await accept(invited.invitation_id!, holder)).toBe('ALREADY_SETTLED');

    const grants = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_grants'),
    );
    expect(Number(grants.n)).toBe(0);
  });

  test('accepter deux fois → ALREADY_SETTLED ; accepter une expirée → EXPIRED (et la ligne se clôt)', async () => {
    const line = '+243890000045';
    const programId = await newProgram('prog-fin');
    const holder = await newAccount();
    await proveLine(holder, line);

    const invited = await open(programId, line);
    expect(await accept(invited.invitation_id!, holder)).toBe('ACCEPTED');
    expect(await accept(invited.invitation_id!, holder)).toBe('ALREADY_SETTLED');

    // Une invitation posée expirée (fixture owner, backdatée). Pas besoin de
    // prouver cette ligne : le verdict EXPIRED tombe AVANT le contrôle BOLA.
    const fp = fingerprintOf(crypto.fingerprint, '+243890000046');
    const staleId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at, created_at)
         VALUES ($1, $2, $3, now() - interval '1 hour', now() - interval '2 hours') RETURNING id`,
        [programId, fp.value, fp.hmacKeyId],
      ),
    ).id;
    expect(await accept(staleId, holder)).toBe('EXPIRED');
    const stale = firstRow(
      await owner.query<{ status: string }>(
        'SELECT status FROM program_invitations WHERE id = $1',
        [staleId],
      ),
    );
    expect(stale.status).toBe('EXPIRED');
  });

  // ---------------------------------------------------------------------------
  // La règle de Kevin : ce que la famille a fermé, elle seule le rouvre
  // ---------------------------------------------------------------------------

  test('un programme n\'ouvre un droit QUE sur le mode accordé (P0110, sous rôle bridé)', async () => {
    const programId = await newProgram('prog-libre', 'SELF_SERVICE');
    const account = await newAccount();
    await expect(
      app.query(
        "INSERT INTO program_grants (account_id, program_id, granted_by) VALUES ($1, $2, 'PROGRAM')",
        [account, programId],
      ),
    ).rejects.toMatchObject({ code: 'P0110' });
  });

  test('la famille a fermé (SELF) → le programme ne ré-impose PAS (P0110, gravé)', async () => {
    const programId = await newProgram('prog-kevin');
    const account = await newAccount();
    await app.query(
      "INSERT INTO program_grants (account_id, program_id, granted_by) VALUES ($1, $2, 'PROGRAM')",
      [account, programId],
    );
    await app.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF'
        WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
      [account, programId],
    );
    // Ni sous rôle bridé, ni sous OWNER : le trigger tient aux deux étages.
    await expect(
      app.query(
        "INSERT INTO program_grants (account_id, program_id, granted_by) VALUES ($1, $2, 'PROGRAM')",
        [account, programId],
      ),
    ).rejects.toMatchObject({ code: 'P0110' });
    await expect(
      owner.query(
        "INSERT INTO program_grants (account_id, program_id, granted_by) VALUES ($1, $2, 'PROGRAM')",
        [account, programId],
      ),
    ).rejects.toMatchObject({ code: 'P0110' });
  });

  test('après fermeture SELF, ACCEPTER une invitation = le clic de la famille → droit rené granted_by=SELF', async () => {
    const line = '+243890000050';
    const programId = await newProgram('prog-clic');
    const holder = await newAccount();
    await proveLine(holder, line);

    // Cycle : le programme ouvre (invitation), la famille ferme, ré-invitation.
    const first = await open(programId, line);
    expect(await accept(first.invitation_id!, holder)).toBe('ACCEPTED');
    await app.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF'
        WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
      [holder, programId],
    );

    const second = await open(programId, line);
    expect(await accept(second.invitation_id!, holder)).toBe('ACCEPTED');

    const grants = await owner.query<{ granted_by: string; status: string }>(
      'SELECT granted_by, status FROM program_grants WHERE account_id = $1 ORDER BY seq',
      [holder],
    );
    expect(grants.rows).toHaveLength(2);
    expect(grants.rows[1]).toEqual({ granted_by: 'SELF', status: 'ACTIVE' });
  });

  test('après retrait par le PROGRAMME, le programme peut rouvrir (il rouvre ce qu\'il a fermé)', async () => {
    const programId = await newProgram('prog-rouvre');
    const account = await newAccount();
    await app.query(
      "INSERT INTO program_grants (account_id, program_id, granted_by) VALUES ($1, $2, 'PROGRAM')",
      [account, programId],
    );
    await app.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'PROGRAM'
        WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
      [account, programId],
    );
    await expect(
      app.query(
        "INSERT INTO program_grants (account_id, program_id, granted_by) VALUES ($1, $2, 'PROGRAM')",
        [account, programId],
      ),
    ).resolves.toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // Machine d'état, clé d'empreinte, droits du rôle
  // ---------------------------------------------------------------------------

  test('contenu immuable, clôture figée, horodatages de la base (P0101/P0103/P0104, sous owner)', async () => {
    const line = '+243890000060';
    const programId = await newProgram('prog-etat');
    const holder = await newAccount();
    await proveLine(holder, line);
    const invited = await open(programId, line);

    await expect(
      owner.query("UPDATE program_invitations SET phone_hmac = 'falsifie' WHERE id = $1", [
        invited.invitation_id,
      ]),
    ).rejects.toMatchObject({ code: 'P0101' });
    await expect(
      owner.query(
        "UPDATE program_invitations SET expires_at = now() + interval '1 year' WHERE id = $1",
        [invited.invitation_id],
      ),
    ).rejects.toMatchObject({ code: 'P0101' });
    await expect(
      owner.query("UPDATE program_invitations SET settled_at = now() WHERE id = $1", [
        invited.invitation_id,
      ]),
    ).rejects.toMatchObject({ code: 'P0104' });
    await expect(
      owner.query('UPDATE program_invitations SET accepted_account_id = $2 WHERE id = $1', [
        invited.invitation_id,
        holder,
      ]),
    ).rejects.toMatchObject({ code: 'P0104' });
    // Cacher une invitation visible = réécrire l'histoire → P0102.
    await expect(
      owner.query('UPDATE program_invitations SET suppressed = true WHERE id = $1', [
        invited.invitation_id,
      ]),
    ).rejects.toMatchObject({ code: 'P0102' });

    await accept(invited.invitation_id!, holder);
    await expect(
      owner.query("UPDATE program_invitations SET status = 'DECLINED' WHERE id = $1", [
        invited.invitation_id,
      ]),
    ).rejects.toMatchObject({ code: 'P0103' });
  });

  test('empreinte sous une clé PÉRIMÉE → P0109 ; programme RETIRED → UNKNOWN_PROGRAM et P0108', async () => {
    const programId = await newProgram('prog-cles');
    await expect(
      owner.query(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at)
         VALUES ($1, 'empreinte', 'H0', now() + interval '1 day')`,
        [programId],
      ),
    ).rejects.toMatchObject({ code: 'P0109' });

    const retired = await newProgram('prog-retire');
    await owner.query(
      "UPDATE programs SET status = 'RETIRED', retired_at = now() WHERE id = $1",
      [retired],
    );
    const refused = await open(retired, '+243890000061');
    expect(refused.verdict).toBe('UNKNOWN_PROGRAM');
    await expect(
      owner.query(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at)
         VALUES ($1, 'empreinte', 'H1', now() + interval '1 day')`,
        [retired],
      ),
    ).rejects.toMatchObject({ code: 'P0108' });
  });

  test('le rôle bridé n\'écrit RIEN : INSERT/UPDATE/DELETE/TRUNCATE refusés, journal figé sous owner', async () => {
    const programId = await newProgram('prog-droits');
    const invited = await open(programId, '+243890000062');

    await expect(
      app.query(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at)
         VALUES ($1, 'x', 'H1', now() + interval '1 day')`,
        [programId],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query("UPDATE program_invitations SET status = 'DECLINED' WHERE id = $1", [
        invited.invitation_id,
      ]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query('DELETE FROM program_invitations WHERE id = $1', [invited.invitation_id]),
    ).rejects.toThrow(/permission denied/);
    await expect(app.query('TRUNCATE program_invitations CASCADE')).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      app.query(
        "INSERT INTO program_invitation_refusals (program_id, phone_hmac, hmac_key_id, reason) VALUES ($1, 'x', 'H1', 'LINE_INVITE_CAP')",
        [programId],
      ),
    ).rejects.toThrow(/permission denied/);

    // Sous owner, les triggers tiennent : DELETE interdit, journal immuable.
    await expect(
      owner.query('DELETE FROM program_invitations WHERE id = $1', [invited.invitation_id]),
    ).rejects.toMatchObject({ code: 'P0107' });

    const p2 = await newProgram('prog-droits-2');
    await open(p2, '+243890000063', { clientCap: 0 }); // force un refus journalisé
    await expect(
      owner.query("UPDATE program_invitation_refusals SET reason = 'LINE_INVITE_CAP'"),
    ).rejects.toMatchObject({ code: 'P0101' });
    await expect(owner.query('DELETE FROM program_invitation_refusals')).rejects.toMatchObject({
      code: 'P0107',
    });
  });

  test('accepter avec un uuid inconnu → UNKNOWN, rien ne fuit', async () => {
    const holder = await newAccount();
    await proveLine(holder, '+243890000064');
    expect(await accept(randomUUID(), holder)).toBe('UNKNOWN');
  });
});
