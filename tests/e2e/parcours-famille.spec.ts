import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// LE PARCOURS DU LOT /v1, de bout en bout et par les SERVICES : le clic de
// l'école → le droit de l'enfant naît AVANT tout compte parent → le parent
// prouve SA ligne (contre un fournisseur qui MENT — un prouveur du seul
// chemin heureux ne prouve rien) → l'invitation se découvre, nom d'affichage
// seul → l'acceptation crée les liens. Puis la famille existante (zéro
// nouvelle preuve), et le numéro recyclé (dans et hors fenêtre).
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
const codeKeyring = assembleProofCodeKeyring({
  USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1: randomBytes(32).toString('base64') }),
  USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
});
const phoneConfig = assemblePhoneConfig({ PROOF_LINE_CAP: '10' });

const YEAR = new Date().getUTCFullYear();
const LINE = '+243820000001';

describe('e2e — le parcours famille du lot /v1', () => {
  let app: Pool;
  let owner: Pool;
  let prover: LyingProver;
  let phone: PhoneService;
  let click: DependentAccessService;
  let invitations: AccountInvitationsService;
  let programId: string;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    prover = new LyingProver();
    phone = new PhoneService(app, crypto, codeKeyring, prover, phoneConfig);
    click = new DependentAccessService(app, crypto, references, {
      dependentInvitationTtlSeconds: 3600,
      inviteClientCap: 1000,
      inviteClientCapWindowSeconds: 3600,
      inviteLineCap: 1000,
      inviteLineCapWindowSeconds: 3600,
    });
    invitations = new AccountInvitationsService(app, crypto);
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'possession_proofs',
      'program_invitation_dependents',
      'program_idempotency_keys',
      'program_invitation_refusals',
      'program_invitations',
      'program_grants',
      'programs',
      'person_responsibilities',
      'phone_claims',
      'session_refresh_tokens',
      'sessions',
      'account_secrets',
      'accounts',
      'persons',
    );
    programId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ('prog-famille', 'P', 'GRANTED') RETURNING id`,
      ),
    ).id;
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(9_200_000_000 + seq);
  }

  async function proveLine(accountId: string, line: string): Promise<void> {
    const declared = await phone.declare(accountId, line);
    if (declared.outcome !== 'DECLARED') throw new Error(`DECLARED attendu, reçu ${declared.outcome}`);

    // LE FOURNISSEUR MENT d'abord (erreur franche) : rien ne part, la preuve
    // se clôt proprement, et RIEN n'est facturé — puis il redevient honnête
    // (le mensonge PERSISTE tant qu'on ne le lève pas : c'est son contrat).
    prover.willLie('PROVIDER_ERROR');
    expect((await phone.requestProof(accountId, declared.claimId, 'SMS')).outcome).toBe('UNDELIVERABLE');
    prover.willLie('HONEST');

    const sent = await phone.requestProof(accountId, declared.claimId, 'SMS');
    expect(sent.outcome).toBe('SENT');
    const code = prover.delivered[prover.delivered.length - 1]?.code ?? '';

    // Un mauvais code d'abord (le doigt qui glisse) : WRONG, l'essai est
    // compté EN BASE — puis le bon.
    expect((await phone.verify(accountId, declared.claimId, '000000')).outcome).toBe('WRONG');
    expect((await phone.verify(accountId, declared.claimId, code)).outcome).toBe('PROVEN');
  }

  let parentAccount: string;
  let juniorIdentifier: string;

  test('NOUVELLE FAMILLE : le droit de l\'enfant naît au clic — avant tout compte parent — puis la ligne se prouve et les liens naissent', async () => {
    // 1) Le clic de l'école. AUCUN compte n'existe encore.
    const opened = await click.open(programId, 'famille-junior', {
      nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
      displayName: 'Kabeya Junior',
      birthDate: `${YEAR - 9}-03-12`,
    }, LINE);
    if (opened.outcome !== 'ACCEPTED') throw new Error(`ACCEPTED attendu, reçu ${opened.outcome}`);
    juniorIdentifier = opened.dependentIdentifier;

    // Le droit est LÀ, tout de suite — la personne n'a ni compte ni
    // responsable (l'état nommé de 021), et le registre le prouve.
    const state = firstRow(
      await owner.query<{ grants: string; accounts: string; links: string }>(
        `SELECT (SELECT count(*) FROM program_grants g JOIN persons p ON p.id = g.person_id
                  WHERE p.public_identifier = $1 AND g.status = 'ACTIVE') AS grants,
                (SELECT count(*) FROM accounts a JOIN persons p ON p.id = a.person_id
                  WHERE p.public_identifier = $1) AS accounts,
                (SELECT count(*) FROM person_responsibilities r JOIN persons p ON p.id = r.dependent_person_id
                  WHERE p.public_identifier = $1) AS links`,
        [juniorIdentifier],
      ),
    );
    expect(state).toEqual({ grants: '1', accounts: '0', links: '0' });

    // 2) Le parent : compte, puis SA ligne — contre le fournisseur qui ment.
    parentAccount = await createAccount(app, nextIdentifier());
    await proveLine(parentAccount, LINE);

    // 3) La découverte : l'invitation apparaît, NOM D'AFFICHAGE SEUL.
    const listed = await invitations.list(parentAccount);
    expect(listed).toHaveLength(1);
    expect(listed[0]?.dependents).toEqual([{ displayName: 'Kabeya Junior' }]);

    // 4) L'acceptation : le lien naît, l'acceptant ne gagne AUCUN droit.
    expect((await invitations.accept(parentAccount, listed[0]!.id)).outcome).toBe('ACCEPTED');
    const after = firstRow(
      await owner.query<{ links: string; parent_grants: string }>(
        `SELECT (SELECT count(*) FROM person_responsibilities r JOIN accounts a ON a.person_id = r.responsible_person_id
                  WHERE a.id = $1 AND r.status = 'ACTIVE') AS links,
                (SELECT count(*) FROM program_grants g JOIN accounts a ON a.person_id = g.person_id
                  WHERE a.id = $1) AS parent_grants`,
        [parentAccount],
      ),
    );
    expect(after).toEqual({ links: '1', parent_grants: '0' });
  });

  test('FAMILLE EXISTANTE : le deuxième enfant — l\'invitation apparaît IMMÉDIATEMENT, zéro nouvelle preuve', async () => {
    const proofsBefore = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM possession_proofs'),
    ).n;

    const opened = await click.open(programId, 'famille-grace', {
      nameComponents: ['Kabeya', 'Ntumba', 'Grace'],
      displayName: 'Kabeya Grace',
      birthDate: `${YEAR - 7}-11-02`,
    }, LINE);
    if (opened.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');

    // Le rattachement n'a aucun état : la ligne déjà prouvée SUFFIT — la
    // liste montre la nouvelle invitation sans un SMS de plus (compté).
    const listed = await invitations.list(parentAccount);
    expect(listed).toHaveLength(1);
    expect(listed[0]?.dependents).toEqual([{ displayName: 'Kabeya Grace' }]);
    expect(
      firstRow(await owner.query<{ n: string }>('SELECT count(*) AS n FROM possession_proofs')).n,
    ).toBe(proofsBefore);

    expect((await invitations.accept(parentAccount, listed[0]!.id)).outcome).toBe('ACCEPTED');
    const links = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities r JOIN accounts a ON a.person_id = r.responsible_person_id
          WHERE a.id = $1 AND r.status = 'ACTIVE'`,
        [parentAccount],
      ),
    );
    expect(links.n).toBe('2');
  });

  test('LE RECYCLÉ : la preuve la plus récente gagne — la découverte suit la LIGNE, la fenêtre la borne', async () => {
    // Un troisième clic : invitation PENDING pour le troisième enfant.
    const opened = await click.open(programId, 'famille-trois', {
      nameComponents: ['Composante'],
      displayName: 'Troisieme Enfant',
      birthDate: `${YEAR - 6}-01-20`,
    }, LINE);
    if (opened.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');

    // La SIM change de mains : l'inconnu prouve la MÊME ligne par le chemin
    // réel — la revendication du parent tombe (SUPERSEDED), il est prévenu
    // par l'outbox (le patron du recyclage, inchangé).
    const stranger = await createAccount(app, nextIdentifier());
    await proveLine(stranger, LINE);
    const superseded = firstRow(
      await owner.query<{ status: string; revoke_reason: string }>(
        `SELECT c.status, c.revoke_reason FROM phone_claims c
          JOIN accounts a ON a.person_id = c.person_id
         WHERE a.id = $1 ORDER BY c.created_at DESC LIMIT 1`,
        [parentAccount],
      ),
    );
    expect(superseded).toEqual({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });

    // La découverte SUIT LA LIGNE : le parent ne voit plus rien…
    expect(await invitations.list(parentAccount)).toEqual([]);
    // …et l'inconnu, DANS la fenêtre, voit le nom d'affichage du troisième
    // enfant — le résidu déclaré de 021, borné par le TTL, réparable par
    // acte staff (end_responsibility).
    const strangerSees = await invitations.list(stranger);
    expect(strangerSees).toHaveLength(1);
    expect(strangerSees[0]?.dependents).toEqual([{ displayName: 'Troisieme Enfant' }]);

    // HORS fenêtre : plus rien — ni liste, ni acceptation, ni lien (compté).
    const invitationId = strangerSees[0]!.id;
    await owner.query('ALTER TABLE program_invitations DISABLE TRIGGER USER');
    try {
      await owner.query(
        `UPDATE program_invitations SET created_at = now() - interval '2 hours',
                expires_at = now() - interval '1 second' WHERE id = $1`,
        [invitationId],
      );
    } finally {
      await owner.query('ALTER TABLE program_invitations ENABLE TRIGGER USER');
    }
    expect(await invitations.list(stranger)).toEqual([]);
    expect((await invitations.accept(stranger, invitationId)).outcome).toBe('EXPIRED');
    const strangerLinks = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities r JOIN accounts a ON a.person_id = r.responsible_person_id
          WHERE a.id = $1`,
        [stranger],
      ),
    );
    expect(strangerLinks.n).toBe('0');
  });
});
