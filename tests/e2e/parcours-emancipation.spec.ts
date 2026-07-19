import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { CountingDispatcher } from '../../src/dispatch/simulator/counting-dispatcher';
import { OutboxPublisher } from '../../src/outbox/publisher';
import { EmancipationService } from '../../src/persons/emancipation.service';
import { ResponsibilitiesService } from '../../src/persons/responsibilities.service';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { createAccount } from '../helpers/accounts';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// LE PARCOURS DU LOT, de bout en bout et par les SERVICES (aucune fixture
// owner sur le chemin nominal) : rattachement → droits de la personne →
// émancipation par SA ligne → coupure nette, identité stable, ex-responsable
// prévenu dans son compte, irréversibilité — et le test ② de C1 rejoué dans
// le flux réel (l'émancipation entamée jamais achevée ne bloque pas la
// reprise de la ligne par sa détentrice légitime).
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
const phoneConfig = assemblePhoneConfig({ PROOF_LINE_CAP: '10' });

// Une date de naissance « il y a N ans et quelques jours » : l'âge EXACT vaut
// N quel que soit le jour du calendrier où la CI tourne.
function birthDateYearsAgo(years: number, extraDays: number): string {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() - years);
  d.setUTCDate(d.getUTCDate() - extraDays);
  return d.toISOString().slice(0, 10);
}

describe('e2e — rattachement, émancipation, coupure nette (LOT 5)', () => {
  const authConfig = testAuthAssembly();
  let app: Pool;
  let owner: Pool;
  let provider: LocalAuthenticationProvider;
  let auth: AuthService;
  let prover: LyingProver;
  let responsibilities: ResponsibilitiesService;
  let emancipation: EmancipationService;
  let phone: PhoneService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    provider = new LocalAuthenticationProvider(authConfig);
    await provider.init();
    auth = new AuthService(app, provider, provider, authConfig, new LoginThrottle(1000, 60));
    prover = new LyingProver();
    responsibilities = new ResponsibilitiesService(app, crypto);
    emancipation = new EmancipationService(
      app,
      crypto,
      codeKeyring,
      prover,
      phoneConfig,
      provider,
      authConfig,
      new LoginThrottle(1000, 60),
    );
    phone = new PhoneService(app, crypto, codeKeyring, prover, phoneConfig);
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'possession_proofs',
      'phone_claims',
      'program_grants',
      'programs',
      'person_responsibilities',
      'session_refresh_tokens',
      'sessions',
      'account_secrets',
      'accounts',
      'persons',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_900_000_000 + seq);
  }

  test('le parcours complet — et rien à transférer à la fin', async () => {
    // 1) Le parent existe et rattache Junior (9 ans) — le chemin réel.
    const parentAccount = await createAccount(app, nextIdentifier());
    const parentPerson = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        parentAccount,
      ]),
    ).person_id;
    const attached = await responsibilities.attach(parentAccount, {
      nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
      displayName: 'Kabeya Junior',
      birthDate: birthDateYearsAgo(10, 5), // dix ans révolus, stable au calendrier
    });
    if (attached.outcome !== 'OK') throw new Error(`OK attendu, reçu ${attached.outcome}`);

    // 2) « Scolaria pour Junior » : le droit est À LA PERSONNE du mineur.
    const programId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ('prog-e2e', 'P', 'SELF_SERVICE')
         RETURNING id`,
      ),
    ).id;
    await app.query(
      `INSERT INTO program_grants (person_id, program_id, granted_by) VALUES ($1, $2, 'SELF')`,
      [attached.dependentPersonId, programId],
    );

    // 3) Les années passent : la POLITIQUE le dit (paramétrable, jamais le
    //    code) — le harnais la baisse sous owner, comme une migration signée
    //    le ferait, et la restaure en fin de test.
    await owner.query('UPDATE emancipation_policy SET minimum_age_years = 10');
    try {
      // 4) Junior prouve SA ligne — endpoints publics, par le code réel.
      const line = '+243890000101';
      const started = await emancipation.start(
        attached.dependentPublicIdentifier,
        line,
        'SMS',
        '10.9.0.1',
      );
      expect(started.outcome).toBe('ACCEPTED');
      const code = prover.delivered[prover.delivered.length - 1]?.code ?? '';
      expect(code).toMatch(/^[0-9]{6}$/);

      const done = await emancipation.complete(
        attached.dependentPublicIdentifier,
        code,
        'S3cretDeJunior!',
        '10.9.0.2',
      );
      if (done.outcome !== 'EMANCIPATED') throw new Error(`EMANCIPATED attendu, reçu ${done.outcome}`);

      // 5) Le compte est RÉEL : Junior se connecte avec ce qui lui a été rendu.
      const login = await auth.login(done.accountIdentifier, 'S3cretDeJunior!', '10.9.0.3');
      expect(login.outcome).toBe('OK');

      // MÊME person_id — identité stable, zéro ressaisie.
      const account = firstRow(
        await app.query<{ person_id: string }>(
          'SELECT person_id FROM accounts WHERE public_identifier = $1',
          [done.accountIdentifier],
        ),
      );
      expect(account.person_id).toBe(attached.dependentPersonId);

      // 6) LA COUPURE NETTE : lien clos EMANCIPATED…
      const link = firstRow(
        await app.query<{ status: string; end_reason: string }>(
          'SELECT status, end_reason FROM person_responsibilities WHERE dependent_person_id = $1',
          [attached.dependentPersonId],
        ),
      );
      expect(link).toEqual({ status: 'ENDED', end_reason: 'EMANCIPATED' });

      // …RIEN à transférer : le droit était déjà le sien, il l'a toujours.
      const grant = firstRow(
        await app.query<{ status: string }>(
          'SELECT status FROM program_grants WHERE person_id = $1',
          [attached.dependentPersonId],
        ),
      );
      expect(grant.status).toBe('ACTIVE');

      // …l'ex-responsable ne reprend JAMAIS la main (C11, armé par EMANCIPATED).
      await expect(
        responsibilities.addCoResponsible(
          parentAccount,
          attached.dependentPersonId,
          firstRow(
            await app.query<{ public_identifier: string }>(
              'SELECT public_identifier FROM persons WHERE id = $1',
              [parentPerson],
            ),
          ).public_identifier,
        ),
      ).resolves.toEqual({ outcome: 'NOT_RESPONSIBLE' }); // il ne l'est plus — et ne le redeviendra pas

      // 7) Le parent est prévenu DANS SON COMPTE — zéro envoi externe.
      const dispatcher = new CountingDispatcher();
      const publisher = new OutboxPublisher(app, dispatcher, crypto, {
        batchSize: 20,
        leaseSeconds: 1,
        maxAttempts: 5,
        backoffBaseSeconds: 1,
        backoffCapSeconds: 1,
      });
      const report = await publisher.drain();
      expect(report.published).toBeGreaterThanOrEqual(1);
      expect(dispatcher.calls).toBe(0); // l'absence se prouve en COMPTANT
      const notified = firstRow(
        await owner.query<{ n: string }>(
          `SELECT count(*) AS n FROM account_notifications
            WHERE account_id = $1 AND event_type = 'DEPENDENT_EMANCIPATED'`,
          [parentAccount],
        ),
      );
      expect(notified.n).toBe('1');
    } finally {
      await owner.query('UPDATE emancipation_policy SET minimum_age_years = 16');
    }
  });

  test('sans oracle : identifiant inconnu et personne autonome rendent LA MÊME réponse — et AUCUN envoi', async () => {
    const before = prover.deliveries;
    expect(
      (await emancipation.start('1234567890', '+243890000102', 'SMS', '10.9.1.1')).outcome,
    ).toBe('ACCEPTED');

    const adult = await createAccount(app, nextIdentifier());
    const adultIdentifier = firstRow(
      await app.query<{ public_identifier: string }>(
        `SELECT p.public_identifier FROM persons p
          JOIN accounts a ON a.person_id = p.id WHERE a.id = $1`,
        [adult],
      ),
    ).public_identifier;
    expect(
      (await emancipation.start(adultIdentifier, '+243890000103', 'SMS', '10.9.1.2')).outcome,
    ).toBe('ACCEPTED');

    // Rien n'est parti : ni pour l'inconnu, ni pour l'autonome (espion).
    expect(prover.deliveries).toBe(before);
  });

  test('test ② de C1, dans le flux réel : l\'émancipation entamée jamais achevée ne bloque pas la détentrice légitime', async () => {
    // Un deuxième mineur, rattaché, entame son émancipation avec la ligne L…
    const parent2 = await createAccount(app, nextIdentifier());
    const attached2 = await responsibilities.attach(parent2, {
      nameComponents: ['Deuxieme'],
      displayName: 'Deuxieme Mineur',
      birthDate: birthDateYearsAgo(10, 5),
    });
    if (attached2.outcome !== 'OK') throw new Error('OK attendu');

    const line = '+243890000104';
    await owner.query('UPDATE emancipation_policy SET minimum_age_years = 10');
    try {
      await emancipation.start(attached2.dependentPublicIdentifier, line, 'SMS', '10.9.2.1');
      const code = prover.delivered[prover.delivered.length - 1]?.code ?? '';
      // Le code est vérifié (la ligne devient ACTIVE pour cette personne SANS
      // compte)… et l'acte n'est JAMAIS achevé.
      const claimId = firstRow(
        await app.query<{ id: string }>(
          `SELECT id FROM phone_claims WHERE person_id = $1 AND status = 'PENDING'`,
          [attached2.dependentPersonId],
        ),
      ).id;
      const { hashProofCodeUnder } = await import('../../src/proving/proof-code');
      const hmac = hashProofCodeUnder(codeKeyring, 'C1', code);
      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM verify_possession_code($1, $2)', [
          claimId,
          hmac,
        ]),
      );
      expect(verdict.verdict).toBe('PROVEN');
    } finally {
      await owner.query('UPDATE emancipation_policy SET minimum_age_years = 16');
    }

    // …la mère — détentrice réelle de la SIM — reprend SA ligne, par le
    // chemin normal d'un compte. AVANT 018 : abort. Ici : reprise.
    const mother = await createAccount(app, nextIdentifier());
    const declared = await phone.declare(mother, line);
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');
    const sent = await phone.requestProof(mother, declared.claimId, 'SMS');
    expect(sent.outcome).toBe('SENT');
    const motherCode = prover.delivered[prover.delivered.length - 1]?.code ?? '';
    expect((await phone.verify(mother, declared.claimId, motherCode)).outcome).toBe('PROVEN');

    // La revendication de l'émancipation entamée est SUPERSEDED, tracée.
    const orphanClaim = firstRow(
      await app.query<{ status: string; revoke_reason: string }>(
        `SELECT status, revoke_reason FROM phone_claims
          WHERE person_id = $1 ORDER BY created_at DESC LIMIT 1`,
        [attached2.dependentPersonId],
      ),
    );
    expect(orphanClaim).toEqual({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });
  });
});
