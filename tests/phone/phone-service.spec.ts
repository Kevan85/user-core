import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { encrypt } from '../../src/crypto/aes-gcm';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { assemblePhoneConfig, assertFingerprintKeyAligned } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { ConfigViolations } from '../../src/bootstrap/assembly';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

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
const config = assemblePhoneConfig({ PROOF_LINE_CAP: '3' });

describe('PhoneService — déclaration, preuve, vérification', () => {
  let app: Pool;
  let owner: Pool;
  let prover: LyingProver;
  let phone: PhoneService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  beforeEach(async () => {
    prover = new LyingProver();
    phone = new PhoneService(app, crypto, codeKeyring, prover, config);
    await truncateTables(
      owner,
      'outbox',
      'proof_dispatches',
      'possession_proof_refusals',
      'possession_proofs',
      'phone_claims',
      'session_refresh_tokens',
      'sessions',
      'account_secrets',
      'accounts',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    // Depuis 011, le chemin unique — les fixtures l'empruntent comme le service.
    return createAccountFixture(app, String(7400000000 + seq));
  }

  test('VÉRIFICATION PARESSEUSE — déclarer n\'envoie RIEN (comptage d\'appels, pas de résultat)', async () => {
    const accountId = await newAccount();
    const declared = await phone.declare(accountId, '+243 84 000 00 01');
    expect(declared.outcome).toBe('DECLARED');

    // LE point : zéro appel au fournisseur. Le coût suit le REVENU, pas la
    // base d'utilisateurs (SMS ≈ 0,25 $ ; 500 parents = 35 % du revenu d'une
    // école — CDC §6.4).
    expect(prover.deliveries).toBe(0);
    expect(prover.delivered).toHaveLength(0);

    const claim = firstRow(
      await app.query<{ status: string; assurance_level: string }>(
        'SELECT status, assurance_level FROM phone_claims WHERE account_id = $1',
        [accountId],
      ),
    );
    expect(claim.status).toBe('PENDING');
    expect(claim.assurance_level).toBe('DECLARED');
  });

  test('ZÉRO OTP DE ROUTINE — un cycle de login complet ne déclenche AUCUN envoi', async () => {
    const authConfig = testAuthAssembly();
    const provider = new LocalAuthenticationProvider(authConfig);
    await provider.init();
    const auth = new AuthService(app, provider, provider, authConfig, new LoginThrottle(100, 60));

    seq += 1;
    const identifier = String(7450000000 + seq);
    const accountId = await createAccountFixture(app, identifier, {
      secretHash: await provider.hashSecret('S3cret!'),
    });
    await phone.declare(accountId, '+243840000002');

    // Login réussi, login raté : le chemin d'authentification ne connaît même
    // pas le prover. Prouvé en COMPTANT les appels (§5).
    expect((await auth.login(identifier, 'S3cret!', '10.0.0.1')).outcome).toBe('OK');
    expect((await auth.login(identifier, 'faux', '10.0.0.1')).outcome).toBe('FAILED');
    expect(prover.deliveries).toBe(0);
  });

  test('§3.13 — l\'appel au fournisseur a lieu HORS transaction (aucune transaction ouverte pendant)', async () => {
    const accountId = await newAccount();
    const declared = await phone.declare(accountId, '+243840000003');
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');

    // Espion : au MOMENT où le fournisseur est appelé, on interroge la base
    // pour vérifier qu'aucune transaction de ce service n'est ouverte.
    let openTransactionsDuringCall = -1;
    const spy = new LyingProver();
    const originalDeliver = spy.deliver.bind(spy);
    spy.deliver = async (request) => {
      const inspector = new Pool({ connectionString: adminUrl() });
      try {
        const r = await inspector.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM pg_stat_activity
            WHERE datname = current_database()
              AND state IN ('idle in transaction', 'idle in transaction (aborted)')`,
        );
        openTransactionsDuringCall = Number(r.rows[0]?.count ?? -1);
      } finally {
        await inspector.end();
      }
      return originalDeliver(request);
    };

    const service = new PhoneService(app, crypto, codeKeyring, spy, config);
    const result = await service.requestProof(accountId, declared.claimId, 'CALL');
    expect(result.outcome).toBe('SENT');

    // On réserve, on COMMIT, on appelle : aucune transaction ne reste ouverte
    // pendant que l'on parle à un réseau qui peut mettre 30 secondes à
    // répondre (RDC).
    expect(openTransactionsDuringCall).toBe(0);
  });

  test('P6 — la ligne de COÛT n\'existe que si le fournisseur a accepté', async () => {
    const accountId = await newAccount();
    const declared = await phone.declare(accountId, '+243840000004');
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');

    // Fournisseur en erreur franche : rien n'est parti, rien n'est facturable.
    prover.willLie('PROVIDER_ERROR');
    const failed = await phone.requestProof(accountId, declared.claimId, 'SMS');
    expect(failed.outcome).toBe('UNDELIVERABLE');

    const proofs = await app.query('SELECT id FROM possession_proofs');
    const dispatches = await app.query('SELECT id FROM proof_dispatches');
    expect(proofs.rows).toHaveLength(1); // une preuve réservée…
    expect(dispatches.rows).toHaveLength(0); // …mais AUCUN envoi facturable

    // Le fournisseur muet, lui, encaisse : il y a bien un coût.
    prover.willLie('SILENT');
    const silent = await phone.requestProof(accountId, declared.claimId, 'SMS');
    expect(silent.outcome).toBe('SENT');
    const billed = await app.query<{ channel: string }>('SELECT channel FROM proof_dispatches');
    expect(billed.rows).toHaveLength(1);
    expect(billed.rows[0]?.channel).toBe('SMS');
    expect(prover.delivered).toHaveLength(0); // rien n'est arrivé sur le téléphone
  });

  test('P4 — empreinte et valeur chiffrée qui divergent → REFUS et ZÉRO appel au fournisseur', async () => {
    const accountId = await newAccount();
    // On FORGE la revendication piégée : l'empreinte de la ligne A, la valeur
    // chiffrée du numéro B. C'est le bug de câblage que la base ne peut PAS
    // voir (elle n'a pas les clés).
    const lineA = '+243840000005';
    const lineB = '+243840000006';
    const fingerprintA = (
      await import('../../src/crypto/fingerprint')
    ).fingerprintOf(crypto.fingerprint, lineA);
    const claimId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, 'E1') RETURNING id`,
        [accountId, fingerprintA.value, fingerprintA.hmacKeyId, encrypt(crypto.encryption, lineB)],
      ),
    ).id;

    const result = await phone.requestProof(accountId, claimId, 'CALL');
    expect(result.outcome).toBe('INTEGRITY_VIOLATION');

    // LE POINT : le téléphone de l'inconnu n'a pas sonné. On le prouve en
    // comptant les appels, pas en lisant un résultat.
    expect(prover.deliveries).toBe(0);
    expect(prover.delivered).toHaveLength(0);
    // Et aucune preuve n'a été réservée : rien à facturer, rien à expliquer.
    const proofs = await app.query('SELECT id FROM possession_proofs');
    expect(proofs.rows).toHaveLength(0);
  });

  test('BOLA — un compte ne peut ni demander ni vérifier sur la revendication d\'un autre', async () => {
    const victim = await newAccount();
    const attacker = await newAccount();
    const declared = await phone.declare(victim, '+243840000007');
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');

    const stolen = await phone.requestProof(attacker, declared.claimId, 'CALL');
    expect(stolen.outcome).toBe('NOT_FOUND');
    expect(prover.deliveries).toBe(0); // le téléphone de la victime n'a pas sonné

    const stolenVerify = await phone.verify(attacker, declared.claimId, '123456');
    expect(stolenVerify.outcome).toBe('NOT_FOUND');

    // La revendication de la victime est INTACTE (nombre de lignes des deux côtés).
    const victimClaims = await app.query<{ status: string }>(
      'SELECT status FROM phone_claims WHERE account_id = $1',
      [victim],
    );
    expect(victimClaims.rows).toHaveLength(1);
    expect(victimClaims.rows[0]?.status).toBe('PENDING');
    const attackerClaims = await app.query('SELECT id FROM phone_claims WHERE account_id = $1', [
      attacker,
    ]);
    expect(attackerClaims.rows).toHaveLength(0);
  });

  test('cycle complet : déclaration → preuve → code présenté → ligne PROUVÉE', async () => {
    const accountId = await newAccount();
    const declared = await phone.declare(accountId, '+243840000008');
    if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');

    const sent = await phone.requestProof(accountId, declared.claimId, 'CALL');
    expect(sent.outcome).toBe('SENT');

    const code = prover.delivered[0]?.code;
    expect(code).toMatch(/^[0-9]{6}$/);

    expect((await phone.verify(accountId, declared.claimId, '000000')).outcome).toBe('WRONG');
    expect((await phone.verify(accountId, declared.claimId, code!)).outcome).toBe('PROVEN');

    const claim = firstRow(
      await app.query<{ status: string; assurance_level: string }>(
        'SELECT status, assurance_level FROM phone_claims WHERE id = $1',
        [declared.claimId],
      ),
    );
    expect(claim.status).toBe('ACTIVE');
    expect(claim.assurance_level).toBe('PROVEN');
  });

  test('déclarer un AUTRE numéro révoque la revendication précédente (REPLACED)', async () => {
    const accountId = await newAccount();
    const first = await phone.declare(accountId, '+243840000009');
    const second = await phone.declare(accountId, '+243840000010');
    expect(second.outcome).toBe('DECLARED');

    const claims = await app.query<{ status: string; revoke_reason: string | null }>(
      'SELECT status, revoke_reason FROM phone_claims WHERE account_id = $1 ORDER BY created_at',
      [accountId],
    );
    expect(claims.rows).toHaveLength(2);
    expect(claims.rows[0]).toMatchObject({ status: 'REVOKED', revoke_reason: 'REPLACED' });
    expect(claims.rows[1]).toMatchObject({ status: 'PENDING' });
    if (first.outcome !== 'DECLARED') throw new Error('déclaration attendue');
  });

  test('numéro invalide → refus, aucune ligne, aucun appel', async () => {
    const accountId = await newAccount();
    expect((await phone.declare(accountId, '0812345678')).outcome).toBe('INVALID_PHONE');
    expect((await phone.declare(accountId, 'pas-un-numero')).outcome).toBe('INVALID_PHONE');
    expect(prover.deliveries).toBe(0);
    const claims = await app.query('SELECT id FROM phone_claims WHERE account_id = $1', [
      accountId,
    ]);
    expect(claims.rows).toHaveLength(0);
  });

  test('GARDE DE BOOT — trousseau d\'empreinte désaligné avec la base → refus de démarrer', async () => {
    await expect(assertFingerprintKeyAligned(app, crypto)).resolves.toBeUndefined();

    const misconfigured = assembleCryptoFromEnv({
      USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
      USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
      USER_CORE_HMAC_KEYS: JSON.stringify({ H9: randomBytes(32).toString('base64') }),
      USER_CORE_HMAC_ACTIVE_KEY_ID: 'H9',
    });
    await expect(assertFingerprintKeyAligned(app, misconfigured)).rejects.toThrow(
      ConfigViolations,
    );
    await expect(assertFingerprintKeyAligned(app, misconfigured)).rejects.toThrow(
      /clé d'empreinte désalignée/,
    );
  });

  test('ZÉRO PII dans les logs, sur un cycle complet (y compris les refus)', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const accountId = await newAccount();
      const line = '+243840000011';
      const declared = await phone.declare(accountId, line);
      if (declared.outcome !== 'DECLARED') throw new Error('déclaration attendue');
      const sent = await phone.requestProof(accountId, declared.claimId, 'SMS');
      expect(sent.outcome).toBe('SENT');
      const code = prover.delivered[0]?.code ?? '';
      await phone.verify(accountId, declared.claimId, '000000');
      await phone.verify(accountId, declared.claimId, code);

      // Et le chemin d'alerte d'intégrité (celui qui LOGGE) : il ne doit
      // porter que des identifiants techniques.
      const fingerprintA = (
        await import('../../src/crypto/fingerprint')
      ).fingerprintOf(crypto.fingerprint, '+243840000012');
      const trap = firstRow(
        await owner.query<{ id: string }>(
          `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
           VALUES ($1, $2, $3, $4, 'E1') RETURNING id`,
          [
            await newAccount(),
            fingerprintA.value,
            fingerprintA.hmacKeyId,
            encrypt(crypto.encryption, '+243840000013'),
          ],
        ),
      ).id;
      const owner2 = firstRow(
        await app.query<{ account_id: string }>(
          'SELECT account_id FROM phone_claims WHERE id = $1',
          [trap],
        ),
      ).account_id;
      await phone.requestProof(owner2, trap, 'SMS');

      const logged = [...logSpy.mock.calls, ...errorSpy.mock.calls, ...warnSpy.mock.calls]
        .flat()
        .map(String)
        .join(' ');
      expect(logged).not.toContain(line);
      expect(logged).not.toContain('840000011');
      expect(logged).not.toContain('840000013');
      if (code !== '') {
        expect(logged).not.toContain(code);
      }
    } finally {
      logSpy.mockRestore();
      errorSpy.mockRestore();
      warnSpy.mockRestore();
    }
  });
});
