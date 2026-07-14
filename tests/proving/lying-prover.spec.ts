import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import {
  assembleProofCodeKeyring,
  generateProofCode,
  hashProofCode,
  hashProofCodeUnder,
} from '../../src/proving/proof-code';
import { DeliveryFailed } from '../../src/proving/line-ownership-prover';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// LES SIX MENSONGES, joués contre la VRAIE base. Le point de chacun : aucun
// mensonge du fournisseur ne doit pouvoir activer une ligne — la preuve est
// le code renvoyé par l'utilisateur, comparé EN BASE.
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

const PHONE = '+243830000001';
const TTL = 300;
const MAX_ATTEMPTS = 3;
const CAP = 10;
const WINDOW = 86400;
const CODE_DIGITS = 6;

describe('Le simulateur qui MENT — six mensonges contre la vraie base', () => {
  let app: Pool;
  let owner: Pool;
  let prover: LyingProver;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  beforeEach(async () => {
    prover = new LyingProver();
    await truncateTables(
      owner,
      'outbox',
      'possession_proof_refusals',
      'possession_proofs',
      'phone_claims',
      'accounts',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  // Le flux réel, en miniature (le service complet arrive à l'étape 6) :
  // on réserve en base, on commit, PUIS on appelle le fournisseur (§3.13).
  async function declareAndSend(
    phone = PHONE,
    ttl = TTL,
  ): Promise<{ claimId: string; code: string; accountId: string }> {
    seq += 1;
    const accountId = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7300000000 + seq)],
      ),
    ).id;
    const fp = fingerprintOf(crypto.fingerprint, phone);
    const claimId = firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [accountId, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, phone), 'E1'],
      ),
    ).id;

    const code = generateProofCode(CODE_DIGITS);
    const hashed = hashProofCode(codeKeyring, code);
    const opened = firstRow(
      await app.query<{ proof_id: string; verdict: string }>(
        'SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)',
        [claimId, 'CALL', hashed.hmac, hashed.keyId, ttl, MAX_ATTEMPTS, CAP, WINDOW],
      ),
    );
    expect(opened.verdict).toBe('OPENED');

    // L'appel réseau a lieu HORS transaction (§3.13).
    await prover.deliver({ channel: 'CALL', phone, code });
    return { claimId, code, accountId };
  }

  async function present(claimId: string, code: string): Promise<string> {
    const hmac = hashProofCodeUnder(codeKeyring, 'C1', code);
    return firstRow(
      await app.query<{ verdict: string }>('SELECT * FROM verify_possession_code($1, $2)', [
        claimId,
        hmac,
      ]),
    ).verdict;
  }

  async function claimStatus(claimId: string): Promise<string> {
    return firstRow(
      await app.query<{ status: string }>('SELECT status FROM phone_claims WHERE id = $1', [
        claimId,
      ]),
    ).status;
  }

  test('HONNÊTE (le chemin heureux, la référence) → la ligne est prouvée', async () => {
    const { claimId, code } = await declareAndSend();
    expect(prover.delivered[0]?.code).toBe(code);
    expect(await present(claimId, code)).toBe('PROVEN');
    expect(await claimStatus(claimId)).toBe('ACTIVE');
  });

  test('MENSONGE 1 — CODE FAUX : le fournisseur livre un autre code → jamais prouvé', async () => {
    prover.willLie('WRONG_CODE');
    const { claimId, code } = await declareAndSend();

    // Ce que l'utilisateur a REÇU n'est pas ce que la base attend.
    const received = prover.delivered[0]?.code;
    expect(received).not.toBe(code);

    expect(await present(claimId, received!)).toBe('WRONG');
    expect(await claimStatus(claimId)).toBe('PENDING'); // jamais activée
  });

  test('MENSONGE 2 — LENT : le code arrive après l\'expiration → EXPIRED, aucune activation', async () => {
    prover.willLie('SLOW');
    const { claimId, code } = await declareAndSend(PHONE, 1); // TTL 1 s (config, pas en dur)
    await app.query('SELECT pg_sleep(1.3)');

    expect(await present(claimId, code)).toBe('EXPIRED');
    expect(await claimStatus(claimId)).toBe('PENDING');
  });

  test('MENSONGE 3 — MUET : il accuse réception et ne livre RIEN. Prouvé par COMPTAGE, pas par un résultat', async () => {
    prover.willLie('SILENT');
    const { claimId } = await declareAndSend();

    // Le fournisseur a bien été appelé UNE fois…
    expect(prover.deliveries).toBe(1);
    // …et RIEN n'est arrivé sur le téléphone. On compte les envois, on ne
    // déduit pas une absence d'un résultat (CLAUDE.md §5).
    expect(prover.delivered).toHaveLength(0);

    // Sans code reçu, l'utilisateur ne peut rien présenter : la ligne reste
    // PENDING pour toujours. Aucun chemin ne l'active « par défaut ».
    expect(await claimStatus(claimId)).toBe('PENDING');

    // Et un attaquant qui devinerait un code au hasard épuise les essais.
    for (let i = 0; i < MAX_ATTEMPTS - 1; i++) {
      expect(await present(claimId, '000000')).toBe('WRONG');
    }
    expect(await present(claimId, '000000')).toBe('EXHAUSTED');
    expect(await claimStatus(claimId)).toBe('PENDING');
  });

  test('MENSONGE 4 — DOUBLE LIVRAISON : deux messages, UN SEUL code valable, UNE SEULE preuve', async () => {
    prover.willLie('DOUBLE_DELIVERY');
    const { claimId, code } = await declareAndSend();

    expect(prover.delivered).toHaveLength(2); // le téléphone a bien sonné deux fois
    expect(prover.delivered[0]?.code).toBe(prover.delivered[1]?.code); // même code

    // Une seule preuve en base : la double livraison ne double pas le registre
    // (et ne doublera pas la facture).
    const proofs = await app.query('SELECT id FROM possession_proofs WHERE claim_id = $1', [
      claimId,
    ]);
    expect(proofs.rows).toHaveLength(1);

    expect(await present(claimId, code)).toBe('PROVEN');
    // Le second exemplaire du même code, rejoué : la preuve est close.
    expect(await present(claimId, code)).toBe('ALREADY_SETTLED');
  });

  test('MENSONGE 5 — ERREUR FRANCHE : le fournisseur échoue → DeliveryFailed, la preuve se clôt', async () => {
    seq += 1;
    const accountId = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7390000000 + seq)],
      ),
    ).id;
    const fp = fingerprintOf(crypto.fingerprint, PHONE);
    const claimId = firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [accountId, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, PHONE), 'E1'],
      ),
    ).id;
    const code = generateProofCode(CODE_DIGITS);
    const hashed = hashProofCode(codeKeyring, code);
    const opened = firstRow(
      await app.query<{ proof_id: string }>(
        'SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)',
        [claimId, 'SMS', hashed.hmac, hashed.keyId, TTL, MAX_ATTEMPTS, CAP, WINDOW],
      ),
    );

    prover.willLie('PROVIDER_ERROR');
    await expect(
      prover.deliver({ channel: 'SMS', phone: PHONE, code }),
    ).rejects.toThrow(DeliveryFailed);
    expect(prover.delivered).toHaveLength(0);

    // Le service clôt la preuve — BOLA EN BASE : le compte doit être le sien.
    const closedByStranger = firstRow(
      await app.query<{ abandon_possession_proof: boolean }>(
        'SELECT abandon_possession_proof($1, $2)',
        [opened.proof_id, accountId],
      ),
    );
    expect(closedByStranger.abandon_possession_proof).toBe(true);

    const proof = firstRow(
      await app.query<{ status: string }>('SELECT status FROM possession_proofs WHERE id = $1', [
        opened.proof_id,
      ]),
    );
    expect(proof.status).toBe('FAILED');
    expect(await claimStatus(claimId)).toBe('PENDING');
  });

  test('MENSONGE 6 — RÉFÉRENCE REJOUÉE : le fournisseur rend une référence déjà vue → aucune confusion', async () => {
    const first = await declareAndSend('+243830000002');
    prover.willLie('REPLAYED_REF');
    const second = await declareAndSend('+243830000003');

    // Le fournisseur a « corrélé » les deux envois sur la même référence.
    expect(prover.delivered[0]?.providerRef).toBe(prover.delivered[1]?.providerRef);

    // La base, elle, ne corrèle RIEN par la référence du fournisseur : chaque
    // preuve appartient à SA revendication. Le code du premier ne prouve pas
    // la ligne du second.
    expect(await present(second.claimId, first.code)).toBe('WRONG');
    expect(await claimStatus(second.claimId)).toBe('PENDING');
    expect(await present(second.claimId, second.code)).toBe('PROVEN');
    expect(await claimStatus(first.claimId)).toBe('PENDING'); // intacte, non activée
  });

  test('BOLA en base — un compte étranger ne peut PAS clore la preuve d\'un autre', async () => {
    const { claimId } = await declareAndSend('+243830000004');
    seq += 1;
    const stranger = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7380000000 + seq)],
      ),
    ).id;
    const proofId = firstRow(
      await app.query<{ id: string }>(
        "SELECT id FROM possession_proofs WHERE claim_id = $1 AND status = 'PENDING'",
        [claimId],
      ),
    ).id;

    const refused = firstRow(
      await app.query<{ abandon_possession_proof: boolean }>(
        'SELECT abandon_possession_proof($1, $2)',
        [proofId, stranger],
      ),
    );
    expect(refused.abandon_possession_proof).toBe(false);

    // La preuve de la victime est INTACTE.
    const proof = firstRow(
      await app.query<{ status: string }>('SELECT status FROM possession_proofs WHERE id = $1', [
        proofId,
      ]),
    );
    expect(proof.status).toBe('PENDING');
  });

  test('le code est un CSPRNG à longueur configurable, jamais une séquence', () => {
    const draws = Array.from({ length: 200 }, () => generateProofCode(6));
    for (const code of draws) {
      expect(code).toMatch(/^[0-9]{6}$/);
    }
    let increases = 0;
    let decreases = 0;
    for (let i = 1; i < draws.length; i++) {
      const current = Number(draws[i]);
      const previous = Number(draws[i - 1]);
      if (current > previous) increases++;
      if (current < previous) decreases++;
    }
    expect(increases).toBeGreaterThan(0);
    expect(decreases).toBeGreaterThan(0);
    // Longueur pilotée par la config (CDC §9 : on paramètre, on ne fige pas).
    expect(generateProofCode(4)).toMatch(/^[0-9]{4}$/);
    expect(generateProofCode(8)).toMatch(/^[0-9]{8}$/);
  });

  test('P1 — le HMAC du code n\'est pas un condensat nu : deux clés → deux empreintes', () => {
    const other = assembleProofCodeKeyring({
      USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1: randomBytes(32).toString('base64') }),
      USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
    });
    const code = '123456';
    expect(hashProofCode(codeKeyring, code).hmac).not.toBe(hashProofCode(other, code).hmac);
  });
});
