import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

/**
 * ZÉRO PII — la preuve globale du LOT 2, sur un CYCLE COMPLET :
 * déclaration → demande → mensonges du fournisseur → succès → RECYCLAGE.
 *
 * On vérifie deux choses que rien d'autre ne vérifie :
 *   1. aucun log, sur aucun chemin (y compris les alertes d'intégrité et les
 *      refus), ne porte un numéro, un code, une clé ou un fragment ;
 *   2. AUCUNE TABLE du schéma ne contient le numéro en clair — on relit
 *      TOUTES les colonnes texte de TOUTES les tables, sous OWNER (le rôle le
 *      plus puissant), et on cherche le numéro. S'il est quelque part, il est
 *      trouvé ici.
 */
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

const LINE = '+243851234567';
const NATIONAL = '851234567'; // le numéro sans indicatif : un fragment compte aussi

describe('ZÉRO PII — cycle complet du lot', () => {
  let app: Pool;
  let owner: Pool;
  let prover: LyingProver;
  let phone: PhoneService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    prover = new LyingProver();
    phone = new PhoneService(app, crypto, codeKeyring, prover, assemblePhoneConfig({}));
    await truncateTables(
      owner,
      'outbox',
      'proof_dispatches',
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

  async function newAccount(): Promise<string> {
    seq += 1;
    return firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7500000000 + seq)],
      ),
    ).id;
  }

  test('le cycle complet ne laisse NI numéro NI code, ni en log ni en base', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const codes: string[] = [];

    try {
      // --- Le premier détenteur prouve sa ligne.
      const ancien = await newAccount();
      const claim1 = await phone.declare(ancien, LINE);
      if (claim1.outcome !== 'DECLARED') throw new Error('déclaration attendue');

      // Le fournisseur ment d'abord (code faux), puis se tient bien.
      prover.willLie('WRONG_CODE');
      await phone.requestProof(ancien, claim1.claimId, 'SMS');
      codes.push(prover.delivered[0]?.code ?? '');
      await phone.verify(ancien, claim1.claimId, prover.delivered[0]?.code ?? '');

      prover.willLie('HONEST');
      // La preuve précédente est encore en cours : on la clôt en épuisant.
      await phone.verify(ancien, claim1.claimId, '000000');
      await phone.verify(ancien, claim1.claimId, '000001');

      const claim1b = await phone.declare(ancien, LINE);
      if (claim1b.outcome !== 'DECLARED') throw new Error('déclaration attendue');
      await phone.requestProof(ancien, claim1b.claimId, 'CALL');
      const codeAncien = prover.delivered[prover.delivered.length - 1]?.code ?? '';
      codes.push(codeAncien);
      expect((await phone.verify(ancien, claim1b.claimId, codeAncien)).outcome).toBe('PROVEN');

      // --- La SIM change de mains : le nouveau détenteur prouve à son tour.
      const nouveau = await newAccount();
      const claim2 = await phone.declare(nouveau, LINE);
      if (claim2.outcome !== 'DECLARED') throw new Error('déclaration attendue');
      await phone.requestProof(nouveau, claim2.claimId, 'CALL');
      const codeNouveau = prover.delivered[prover.delivered.length - 1]?.code ?? '';
      codes.push(codeNouveau);
      expect((await phone.verify(nouveau, claim2.claimId, codeNouveau)).outcome).toBe('PROVEN');

      // La preuve fraîche a gagné, l'ancien détenteur a perdu sa ligne.
      const superseded = firstRow(
        await app.query<{ status: string; revoke_reason: string }>(
          'SELECT status, revoke_reason FROM phone_claims WHERE id = $1',
          [claim1b.claimId],
        ),
      );
      expect(superseded).toMatchObject({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });

      // --- 1. AUCUN LOG ne porte le numéro, un fragment, ou un code.
      const logged = [...logSpy.mock.calls, ...errorSpy.mock.calls, ...warnSpy.mock.calls]
        .flat()
        .map(String)
        .join(' ');
      expect(logged).not.toContain(LINE);
      expect(logged).not.toContain(NATIONAL);
      for (const code of codes.filter((c) => c !== '')) {
        expect(logged).not.toContain(code);
      }
    } finally {
      logSpy.mockRestore();
      errorSpy.mockRestore();
      warnSpy.mockRestore();
    }

    // --- 2. AUCUNE COLONNE TEXTE d'AUCUNE TABLE ne contient le numéro.
    // Lu sous OWNER : si le clair est quelque part, il est trouvé ici.
    const columns = await owner.query<{ table_name: string; column_name: string }>(
      `SELECT table_name, column_name
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND data_type IN ('text', 'character varying', 'json', 'jsonb')
        ORDER BY table_name, ordinal_position`,
    );
    expect(columns.rows.length).toBeGreaterThan(5); // le balayage a bien du grain à moudre

    for (const { table_name, column_name } of columns.rows) {
      const hits = await owner.query<{ hits: string }>(
        `SELECT count(*)::text AS hits FROM ${table_name}
          WHERE ${column_name}::text LIKE $1 OR ${column_name}::text LIKE $2`,
        [`%${LINE}%`, `%${NATIONAL}%`],
      );
      expect({
        table: table_name,
        column: column_name,
        hits: Number(firstRow(hits).hits),
      }).toEqual({ table: table_name, column: column_name, hits: 0 });
    }

    // Et les codes non plus (ils ne vivent qu'en HMAC).
    for (const code of codes.filter((c) => c !== '')) {
      const hits = await owner.query<{ hits: string }>(
        "SELECT count(*)::text AS hits FROM possession_proofs WHERE code_hmac LIKE $1",
        [`%${code}%`],
      );
      expect(Number(firstRow(hits).hits)).toBe(0);
    }
  });
});
