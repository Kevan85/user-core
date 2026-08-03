import { randomBytes } from 'crypto';
import { HttpException, HttpStatus } from '@nestjs/common';
import { Pool } from 'pg';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { EmancipationController } from '../../src/persons/emancipation.controller';
import { EmancipationService } from '../../src/persons/emancipation.service';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { assembleProofCodeKeyring } from '../../src/proving/proof-code';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * e2e — LA PORTE D'ÉMANCIPATION EST FERMÉE (LOT U-sec, étape 2 ; 031).
 *
 * Ce fichier portait le parcours complet du LOT 5 (rattachement → droits →
 * émancipation par SA ligne → coupure nette). Ce parcours n'existe plus : la
 * porte est close, et le rejouer sous l'owner ne prouverait plus un chemin
 * réel — cela prouverait une fiction.
 *
 * Il prouve donc la fermeture À SES DEUX ÉTAGES, parce que l'un sans l'autre
 * serait un mensonge confortable :
 *   · au BORD DE L'API, le contrôleur rend 501 — un refus propre et déclaré ;
 *   · EN BASE, le rôle applicatif ne peut plus exécuter la fonction. C'est LUI
 *     le mur : si le contrôleur était réécrit demain et rappelait le service,
 *     la base refuserait quand même (§3.1, « et la v2 de cet endpoint ? »).
 *
 * ⚠️ CE QUE CETTE FERMETURE RETIRE COMME COUVERTURE — à écrire, pas à laisser
 * découvrir (leçon ⑫). Trois faits n'ont plus de test e2e :
 *   1. le parcours complet du LOT 5 (coupure nette, identité stable, ancien
 *      responsable prévenu dans son compte, irréversibilité armée) — les MURS
 *      qui le garantissent restent prouvés, sous owner, par
 *      tests/persons/emancipation-schema.spec.ts ;
 *   2. la réponse SANS ORACLE de l'ouverture — devenue sans objet : les deux
 *      routes rendent la même 501, uniforme par construction ;
 *   3. le test ② de C1 dans le flux réel (une émancipation entamée jamais
 *      achevée ne bloque pas la détentrice légitime de la ligne) — le fait
 *      reste couvert par tests/phone/line-superseded.spec.ts, mais plus par le
 *      chemin qui le produisait.
 */
const crypto = assembleCryptoFromEnv(fullKeyringEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
}));
const codeKeyring = assembleProofCodeKeyring(fullKeyringEnv({
  USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1: randomBytes(32).toString('base64') }),
  USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
}));

function birthDateYearsAgo(years: number): string {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() - years);
  d.setUTCDate(d.getUTCDate() - 30);
  return d.toISOString().slice(0, 10);
}

describe("e2e — la porte d'émancipation est fermée (031)", () => {
  const authConfig = testAuthAssembly();
  let app: Pool;
  let owner: Pool;
  let provider: LocalAuthenticationProvider;
  let emancipation: EmancipationService;
  let prover: LyingProver;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    provider = new LocalAuthenticationProvider(authConfig);
    await provider.init();
    prover = new LyingProver();
    emancipation = new EmancipationService(
      app,
      crypto,
      codeKeyring,
      prover,
      assemblePhoneConfig({ PROOF_LINE_CAP: '10' }),
      provider,
      authConfig,
      new LoginThrottle(1000, 60),
    );
    await truncateTables(owner, 'possession_proofs', 'phone_claims', 'accounts', 'persons');
  });

  afterAll(async () => {
    await truncateTables(owner, 'possession_proofs', 'phone_claims', 'accounts', 'persons');
    await app.end();
    await owner.end();
  });

  /** Une personne majeure, identifiée, sans compte : la cible d'hier. */
  async function majorPerson(): Promise<string> {
    const identifier = String(8_900_000_001);
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: birthDateYearsAgo(30),
    });
    await owner.query('SELECT create_person($1, $2, $3, $4, $5)', [
      identifier,
      salt,
      enc.token,
      enc.encKeyId,
      enc.birthYear,
    ]);
    return identifier;
  }

  test("AU BORD DE L'API : les deux routes rendent 501, sans toucher au service", () => {
    const controller = new EmancipationController();
    const calls = [(): never => controller.start(), (): never => controller.complete()];
    for (const call of calls) {
      let thrown: unknown;
      try {
        call();
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(HttpException);
      expect((thrown as HttpException).getStatus()).toBe(HttpStatus.NOT_IMPLEMENTED);
    }
  });

  test('EN BASE : même en rappelant le service, le rôle applicatif ne peut plus ouvrir — et RIEN ne part', async () => {
    const identifier = await majorPerson();
    const before = prover.deliveries;

    // Le service est intact et travaille jusqu'à la fonction : c'est la BASE
    // qui refuse. Le mur ne dépend donc pas du contrôleur ci-dessus.
    await expect(
      emancipation.start(identifier, '+243870009001', 'SMS', '203.0.113.9'),
    ).rejects.toThrow(/permission denied/);

    // Absence prouvée en COMPTANT LES APPELS (jamais en lisant un résultat) :
    // aucun code n'est parti sur aucune ligne.
    expect(prover.deliveries).toBe(before);

    // Et le registre est intact : aucune revendication née d'une tentative.
    const claims = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM phone_claims'),
    ).n;
    expect(Number(claims)).toBe(0);
  });
});
