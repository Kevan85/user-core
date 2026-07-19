import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { ResponsibilitiesService } from '../../src/persons/responsibilities.service';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Le service du lien de responsabilité, SOUS RÔLE BRIDÉ : la façade au jour
// près (§3.1), la BOLA, et l'acte staff (C2 option a) — les murs, eux, sont
// prouvés dans responsibilities-schema.spec.ts.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const YEAR = new Date().getUTCFullYear();

function isoDaysAgoYears(years: number, offsetDays: number): string {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() - years);
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

describe('ResponsibilitiesService — rattacher, co-responsable, acte staff', () => {
  let app: Pool;
  let owner: Pool;
  let service: ResponsibilitiesService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    service = new ResponsibilitiesService(app, crypto);
    await truncateTables(owner, 'person_responsibilities', 'accounts', 'persons');
  });

  afterAll(async () => {
    await truncateTables(owner, 'person_responsibilities', 'accounts', 'persons');
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_600_000_000 + seq);
  }

  async function adult(
    role: 'ACCOUNT_HOLDER' | 'PLATFORM_STAFF' = 'ACCOUNT_HOLDER',
  ): Promise<{ accountId: string; personId: string; personIdentifier: string }> {
    const personIdentifier = nextIdentifier();
    const accountId = await createAccount(app, nextIdentifier(), { role, personIdentifier });
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId, personIdentifier };
  }

  const IDENTITY = {
    nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
    displayName: 'Kabeya Junior',
    birthDate: `${YEAR - 9}-03-12`,
  };

  test('rattacher un ayant droit : personne identifiée + lien actif, identifiant dictable rendu', async () => {
    const parent = await adult();
    const result = await service.attach(parent.accountId, IDENTITY);
    if (result.outcome !== 'OK') {
      throw new Error(`OK attendu, reçu ${result.outcome}`);
    }
    expect(result.dependentPublicIdentifier).toMatch(/^[1-9][0-9]{9}$/);

    const stored = firstRow(
      await app.query<{ birth_year: number; status: string; opened_by: string }>(
        `SELECT p.birth_year, r.status, r.opened_by FROM persons p
          JOIN person_responsibilities r ON r.dependent_person_id = p.id
         WHERE p.id = $1`,
        [result.dependentPersonId],
      ),
    );
    expect(stored).toEqual({ birth_year: YEAR - 9, status: 'ACTIVE', opened_by: 'RESPONSIBLE' });
  });

  test('la façade tranche AU JOUR PRÈS : seize ans révolus hier → refus, seize ans dans deux jours → permis', async () => {
    const parent = await adult();
    // Anniversaire du seuil passé d'un jour : majeur au sens du seuil.
    const justAdult = await service.attach(parent.accountId, {
      ...IDENTITY,
      birthDate: isoDaysAgoYears(16, -1),
    });
    expect(justAdult.outcome).toBe('DEPENDENT_NOT_MINOR');

    // Encore mineur pour deux jours : passe — le mur d'année (frontière)
    // laisse, la façade précise laisse aussi.
    const stillMinor = await service.attach(parent.accountId, {
      ...IDENTITY,
      birthDate: isoDaysAgoYears(16, 2),
    });
    expect(stillMinor.outcome).toBe('OK');
  });

  test('identité invalide → INVALID_IDENTITY avec la raison du module, rien d’écrit', async () => {
    const parent = await adult();
    const result = await service.attach(parent.accountId, { ...IDENTITY, displayName: '' });
    if (result.outcome !== 'INVALID_IDENTITY') {
      throw new Error(`INVALID_IDENTITY attendu, reçu ${result.outcome}`);
    }
    expect(result.reason).toMatch(/nom d'affichage/);
  });

  test('co-responsable : ajouté par un responsable en place — et par LUI seul (BOLA)', async () => {
    const parent = await adult();
    const attached = await service.attach(parent.accountId, IDENTITY);
    if (attached.outcome !== 'OK') throw new Error('OK attendu');

    // Un tiers qui n'est PAS responsable de cette personne : refus, sans
    // même confirmer que la personne existe.
    const stranger = await adult();
    await expect(
      service.addCoResponsible(stranger.accountId, attached.dependentPersonId, stranger.personIdentifier),
    ).resolves.toEqual({ outcome: 'NOT_RESPONSIBLE' });

    // Le responsable ajoute un co-responsable au compte actif : OK.
    const co = await adult();
    const added = await service.addCoResponsible(
      parent.accountId,
      attached.dependentPersonId,
      co.personIdentifier,
    );
    expect(added.outcome).toBe('OK');

    // Deux fois : le doublon est tranché par la base.
    await expect(
      service.addCoResponsible(parent.accountId, attached.dependentPersonId, co.personIdentifier),
    ).resolves.toEqual({ outcome: 'ALREADY_RESPONSIBLE' });

    // Identifiant inconnu.
    await expect(
      service.addCoResponsible(parent.accountId, attached.dependentPersonId, '1234567890'),
    ).resolves.toEqual({ outcome: 'UNKNOWN_PERSON' });
  });

  test('acte staff : réservé au staff, orphelin refusé, remplacement atomique tracé', async () => {
    const parent = await adult();
    const attached = await service.attach(parent.accountId, IDENTITY);
    if (attached.outcome !== 'OK') throw new Error('OK attendu');

    // Un titulaire ordinaire ne retire JAMAIS un responsable (conflit de
    // garde : le système ne tranche pas à la place d'un juge).
    await expect(
      service.endResponsibility(parent.accountId, attached.responsibilityId, null),
    ).resolves.toEqual({ outcome: 'FORBIDDEN' });

    const staff = await adult('PLATFORM_STAFF');

    // Fin sèche du dernier lien : l'invariant P0114 parle, le service traduit.
    await expect(
      service.endResponsibility(staff.accountId, attached.responsibilityId, null),
    ).resolves.toEqual({ outcome: 'WOULD_ORPHAN' });

    // Avec remplaçant : OK — l'ancien lien est clos ADMIN, le nouveau est
    // ACTIF et porte l'acteur PLATFORM_STAFF : l'acte est TRACÉ par le
    // registre lui-même.
    const replacement = await adult();
    await expect(
      service.endResponsibility(
        staff.accountId,
        attached.responsibilityId,
        replacement.personIdentifier,
      ),
    ).resolves.toEqual({ outcome: 'OK' });

    const rows = await owner.query<{ status: string; end_reason: string | null; opened_by: string }>(
      `SELECT status, end_reason, opened_by FROM person_responsibilities
        WHERE dependent_person_id = $1 ORDER BY seq`,
      [attached.dependentPersonId],
    );
    expect(rows.rows).toEqual([
      { status: 'ENDED', end_reason: 'ADMIN', opened_by: 'RESPONSIBLE' },
      { status: 'ACTIVE', end_reason: null, opened_by: 'PLATFORM_STAFF' },
    ]);
  });

  test('acte staff : un remplaçant sans compte actif est refusé proprement', async () => {
    const parent = await adult();
    const attached = await service.attach(parent.accountId, IDENTITY);
    if (attached.outcome !== 'OK') throw new Error('OK attendu');
    const staff = await adult('PLATFORM_STAFF');

    // Une personne sans compte (l'ayant droit d'un AUTRE foyer, p. ex.).
    const other = await adult();
    const otherAttached = await service.attach(other.accountId, IDENTITY);
    if (otherAttached.outcome !== 'OK') throw new Error('OK attendu');

    await expect(
      service.endResponsibility(
        staff.accountId,
        attached.responsibilityId,
        otherAttached.dependentPublicIdentifier,
      ),
    ).resolves.toEqual({ outcome: 'REPLACEMENT_CANNOT_ACT' });
  });
});
