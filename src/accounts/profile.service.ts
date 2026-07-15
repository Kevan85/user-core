import { Pool } from 'pg';
import { DB_ERROR, isDbError } from '../db/errors';

export interface ProfileView {
  displayName: string | null;
  locale: string | null;
}

export type UpdateProfileResult =
  | { outcome: 'OK'; profile: ProfileView }
  | { outcome: 'INVALID_DISPLAY_NAME' }
  | { outcome: 'INVALID_LOCALE' }
  | { outcome: 'ACCOUNT_NOT_ACTIVE' };

export const PROFILE_SERVICE = 'PROFILE_SERVICE';

// Miroirs EXACTS des CHECK de la migration 011 : la façade rend une erreur
// propre, le mur porteur reste en base.
const DISPLAY_NAME_MAX = 80;
const LOCALE_SHAPE = /^[a-z]{2,3}(-[A-Z]{2})?$/;

/**
 * Le profil de base (CDC §2) : nom d'affichage et langue, optionnels.
 * JAMAIS loggé (un nom est de la PII), JAMAIS dans un jeton. Ce service ne
 * logge rien. BOLA : accountId vient du jeton signé, jamais du corps.
 * Sémantique PUT : la requête REMPLACE le profil — un champ absent ou null
 * l'efface.
 */
export class ProfileService {
  constructor(private readonly pool: Pool) {}

  async get(accountId: string): Promise<ProfileView> {
    const result = await this.pool.query<{ display_name: string | null; locale: string | null }>(
      'SELECT display_name, locale FROM account_profiles WHERE account_id = $1',
      [accountId],
    );
    const row = result.rows[0];
    return { displayName: row?.display_name ?? null, locale: row?.locale ?? null };
  }

  async replace(
    accountId: string,
    profile: { displayName: string | null; locale: string | null },
  ): Promise<UpdateProfileResult> {
    if (
      profile.displayName !== null &&
      (profile.displayName.length < 1 || profile.displayName.length > DISPLAY_NAME_MAX)
    ) {
      return { outcome: 'INVALID_DISPLAY_NAME' };
    }
    if (profile.locale !== null && !LOCALE_SHAPE.test(profile.locale)) {
      return { outcome: 'INVALID_LOCALE' };
    }

    try {
      await this.pool.query(
        `INSERT INTO account_profiles (account_id, display_name, locale)
         VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO UPDATE
           SET display_name = EXCLUDED.display_name, locale = EXCLUDED.locale`,
        [accountId, profile.displayName, profile.locale],
      );
    } catch (err) {
      if (isDbError(err, DB_ERROR.DEAD_PARENT)) {
        return { outcome: 'ACCOUNT_NOT_ACTIVE' };
      }
      throw err;
    }
    return { outcome: 'OK', profile: { ...profile } };
  }
}
