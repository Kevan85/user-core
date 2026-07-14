/**
 * Le contrat entre la base et le service s'écrit en CODE, jamais en français.
 *
 * Avant 005, le service attrapait une violation de trigger en matchant le
 * TEXTE du message. Le jour où quelqu'un reformule ce message — en toute
 * bonne foi, pour le clarifier — la garde applicative tombe en silence.
 * Les codes de la classe P01xx (posés par la migration 005) sont stables :
 * un message peut changer, un code jamais.
 */
export const DB_ERROR = {
  IMMUTABLE: 'P0101',
  FORBIDDEN_TRANSITION: 'P0102',
  FROZEN_ROW: 'P0103',
  REGISTRY_TIMESTAMP: 'P0104',
  LOCK_WOULD_RECEDE: 'P0105',
  ILLEGAL_ATTEMPT_COUNTER: 'P0106',
  DELETE_FORBIDDEN: 'P0107',
  DEAD_PARENT: 'P0108',
} as const;

export type DbErrorCode = (typeof DB_ERROR)[keyof typeof DB_ERROR];

// pg pose `code` sur l'erreur ; il n'est pas dans le type Error standard.
export function dbErrorCode(err: unknown): string | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const { code } = err as { code?: unknown };
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

export function isDbError(err: unknown, code: DbErrorCode): boolean {
  return dbErrorCode(err) === code;
}
