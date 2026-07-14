import { Pool } from 'pg';

export const PG_POOL = 'PG_POOL';

export function createPool(connectionString: string): Pool {
  const pool = new Pool({ connectionString });
  // Sans handler, la rupture d'une connexion idle (base redémarrée, réseau
  // coupé) émet un 'error' non capté qui TUE le process Node. Le pool doit
  // survivre : les requêtes suivantes rouvrent une connexion. Log sans PII.
  pool.on('error', (err) => {
    console.error(`pg pool: connexion idle perdue (${err.name})`);
  });
  return pool;
}
