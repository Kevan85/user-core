import 'dotenv/config';
import 'reflect-metadata';
import { assembleApiFromEnv, assertBridledRole } from './bootstrap/assembly';
import { assembleCryptoFromEnv } from './crypto/keyring';
import { CountingDispatcher } from './dispatch/simulator/counting-dispatcher';
import { assemblePublisherConfig } from './outbox/publisher-config';
import { OutboxPublisher } from './outbox/publisher';
import { assertFingerprintKeyAligned } from './phone/phone-config';

/**
 * LE worker (processus SÉPARÉ, patron payment-core) : un drainage qui bloque
 * l'API serait un défaut. Boucle « exécute puis attend » — l'intervalle
 * sépare deux passages, il ne les superpose jamais.
 */
async function main(): Promise<void> {
  const assembly = assembleApiFromEnv();
  const crypto = assembleCryptoFromEnv();
  const config = assemblePublisherConfig();

  await assertBridledRole(assembly.pool);
  await assertFingerprintKeyAligned(assembly.pool, crypto);

  // Le dispatcher de simulation tant qu'aucun fournisseur réel n'est branché
  // (son prix et sa disponibilité en RDC sont des inconnues de terrain).
  const publisher = new OutboxPublisher(
    assembly.pool,
    new CountingDispatcher(),
    crypto,
    config,
  );

  let stopping = false;
  const shutdown = async (): Promise<void> => {
    stopping = true;
    await assembly.pool.end();
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown());
  process.once('SIGINT', () => void shutdown());

  while (!stopping) {
    const report = await publisher.drain();
    if (report.claimed > 0) {
      // Zéro PII : des comptes, jamais un destinataire.
      console.log(
        `outbox: ${report.claimed} pris, ${report.published} publiés, ` +
          `${report.retried} à retenter, ${report.failed} morts`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, config.tickIntervalMs));
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
