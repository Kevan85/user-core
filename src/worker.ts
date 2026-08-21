import 'dotenv/config';
import 'reflect-metadata';
import { assembleApiFromEnv, assertBridledRole } from './bootstrap/assembly';
import { assertProductionSecretsNotPublic } from './bootstrap/production-secrets';
import { declareSimulatedSeam } from './bootstrap/simulation';
import {
  assembleObservabilityFromEnv,
  captureError,
  flushObservability,
  initObservability,
} from './observability/sentry';
import { assembleKeyringsFromEnv } from './crypto/keyring';
import { CountingDispatcher } from './dispatch/simulator/counting-dispatcher';
import { assemblePublisherConfig } from './outbox/publisher-config';
import { OutboxPublisher } from './outbox/publisher';
import { ErasureScheduler } from './persons/erasure-scheduler';
import { assertFingerprintKeyAligned } from './phone/phone-config';

/**
 * LE worker (processus SÉPARÉ, patron payment-core) : un drainage qui bloque
 * l'API serait un défaut. Boucle « exécute puis attend » — l'intervalle
 * sépare deux passages, il ne les superpose jamais.
 */
async function main(): Promise<void> {
  // Même mur que l'API (étape 3) : un secret publié refuse de démarrer.
  assertProductionSecretsNotPublic();
  // Même règle que l'API (étape 5) : murs armés sans DSN = refus (C2).
  initObservability(assembleObservabilityFromEnv());
  const assembly = assembleApiFromEnv();
  // Le worker ne se sert que du chiffrement et de l'empreinte, mais il valide
  // les QUATRE trousseaux (dette ②) : la config d'une machine est saine ou ne
  // l'est pas — jamais « saine pour le processus qui s'en sert ».
  // Contrepartie assumée : il détient en mémoire deux trousseaux dont il n'a
  // aucun usage (codes, références). Le jour où le worker se déploie sur une
  // machine distincte avec son propre env, cette exigence inverse le moindre
  // privilège — la règle se révise alors, elle ne se défend pas.
  const crypto = assembleKeyringsFromEnv();
  const config = assemblePublisherConfig();

  await assertBridledRole(assembly.pool);
  await assertFingerprintKeyAligned(assembly.pool, crypto);

  // LE MUR DES DOUBLURES. Cette ligne portait un commentaire qui NOMMAIT le
  // risque — « le dispatcher de simulation tant qu'aucun fournisseur réel
  // n'est branché » — sans qu'aucun mur ne le tienne : leçon ⑬, un risque
  // nommé donne au lecteur suivant le sentiment qu'il est traité. Sous murs
  // de production, la couture DISPATCH se DÉCLARE ou le worker refuse de
  // démarrer. Le fournisseur réel reste une inconnue de terrain (son prix et
  // sa disponibilité en RDC), et c'est justement pourquoi le mur est ici.
  declareSimulatedSeam('DISPATCH');
  const publisher = new OutboxPublisher(
    assembly.pool,
    new CountingDispatcher(),
    crypto,
    config,
  );
  // Le chemin différé de l'effacement (étape 4) : préavis à J-48 h, exécution
  // à l'échéance — même boucle, même processus, aucune couture neuve.
  const erasures = new ErasureScheduler(assembly.pool);

  let stopping = false;
  const shutdown = async (): Promise<void> => {
    stopping = true;
    await assembly.pool.end();
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown());
  process.once('SIGINT', () => void shutdown());

  while (!stopping) {
    try {
      const report = await publisher.drain();
      if (report.claimed > 0) {
        // Zéro PII : des comptes, jamais un destinataire.
        console.log(
          `outbox: ${report.claimed} pris, ${report.published} publiés, ` +
            `${report.retried} à retenter, ${report.failed} morts`,
        );
      }
      const erasureReport = await erasures.tick();
      if (
        erasureReport.noticed > 0 ||
        erasureReport.executed > 0 ||
        erasureReport.blocked > 0 ||
        erasureReport.failed > 0
      ) {
        // Zéro PII : des comptes d'actes, jamais une personne.
        console.log(
          `effacement: ${erasureReport.noticed} préavis, ` +
            `${erasureReport.executed} exécutés, ${erasureReport.blocked} bloqués (mur), ` +
            `${erasureReport.failed} en PANNE`,
        );
      }
    } catch (err) {
      // Une défaillance du drainage part vers l'observabilité AVANT de tuer
      // le processus — un worker mort en silence est un fail-open.
      captureError(err);
      await flushObservability();
      throw err;
    }
    await new Promise((resolve) => setTimeout(resolve, config.tickIntervalMs));
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
