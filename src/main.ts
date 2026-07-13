import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { assembleApiFromEnv } from './bootstrap/assembly';

// Le service ne migre JAMAIS la base au démarrage : les migrations sont un
// acte d'exploitation séparé (npm run migrate), pas un effet de bord d'un boot.
async function bootstrap(): Promise<void> {
  const assembly = assembleApiFromEnv();
  const app = await NestFactory.create(AppModule.register(assembly));

  // Arrêt propre — on cesse d'accepter, on finit, on ferme le pool.
  const shutdown = async (): Promise<void> => {
    await app.close();
    await assembly.pool.end();
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown());
  process.once('SIGINT', () => void shutdown());

  await app.listen(assembly.port);
}

bootstrap().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
