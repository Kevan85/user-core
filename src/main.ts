import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { assembleAuthFromEnv } from './auth/auth-config';
import { AuthService } from './auth/auth.service';
import { LocalAuthenticationProvider } from './auth/local-authentication-provider';
import { LoginThrottle } from './auth/login-throttle';
import { assembleApiFromEnv, assertBridledRole } from './bootstrap/assembly';

// Le service ne migre JAMAIS la base au démarrage : les migrations sont un
// acte d'exploitation séparé (npm run migrate), pas un effet de bord d'un boot.
async function bootstrap(): Promise<void> {
  const assembly = assembleApiFromEnv();
  const authConfig = assembleAuthFromEnv();
  // Refus de booter sous un autre rôle que le rôle bridé — AVANT tout trafic.
  await assertBridledRole(assembly.pool);

  // Assemblage explicite (K2) : le hash de référence C3 se calcule AVANT
  // d'accepter le moindre login — jamais un premier appelant plus rapide.
  const provider = new LocalAuthenticationProvider(authConfig);
  await provider.init();
  const authService = new AuthService(
    assembly.pool,
    provider,
    provider,
    authConfig,
    new LoginThrottle(authConfig.throttleMaxAttempts, authConfig.throttleWindowSeconds),
  );

  const app = await NestFactory.create(AppModule.register(assembly, authService));

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
