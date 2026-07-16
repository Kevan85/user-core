import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { IdentityService } from './accounts/identity.service';
import { ProfileService } from './accounts/profile.service';
import { RegistrationService } from './accounts/registration.service';
import { AppModule } from './app.module';
import { assembleAuthFromEnv } from './auth/auth-config';
import { AccountInvitationsService } from './invitations/account-invitations.service';
import { AuthService } from './auth/auth.service';
import { LocalAuthenticationProvider } from './auth/local-authentication-provider';
import { LoginThrottle } from './auth/login-throttle';
import { SessionService } from './auth/session.service';
import { assembleApiFromEnv, assertBridledRole } from './bootstrap/assembly';
import { CatalogService } from './catalog/catalog.service';
import { ResponsibilitiesService } from './persons/responsibilities.service';
import { assembleCryptoFromEnv } from './crypto/keyring';
import { assemblePhoneConfig, assertFingerprintKeyAligned } from './phone/phone-config';
import { PhoneService } from './phone/phone.service';
import { buildJwks } from './programs/jwks';
import { assembleProgramAuthFromEnv } from './programs/program-auth-config';
import { ProgramAuthService } from './programs/program-auth.service';
import { assembleProofCodeKeyring } from './proving/proof-code';
import { LyingProver } from './proving/simulator/lying-prover';

// Le service ne migre JAMAIS la base au démarrage : les migrations sont un
// acte d'exploitation séparé (npm run migrate), pas un effet de bord d'un boot.
async function bootstrap(): Promise<void> {
  const assembly = assembleApiFromEnv();
  const authConfig = assembleAuthFromEnv();
  const cryptoConfig = assembleCryptoFromEnv();
  const codeKeyring = assembleProofCodeKeyring();
  const phoneConfig = assemblePhoneConfig();

  // Refus de booter sous un autre rôle que le rôle bridé — AVANT tout trafic.
  await assertBridledRole(assembly.pool);
  // Refus de booter si le trousseau d'empreinte du service diverge de la
  // référence gravée en base : sinon chaque déclaration de numéro serait
  // rejetée en production, une à une, sans cause visible.
  await assertFingerprintKeyAligned(assembly.pool, cryptoConfig);

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
  const sessionService = new SessionService(
    assembly.pool,
    provider,
    authConfig,
    // Throttle DISTINCT de celui du login : les deux surfaces ne partagent
    // pas leur budget de tentatives.
    new LoginThrottle(authConfig.throttleMaxAttempts, authConfig.throttleWindowSeconds),
  );

  // LineOwnershipProver : le simulateur derrière la couture (§3.9). Un
  // fournisseur réel (flash call, SMS, SNA) se branchera ici — son prix et sa
  // disponibilité en RDC sont des inconnues de terrain (CDC §9), pas des
  // valeurs à supposer.
  const phoneService = new PhoneService(
    assembly.pool,
    cryptoConfig,
    codeKeyring,
    new LyingProver(),
    phoneConfig,
  );

  const catalogService = new CatalogService(assembly.pool);

  // LOT 4 — l'inscription publique : throttle DÉDIÉ (par IP seule, budget
  // distinct du login), et la première session naît par le chemin du login.
  const registrationService = new RegistrationService(
    assembly.pool,
    provider,
    authService,
    authConfig,
    new LoginThrottle(
      authConfig.registerThrottleMaxAttempts,
      authConfig.registerThrottleWindowSeconds,
    ),
  );
  const profileService = new ProfileService(assembly.pool);
  // LOT 5 — l'identité civile de la personne du compte : chiffrée par clé
  // dérivée (sel par personne), lue par le point unique avec re-dérivation.
  const identityService = new IdentityService(assembly.pool, cryptoConfig);
  // LOT 5 — le lien de responsabilité : rattacher un ayant droit, ajouter un
  // co-responsable, et l'acte staff de retrait (contrôlé, tracé, atomique).
  const responsibilitiesService = new ResponsibilitiesService(assembly.pool, cryptoConfig);
  const accountInvitationsService = new AccountInvitationsService(assembly.pool);

  // LOT 4 — la porte des programmes : assertion signée Ed25519 → jeton court
  // (pid = LA frontière de /v1), throttle dédié par IP et par client visé.
  const programAuthConfig = assembleProgramAuthFromEnv();
  const programAuthService = new ProgramAuthService(
    assembly.pool,
    authConfig,
    programAuthConfig,
    new LoginThrottle(
      programAuthConfig.throttleMaxAttempts,
      programAuthConfig.throttleWindowSeconds,
    ),
  );
  const jwks = buildJwks(authConfig);

  const app = await NestFactory.create(
    AppModule.register(assembly, {
      authService,
      sessionService,
      provider,
      phoneService,
      catalogService,
      registrationService,
      profileService,
      identityService,
      responsibilitiesService,
      accountInvitationsService,
      programAuthService,
      jwks,
    }),
  );

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
