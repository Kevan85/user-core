import { Logger } from '@nestjs/common';
import { request as httpRequest, type Server } from 'http';
import type { AddressInfo, Socket } from 'net';
import { IdentityService } from '../../src/accounts/identity.service';
import { ProfileService } from '../../src/accounts/profile.service';
import { RegistrationService } from '../../src/accounts/registration.service';
import { AppModule, type AuthWiring } from '../../src/app.module';
import { assembleAuthFromEnv } from '../../src/auth/auth-config';
import { AuthService } from '../../src/auth/auth.service';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { SessionService } from '../../src/auth/session.service';
import { createApiApplication } from '../../src/bootstrap/api-application';
import { assembleApiFromEnv, assertBridledRole, type ApiAssembly } from '../../src/bootstrap/assembly';
import { assembleTrustedProxiesFromEnv } from '../../src/bootstrap/trusted-proxies';
import { CatalogService } from '../../src/catalog/catalog.service';
import {
  ClientAddress,
  reportClientAddressSignal,
  type ClientAddressSignal,
} from '../../src/client-address/client-address';
import { assembleKeyringsFromEnv } from '../../src/crypto/keyring';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { ObservabilityExceptionFilter } from '../../src/observability/observability.filter';
import { EmancipationService } from '../../src/persons/emancipation.service';
import { ErasureService } from '../../src/persons/erasure.service';
import { ResponsibilitiesService } from '../../src/persons/responsibilities.service';
import { assemblePhoneConfig } from '../../src/phone/phone-config';
import { PhoneService } from '../../src/phone/phone.service';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { buildJwks } from '../../src/programs/jwks';
import { assembleProgramAuthFromEnv } from '../../src/programs/program-auth-config';
import { ProgramAuthService } from '../../src/programs/program-auth.service';
import { ProgramGrantsService } from '../../src/programs/program-grants.service';
import { assembleProgramOperationsFromEnv } from '../../src/programs/program-operations-config';
import { ProgramRequestAuth } from '../../src/programs/program-request-auth';
import { LyingProver } from '../../src/proving/simulator/lying-prover';
import { constructedEnv } from './constructed-env';

/**
 * LE HARNAIS HTTP DE L'API (lot déploiement, étape 2, sous-étape 4) — l'application
 * de PRODUCTION, dans le processus de test, sur un port libre.
 *
 * Elle écoute SANS HÔTE, comme main.ts : en double pile, un client IPv4 y arrive
 * sous la forme ::ffff:127.0.0.1 — celle que la production voit, et celle qui a
 * trompé le patron voisin (comparaison de chaînes exacte). Écouter sur 127.0.0.1
 * aurait caché ce chemin aux tests (bloc A-2026-10-03-1, P4) ; un test regarde la
 * forme vue par le service (remoteAddresses).
 *
 * Ce qui est RÉEL : la fabrique (createApiApplication, donc les mêmes lecteurs de
 * corps que main.ts — un test le prouve par un 415), le module (AppModule.register,
 * donc les vrais contrôleurs et leur surface), les assembleurs de configuration, le
 * point unique de l'adresse cliente, les services et leurs throttles, le rôle bridé.
 * L'environnement est CONSTRUIT (constructed-env.ts) et passé EXPLICITEMENT à chaque
 * assembleur : process.env, où Jest a chargé le .env du poste, n'est jamais lu.
 *
 * Ce qui est RÉDUIT : chaque plafond par adresse à HARNESS_BUDGET (un dépassement
 * coûte trois requêtes), argon2 au minimum de la bibliothèque (vitesse, comme
 * tests/helpers/auth.ts ; sans effet sur l'objet testé).
 *
 * ⚠️ LIMITE, écrite plutôt que tue : le câblage des services est RECOPIÉ de main.ts
 * (assembleAccountWiring, assembleProgramWiring), qui s'exécute dès qu'on l'importe.
 * Un écart futur de ce câblage — un throttle partagé entre deux surfaces, un budget
 * branché sur la mauvaise variable — ne serait pas vu ici ; le démarrage réel reste
 * prouvé par main-boot.spec.ts. Murs de démarrage rejoués : le rôle bridé et
 * l'aiguilleur. Non rejoués : l'alignement du trousseau d'empreinte (sans rapport
 * avec l'objet), les secrets publics et l'observabilité (armés seulement).
 */
export const HARNESS_BUDGET = 2;

const HARNESS_SETTINGS: NodeJS.ProcessEnv = {
  AUTH_REGISTER_THROTTLE_MAX_ATTEMPTS: String(HARNESS_BUDGET),
  AUTH_THROTTLE_MAX_ATTEMPTS: String(HARNESS_BUDGET),
  PROGRAM_TOKEN_THROTTLE_MAX_ATTEMPTS: String(HARNESS_BUDGET),
  AUTH_ARGON2_MEMORY_COST: '2048',
  AUTH_ARGON2_TIME_COST: '2',
  AUTH_ARGON2_PARALLELISM: '1',
};

export interface HarnessOptions {
  /** Réglages propres au test (USER_CORE_TRUSTED_PROXIES, NODE_ENV), posés en dernier. */
  readonly env?: NodeJS.ProcessEnv;
  /** Un espion à la place du puits de production — le point unique reste celui que l'env assemble. */
  readonly signal?: (signal: ClientAddressSignal) => void;
}

export interface RunningApi {
  readonly port: number;
  /** L'adresse de chaque connexion telle que le SERVICE l'a vue (sa socket), dans l'ordre d'arrivée. */
  remoteAddresses(): readonly string[];
  close(): Promise<void>;
}

/** Le câblage de main.ts, recopié dans son ordre (voir la limite ci-dessus). */
async function services(assembly: ApiAssembly, env: NodeJS.ProcessEnv): Promise<Omit<AuthWiring, 'clientAddress'>> {
  const { pool } = assembly;
  const authConfig = assembleAuthFromEnv(env);
  const crypto = assembleKeyringsFromEnv(env);
  const phoneConfig = assemblePhoneConfig(env);
  const programConfig = assembleProgramAuthFromEnv(env);
  const login = (): LoginThrottle => new LoginThrottle(authConfig.throttleMaxAttempts, authConfig.throttleWindowSeconds);
  const register = (): LoginThrottle =>
    new LoginThrottle(authConfig.registerThrottleMaxAttempts, authConfig.registerThrottleWindowSeconds);

  const provider = new LocalAuthenticationProvider(authConfig);
  await provider.init();
  const authService = new AuthService(pool, provider, provider, authConfig, login());
  return {
    authService,
    sessionService: new SessionService(pool, provider, authConfig, login()),
    provider,
    phoneService: new PhoneService(pool, crypto, crypto.proofCode, new LyingProver(), phoneConfig),
    catalogService: new CatalogService(pool),
    registrationService: new RegistrationService(pool, provider, authService, authConfig, register()),
    profileService: new ProfileService(pool),
    identityService: new IdentityService(pool, crypto),
    responsibilitiesService: new ResponsibilitiesService(pool, crypto),
    emancipationService: new EmancipationService(
      pool,
      crypto,
      crypto.proofCode,
      new LyingProver(),
      phoneConfig,
      provider,
      authConfig,
      register(),
    ),
    erasureService: new ErasureService(pool, register()),
    accountInvitationsService: new AccountInvitationsService(pool, crypto),
    programAuthService: new ProgramAuthService(
      pool,
      authConfig,
      programConfig,
      new LoginThrottle(programConfig.throttleMaxAttempts, programConfig.throttleWindowSeconds),
    ),
    programRequestAuth: new ProgramRequestAuth(
      authConfig,
      new LoginThrottle(programConfig.apiThrottleMaxAttempts, programConfig.apiThrottleWindowSeconds),
    ),
    dependentAccessService: new DependentAccessService(pool, crypto, crypto.reference, assembleProgramOperationsFromEnv(env)),
    programGrantsService: new ProgramGrantsService(pool),
    jwks: buildJwks(authConfig),
  };
}

export async function startApi(options: HarnessOptions = {}): Promise<RunningApi> {
  const env = constructedEnv({ ...HARNESS_SETTINGS, ...options.env });
  const assembly = assembleApiFromEnv(env);
  try {
    await assertBridledRole(assembly.pool);
    const trusted = assembleTrustedProxiesFromEnv(env);
    const clientAddress = new ClientAddress({
      trust: trusted.trust,
      armed: trusted.armed,
      signal: options.signal ?? reportClientAddressSignal,
    });
    Logger.overrideLogger(false);
    const app = await createApiApplication(
      AppModule.register(assembly, { ...(await services(assembly, env)), clientAddress }),
    );
    app.useGlobalFilters(new ObservabilityExceptionFilter(app.getHttpAdapter()));
    await app.listen(0);
    const server = app.getHttpServer() as Server;
    const seen: string[] = [];
    server.on('connection', (socket: Socket) => seen.push(socket.remoteAddress ?? 'socket détruite'));
    const { port } = server.address() as AddressInfo;
    return {
      port,
      remoteAddresses: () => [...seen],
      close: async () => {
        await app.close();
        await assembly.pool.end();
      },
    };
  } catch (err) {
    await assembly.pool.end();
    throw err;
  }
}

export interface Sent {
  /** Un objet part en JSON ; une chaîne part telle quelle, sous le content-type des en-têtes. */
  readonly body?: object | string;
  readonly headers?: Readonly<Record<string, string>>;
}

/** Un POST sur une connexion NEUVE (agent: false) : chaque requête arrive de la boucle locale. */
export function post(port: number, path: string, sent: Sent = {}): Promise<number> {
  const payload = typeof sent.body === 'object' ? JSON.stringify(sent.body) : sent.body;
  const headers: Record<string, string> = {
    ...(typeof sent.body === 'object' ? { 'content-type': 'application/json' } : {}),
    ...(payload === undefined ? {} : { 'content-length': String(Buffer.byteLength(payload)) }),
    ...sent.headers,
  };
  return new Promise((done, fail) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'POST', headers, agent: false }, (res) => {
      res.resume();
      done(res.statusCode ?? 0);
    });
    req.on('error', fail);
    req.end(payload);
  });
}
