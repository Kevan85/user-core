import { randomUUID } from 'crypto';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import { ProgramRequestAuth } from '../../src/programs/program-request-auth';
import { issueProgramToken } from '../../src/programs/program-token';
import { testAuthAssembly } from '../helpers/auth';

// LE MUR D'APPEL de /v1 (étape 1) : le programme vient du jeton signé, et de
// lui seul ; le budget métier se compte par client authentifié. Aucune base
// ici — le mur est pur (jeton + horloge + compteur), il se prouve à sec.
describe('/v1 — le mur d\'appel des programmes (étape 1)', () => {
  const authConfig = testAuthAssembly();

  function wall(maxAttempts = 1000): ProgramRequestAuth {
    return new ProgramRequestAuth(authConfig, new LoginThrottle(maxAttempts, 60));
  }

  function bearer(clientId: string, programId: string, ttlSeconds = 60): string {
    return `Bearer ${issueProgramToken(authConfig, { sub: clientId, pid: programId }, ttlSeconds).token}`;
  }

  test('jeton valide → le programme résolu EST celui du jeton (BOLA : ni URL, ni corps, ni en-tête libre)', () => {
    const clientId = randomUUID();
    const programId = randomUUID();
    const result = wall().authenticate(bearer(clientId, programId));
    expect(result).toEqual({ outcome: 'OK', caller: { clientId, programId } });
  });

  test('absent, difforme, signature étrangère, périmé : UN SEUL refus, rien ne s\'énumère', () => {
    const guard = wall();
    expect(guard.authenticate(undefined).outcome).toBe('UNAUTHORIZED');
    expect(guard.authenticate('Bearer ').outcome).toBe('UNAUTHORIZED');
    expect(guard.authenticate('Basic abc').outcome).toBe('UNAUTHORIZED');
    expect(guard.authenticate('Bearer pas-un-jeton').outcome).toBe('UNAUTHORIZED');

    // Signé par une AUTRE clé (un faux trousseau complet, pas juste un octet
    // corrompu) : le vérificateur ne reconnaît pas le kid, ou la signature.
    const foreign = testAuthAssembly();
    const forged = issueProgramToken(foreign, { sub: 'c', pid: 'p' }, 60).token;
    expect(guard.authenticate(`Bearer ${forged}`).outcome).toBe('UNAUTHORIZED');

    // Périmé : émis avec un TTL déjà écoulé.
    const stale = issueProgramToken(authConfig, { sub: 'c', pid: 'p' }, -10).token;
    expect(guard.authenticate(`Bearer ${stale}`).outcome).toBe('UNAUTHORIZED');
  });

  test('DISJONCTION : un jeton de COMPTE (sub/sid), émis par le vrai fournisseur, est nul ici', async () => {
    const provider = new LocalAuthenticationProvider(authConfig);
    const accountToken = await provider.issueAccessToken({
      sub: randomUUID(),
      sid: randomUUID(),
    });
    expect(wall().authenticate(`Bearer ${accountToken.token}`).outcome).toBe('UNAUTHORIZED');
  });

  test('le budget métier se compte PAR CLIENT : épuiser A ne touche pas B — et rien avant authentification', () => {
    const guard = wall(2);
    const clientA = bearer('client-a', randomUUID());
    const clientB = bearer('client-b', randomUUID());

    expect(guard.authenticate(clientA).outcome).toBe('OK');
    expect(guard.authenticate(clientA).outcome).toBe('OK');
    expect(guard.authenticate(clientA).outcome).toBe('THROTTLED');

    // B garde son budget entier : le plafond n'est pas global (un plafond
    // partagé serait un levier de déni de service offert à n'importe qui).
    expect(guard.authenticate(clientB).outcome).toBe('OK');

    // Un porteur NON authentifié ne consomme AUCUN budget : après dix rebuts,
    // B passe encore — l'absence se prouve en comptant les passages restants.
    for (let i = 0; i < 10; i += 1) {
      expect(guard.authenticate('Bearer rebut').outcome).toBe('UNAUTHORIZED');
    }
    expect(guard.authenticate(clientB).outcome).toBe('OK');
  });
});
