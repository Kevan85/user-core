import { spawn, type ChildProcess } from 'child_process';
import { readFileSync } from 'fs';
import { createServer, get, request as httpRequest } from 'http';
import type { AddressInfo } from 'net';
import { join, resolve } from 'path';
import { ed25519KeyBase64 } from '../helpers/auth';
import { appUrl } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * LE PREMIER TEST DE DÉMARRAGE DU DÉPÔT (lot déploiement, étape 2a).
 *
 * Jusqu'ici, aucun test ne regardait src/main.ts : les services étaient testés
 * un par un, jamais leur assemblage. Couper bootstrap() pour R2 (125 lignes de
 * code, plafond 100) exigeait une preuve de comportement inchangé — ce test est
 * cette preuve : le VRAI point d'entrée, dans un vrai processus, doit démarrer et
 * servir /health (qui interroge réellement la base). Il a été vu vert sur le
 * main.ts d'avant la coupe, puis sur celui d'après.
 *
 * L'ENVIRONNEMENT EST CONSTRUIT, JAMAIS HÉRITÉ (leçon ⑪ : une garde qui ne
 * passe que sur le poste de celui qui la teste ne prouve rien). Jest charge le
 * .env du poste dans process.env : l'hériter ferait passer ce test ici et casser
 * en CI. L'enfant ne reçoit donc que quelques variables système, puis :
 * - les réglages du gabarit PUBLIC .env.example — si le code exige un jour une
 *   variable que le gabarit ne porte pas, ce test rougit, et le gabarit reste
 *   complet ;
 * - des secrets TIRÉS pour l'occasion (les quatre trousseaux, la clé de
 *   signature), jamais ceux d'un poste ;
 * - DOTENV_CONFIG_PATH vers un fichier inexistant, pour que main.ts ne recharge
 *   pas le .env du poste par son propre import de dotenv.
 */
const ROOT = resolve(__dirname, '..', '..');
const SYSTEM_VARIABLES = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'windir', 'TEMP', 'TMP', 'HOME', 'USERPROFILE'];

function systemOnly(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of SYSTEM_VARIABLES) {
    if (process.env[name] !== undefined) {
      env[name] = process.env[name];
    }
  }
  return env;
}

function publicTemplate(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const line of readFileSync(join(ROOT, '.env.example'), 'utf8').split('\n')) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (match?.[1] !== undefined && match[2] !== undefined) {
      env[match[1]] = match[2];
    }
  }
  return env;
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((done) => server.close(() => done()));
  return port;
}

function healthStatus(port: number): Promise<number | null> {
  return new Promise((done) => {
    get({ host: '127.0.0.1', port, path: '/health' }, (res) => {
      res.resume();
      done(res.statusCode ?? null);
    }).on('error', () => done(null));
  });
}

function constructedEnv(port: number): NodeJS.ProcessEnv {
  return {
    ...systemOnly(),
    ...publicTemplate(),
    ...fullKeyringEnv(),
    AUTH_SIGNING_KEYS: JSON.stringify({ B1: ed25519KeyBase64() }),
    AUTH_ACTIVE_KEY_ID: 'B1',
    DATABASE_URL: appUrl(),
    PORT: String(port),
    NODE_ENV: 'test',
    DOTENV_CONFIG_PATH: join(ROOT, 'aucun-fichier-env-ici.env'),
    TS_NODE_PROJECT: join(ROOT, 'tsconfig.json'),
  };
}

interface Boot {
  child: ChildProcess;
  output: () => string;
  exitCode: () => number | null;
}

function boot(env: NodeJS.ProcessEnv): Boot {
  let output = '';
  let exitCode: number | null = null;
  const child = spawn(process.execPath, ['-r', 'ts-node/register/transpile-only', join(ROOT, 'src', 'main.ts')], {
    cwd: ROOT,
    env,
  });
  child.stdout?.on('data', (chunk) => (output += String(chunk)));
  child.stderr?.on('data', (chunk) => (output += String(chunk)));
  child.on('exit', (code) => (exitCode = code ?? -1));
  return { child, output: () => output, exitCode: () => exitCode };
}

function post(port: number, path: string, type?: string, body?: string): Promise<number | null> {
  return new Promise((done) => {
    const headers: Record<string, string> = type === undefined ? {} : { 'content-type': type };
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'POST', headers }, (res) => {
      res.resume();
      done(res.statusCode ?? null);
    });
    req.on('error', () => done(null));
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

async function healthyWithin(running: Boot, port: number, ms: number): Promise<number | null> {
  let status: number | null = null;
  const deadline = Date.now() + ms;
  while (status !== 200 && running.exitCode() === null && Date.now() < deadline) {
    status = await healthStatus(port);
    if (status !== 200) {
      await new Promise((done) => setTimeout(done, 300));
    }
  }
  return status;
}

async function exitWithin(running: Boot, ms: number): Promise<number | null> {
  const deadline = Date.now() + ms;
  while (running.exitCode() === null && Date.now() < deadline) {
    await new Promise((done) => setTimeout(done, 200));
  }
  return running.exitCode();
}

describe('main.ts — le vrai point d’entrée démarre et sert /health', () => {
  let running: Boot | undefined;

  afterEach(() => {
    running?.child.kill();
    running = undefined;
  });

  test('démarrage réel, environnement construit, /health répond 200', async () => {
    const port = await freePort();
    running = boot(constructedEnv(port));

    let status: number | null = null;
    const deadline = Date.now() + 45_000;
    while (status !== 200 && running.exitCode() === null && Date.now() < deadline) {
      status = await healthStatus(port);
      if (status !== 200) {
        await new Promise((done) => setTimeout(done, 300));
      }
    }

    if (status !== 200) {
      throw new Error(`démarrage raté (sortie ${String(running.exitCode())}) :\n${running.output().slice(-1500)}`);
    }
    expect(status).toBe(200);
  }, 60_000);

  test('ISOLEMENT (héritage) — rien de l’environnement de Jest ne passe à l’enfant, hors liste système', () => {
    // Le chemin de fuite n°1 : passer process.env à l'enfant. Jest y a chargé le
    // .env du poste ; tout ce qui y figure passerait. Un témoin posé dans
    // process.env ne doit donc jamais apparaître dans l'environnement construit.
    process.env.BOOT_TEST_INHERITANCE_SENTINEL = 'fuite';
    try {
      expect(constructedEnv(1)).not.toHaveProperty('BOOT_TEST_INHERITANCE_SENTINEL');
    } finally {
      delete process.env.BOOT_TEST_INHERITANCE_SENTINEL;
    }
  });

  test('ISOLEMENT (relecture) — sans DATABASE_URL, le démarrage est REFUSÉ : main.ts ne relit pas le .env du poste', async () => {
    // Le chemin de fuite n°2 : le « import 'dotenv/config' » de main.ts relit le
    // .env du répertoire courant. DATABASE_URL est EXIGÉE (aucune valeur de
    // repli) et le .env d'un poste de développement la définit : s'il était
    // relu, l'enfant démarrerait sur la base de développement, et ce test
    // rougirait. Sur une machine sans .env (la CI), il n'y a rien à fuir.
    const env = constructedEnv(await freePort());
    delete env.DATABASE_URL;
    running = boot(env);

    const exitCode = await exitWithin(running, 45_000);
    expect(exitCode).not.toBeNull();
    expect(exitCode).not.toBe(0);
    expect(running.output()).toContain('DATABASE_URL manquant');
  }, 60_000);

  test('JSON SEULEMENT (étape 3bis) — chaque corps reçoit un refus PROPRE, jamais un 500', async () => {
    // Mesuré le 03/10/2026 avant cette étape : formulaire 401 (ses champs lus par
    // qs), text/plain 500, sans corps 500. Un 500 est une exception « inattendue »
    // qui part vers l'observabilité : un client non authentifié en fabriquait à
    // volonté. Les deux routes sans corps prouvent qu'aucune n'a été cassée.
    const port = await freePort();
    running = boot(constructedEnv(port));
    expect(await healthyWithin(running, port, 45_000)).toBe(200);

    const login = JSON.stringify({ identifier: 'inconnu', secret: 'faux-secret' });
    expect({
      json: await post(port, '/auth/login', 'application/json', login),
      formulaire: await post(port, '/auth/login', 'application/x-www-form-urlencoded', 'identifier=inconnu&secret=x'),
      textePlat: await post(port, '/auth/login', 'text/plain', 'identifier=inconnu'),
      sansCorps: await post(port, '/auth/login'),
      jsonInvalide: await post(port, '/auth/login', 'application/json', '{pas du json'),
      deconnexionSansCorps: await post(port, '/auth/logout'),
      revocationSansCorps: await post(port, '/auth/sessions/revoke-all'),
    }).toEqual({
      json: 401,
      formulaire: 415,
      textePlat: 415,
      sansCorps: 400,
      jsonInvalide: 400,
      deconnexionSansCorps: 401,
      revocationSansCorps: 401,
    });
  }, 60_000);

  test('LE MUR DE L’AIGUILLEUR EST APPELÉ AU DÉMARRAGE — « 1 » refuse le boot, même en murs relâchés', async () => {
    // Leçon ⑮ : en murs relâchés, l'ABSENCE de la variable passe en silence — si
    // l'appel du mur disparaissait de bootstrap(), aucun autre test ne rougirait.
    // Une valeur DÉCLARÉE, elle, est validée dans tous les modes : « 1 » (l'habitude
    // Express d'un saut, que la référence lirait comme 0.0.0.1) doit arrêter le
    // vrai main.ts, avec une sortie qui nomme la variable.
    running = boot({ ...constructedEnv(await freePort()), USER_CORE_TRUSTED_PROXIES: '1' });

    const exitCode = await exitWithin(running, 45_000);
    expect(exitCode).not.toBeNull();
    expect(exitCode).not.toBe(0);
    expect(running.output()).toContain('USER_CORE_TRUSTED_PROXIES');
  }, 60_000);
});
