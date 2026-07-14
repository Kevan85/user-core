import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'crypto';
import type { AuthAssembly } from '../../src/auth/auth-config';

// Paramètres argon2id ALLÉGÉS pour les tests (C7 : ils viennent de la config,
// et c'est précisément ce que ce helper prouve — les vrais défauts sont dans
// .env.example). 2048 KiB / 2 passes / p=1 : le minimum accepté par la lib.
export function testAuthAssembly(overrides: Partial<AuthAssembly> = {}): AuthAssembly {
  const { privateKey } = generateKeyPairSync('ed25519');
  const kid = 'T1';
  return {
    accessTokenTtlSeconds: 900,
    activeKid: kid,
    keys: new Map([[kid, { kid, privateKey, publicKey: createPublicKey(privateKey) }]]),
    argon2: { memoryCost: 2048, timeCost: 2, parallelism: 1 },
    lockThreshold: 2,
    lockBaseSeconds: 60,
    lockCapSeconds: 3600,
    refreshTokenTtlSeconds: 3600,
    sessionAbsoluteTtlSeconds: 7200,
    graceWindowSeconds: 30,
    throttleMaxAttempts: 1000,
    throttleWindowSeconds: 60,
    secretMinLength: 8,
    registerThrottleMaxAttempts: 1000,
    registerThrottleWindowSeconds: 60,
    ...overrides,
  };
}

export function ed25519KeyBase64(): string {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
}

// Vérifie qu'une clé exportée est bien relisible (garde le helper honnête).
export function assertImportable(base64: string): void {
  createPrivateKey({ key: Buffer.from(base64, 'base64'), format: 'der', type: 'pkcs8' });
}
