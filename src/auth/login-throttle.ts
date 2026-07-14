/**
 * Throttle à fenêtre fixe, en mémoire (1 service, V1 sobre) : par IP ET par
 * identifiant VISÉ (tranché Q3 — un attaquant distribue ses IP ; c'est le
 * compte qu'on protège). La clé « identifiant » est la chaîne soumise,
 * qu'elle existe ou non : le throttle ne révèle rien de l'existence d'un
 * compte. La vraie garde reste le verrouillage progressif EN BASE (C8) —
 * ceci borne le débit, pas les tentatives.
 */
interface WindowCounter {
  windowStartMs: number;
  count: number;
}

const SWEEP_THRESHOLD = 10_000;

export class LoginThrottle {
  private readonly counters = new Map<string, WindowCounter>();

  constructor(
    private readonly maxAttempts: number,
    private readonly windowSeconds: number,
    private readonly nowMs: () => number = Date.now,
  ) {}

  /** Consomme une tentative sur les DEUX compteurs ; false = refuser. */
  allow(clientIp: string, identifier: string): boolean {
    const ipAllowed = this.consume(`ip:${clientIp}`);
    const idAllowed = this.consume(`id:${identifier}`);
    return ipAllowed && idAllowed;
  }

  private consume(key: string): boolean {
    const now = this.nowMs();
    const windowMs = this.windowSeconds * 1000;
    if (this.counters.size > SWEEP_THRESHOLD) {
      for (const [k, c] of this.counters) {
        if (now - c.windowStartMs >= windowMs) {
          this.counters.delete(k);
        }
      }
    }
    const counter = this.counters.get(key);
    if (counter === undefined || now - counter.windowStartMs >= windowMs) {
      this.counters.set(key, { windowStartMs: now, count: 1 });
      return true;
    }
    counter.count += 1;
    return counter.count <= this.maxAttempts;
  }
}
