import { LoginThrottle } from '../../src/auth/login-throttle';

describe('LoginThrottle (Q3 : par IP ET par identifiant visé)', () => {
  test('au-delà du plafond par IP → refus, même en changeant d\'identifiant', () => {
    let clock = 0;
    const throttle = new LoginThrottle(3, 60, () => clock);
    expect(throttle.allow('1.2.3.4', 'id-a')).toBe(true);
    expect(throttle.allow('1.2.3.4', 'id-b')).toBe(true);
    expect(throttle.allow('1.2.3.4', 'id-c')).toBe(true);
    expect(throttle.allow('1.2.3.4', 'id-d')).toBe(false);
    clock += 61_000; // la fenêtre expire
    expect(throttle.allow('1.2.3.4', 'id-e')).toBe(true);
  });

  test('au-delà du plafond par identifiant → refus, même en distribuant les IP', () => {
    const throttle = new LoginThrottle(3, 60, () => 0);
    expect(throttle.allow('10.0.0.1', 'cible')).toBe(true);
    expect(throttle.allow('10.0.0.2', 'cible')).toBe(true);
    expect(throttle.allow('10.0.0.3', 'cible')).toBe(true);
    // 4 IP différentes : c'est le COMPTE visé qui est protégé.
    expect(throttle.allow('10.0.0.4', 'cible')).toBe(false);
  });

  test('les compteurs sont indépendants entre identifiants', () => {
    const throttle = new LoginThrottle(2, 60, () => 0);
    expect(throttle.allow('10.0.0.1', 'a')).toBe(true);
    expect(throttle.allow('10.0.0.2', 'a')).toBe(true);
    expect(throttle.allow('10.0.0.3', 'a')).toBe(false);
    expect(throttle.allow('10.0.0.4', 'b')).toBe(true);
  });
});
