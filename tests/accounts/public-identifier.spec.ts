import {
  generatePublicIdentifier,
  PUBLIC_IDENTIFIER_SHAPE,
} from '../../src/accounts/public-identifier';

// C4 — l'identifiant de connexion sort d'un CSPRNG : ni séquence, ni
// horodatage. La preuve d'absence de monotonie se fait sur N tirages RÉELS
// du générateur livré, pas sur une hypothèse.
describe('generatePublicIdentifier (CSPRNG, C4)', () => {
  const N = 1000;
  const draws = Array.from({ length: N }, () => generatePublicIdentifier());

  test(`${N} tirages → tous conformes à la forme contractuelle (10 chiffres, pas de zéro de tête)`, () => {
    for (const d of draws) {
      expect(d).toMatch(PUBLIC_IDENTIFIER_SHAPE);
    }
  });

  test('la suite n\'est PAS monotone (ni croissante, ni décroissante)', () => {
    const asNumbers = draws.map(Number);
    let increases = 0;
    let decreases = 0;
    for (let i = 1; i < asNumbers.length; i++) {
      const current = asNumbers[i];
      const previous = asNumbers[i - 1];
      if (current === undefined || previous === undefined) {
        throw new Error('tirage manquant : indexation impossible');
      }
      if (current > previous) increases++;
      if (current < previous) decreases++;
    }
    // Une séquence (ou un horodatage) donnerait decreases = 0 ; un compteur
    // inversé donnerait increases = 0. Un CSPRNG donne les deux, en nombre.
    expect(increases).toBeGreaterThan(0);
    expect(decreases).toBeGreaterThan(0);
  });

  test('dispersion : pas de plage étroite (quasi-unicité sur N tirages)', () => {
    // Sur ~9 × 10⁹ valeurs, 1000 tirages honnêtes ne se répètent pratiquement
    // jamais (espérance de collision ≈ 5 × 10⁻⁵). Seuil à 999 pour ne pas
    // transformer une probabilité en promesse.
    expect(new Set(draws).size).toBeGreaterThanOrEqual(N - 1);
  });
});
