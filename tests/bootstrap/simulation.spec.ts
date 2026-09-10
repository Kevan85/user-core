import { ConfigViolations } from '../../src/bootstrap/assembly';
import {
  SIMULATED_SEAMS_VARIABLE,
  declareSimulatedSeam,
  type SimulatedSeam,
} from '../../src/bootstrap/simulation';

/**
 * LE MUR DES DOUBLURES — et le test qui le prouve POUR LUI-MÊME (leçon ⑮).
 *
 * La question qui a dicté ce fichier : « quel test rougirait si on retirait le
 * mur ce soir ? ». Réponse : ceux-ci, et rien d'autre dans le dépôt — les 551
 * autres tests tournent sous murs relâchés (NODE_ENV=test) et passeraient
 * exactement pareil, mur ou pas. Une garde regardée par personne n'est pas
 * protégée, elle est seulement présente.
 *
 * Le contrôle négatif est aussi important que le mur : si « development » ou
 * « test » se mettait à lever, le poste de développement et toute la CI
 * s'arrêteraient — un mur trop large tue ce qu'il garde.
 */
const SEAMS: SimulatedSeam[] = ['PROVING', 'DISPATCH'];
const ARMED = { NODE_ENV: 'production' };

describe('declareSimulatedSeam — le mode simulé se DÉCLARE (leçon ⑩)', () => {
  let warned: string[];
  let spy: jest.SpyInstance;

  beforeEach(() => {
    warned = [];
    // Prouver une ABSENCE de journal se fait en COMPTANT les appels, jamais
    // en lisant un résultat (CLAUDE.md §5).
    spy = jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
      warned.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    spy.mockRestore();
  });

  describe.each(SEAMS)('couture « %s »', (seam) => {
    test('murs armés + couture NON déclarée ⇒ REFUS de boot', () => {
      expect(() => declareSimulatedSeam(seam, ARMED)).toThrow(ConfigViolations);
    });

    test('le refus NOMME la couture et la variable — jamais un message opaque', () => {
      let message = '';
      try {
        declareSimulatedSeam(seam, ARMED);
      } catch (err) {
        message = err instanceof Error ? err.message : String(err);
      }
      expect(message).toContain(seam);
      expect(message).toContain(SIMULATED_SEAMS_VARIABLE);
    });

    test('variable VIDE sous murs armés ⇒ refus (une chaîne vide ne déclare rien)', () => {
      expect(() =>
        declareSimulatedSeam(seam, { ...ARMED, [SIMULATED_SEAMS_VARIABLE]: '' }),
      ).toThrow(ConfigViolations);
    });

    test('AUTRE couture déclarée ⇒ refus : la liste ne se partage pas', () => {
      const other = SEAMS.filter((s) => s !== seam).join(',');
      expect(() =>
        declareSimulatedSeam(seam, { ...ARMED, [SIMULATED_SEAMS_VARIABLE]: other }),
      ).toThrow(ConfigViolations);
    });

    test('couture DÉCLARÉE sous murs armés ⇒ boot autorisé, et la simulation est AVOUÉE', () => {
      expect(() =>
        declareSimulatedSeam(seam, { ...ARMED, [SIMULATED_SEAMS_VARIABLE]: SEAMS.join(',') }),
      ).not.toThrow();
      // Le nombre d'appels ET le contenu : un « toContain » seul passerait
      // aussi sur dix journaux parasites.
      expect(warned).toHaveLength(1);
      expect(warned[0]).toContain(seam);
    });

    test('CONTRÔLE NÉGATIF — development et test : ni refus, ni journal', () => {
      for (const NODE_ENV of ['development', 'test']) {
        expect(() => declareSimulatedSeam(seam, { NODE_ENV })).not.toThrow();
      }
      expect(warned).toHaveLength(0);
    });
  });

  test('F1 — NODE_ENV absent, vide ou mal orthographié : le mur JOUE', () => {
    const permissive = { [SIMULATED_SEAMS_VARIABLE]: '' };
    expect(() => declareSimulatedSeam('PROVING', permissive)).toThrow(ConfigViolations);
    expect(() => declareSimulatedSeam('PROVING', { ...permissive, NODE_ENV: '' })).toThrow(
      ConfigViolations,
    );
    // La faute de frappe du manifeste (leçon ⑩) : elle ARME, elle ne relâche pas.
    expect(() =>
      declareSimulatedSeam('PROVING', { ...permissive, NODE_ENV: 'produciton' }),
    ).toThrow(ConfigViolations);
    expect(() => declareSimulatedSeam('PROVING', { ...permissive, NODE_ENV: 'staging' })).toThrow(
      ConfigViolations,
    );
  });

  describe('FAIL-CLOSED sur la VALEUR (leçon ⑥) — une faute de frappe ne déclare rien', () => {
    test.each(['PROVER', 'proving', 'DISPATCHER', 'PROVING;DISPATCH', 'ALL'])(
      '« %s » ⇒ refus NOMMÉ, jamais un silence',
      (raw) => {
        let message = '';
        try {
          declareSimulatedSeam('PROVING', { ...ARMED, [SIMULATED_SEAMS_VARIABLE]: raw });
        } catch (err) {
          message = err instanceof Error ? err.message : String(err);
        }
        expect(message).toContain(SIMULATED_SEAMS_VARIABLE);
        expect(warned).toHaveLength(0);
      },
    );

    test('une entrée inconnue À CÔTÉ d\'une entrée valide refuse AUSSI', () => {
      // Sans cela, « PROVING,PROVER » passerait : la moitié ratée serait
      // avalée en silence, et le prochain déploiement croirait avoir déclaré
      // deux coutures alors qu'il n'en a déclaré qu'une.
      expect(() =>
        declareSimulatedSeam('PROVING', {
          ...ARMED,
          [SIMULATED_SEAMS_VARIABLE]: 'PROVING,PROVER',
        }),
      ).toThrow(ConfigViolations);
    });
  });

  describe('tolérances qui n\'OUVRENT rien', () => {
    test('espaces autour des entrées : acceptés (ils ne déclarent rien de plus)', () => {
      expect(() =>
        declareSimulatedSeam('DISPATCH', {
          ...ARMED,
          [SIMULATED_SEAMS_VARIABLE]: ' PROVING , DISPATCH ',
        }),
      ).not.toThrow();
    });

    test('virgule finale : acceptée — un segment vide n\'accorde aucun droit', () => {
      expect(() =>
        declareSimulatedSeam('DISPATCH', { ...ARMED, [SIMULATED_SEAMS_VARIABLE]: 'DISPATCH,' }),
      ).not.toThrow();
    });
  });
});
