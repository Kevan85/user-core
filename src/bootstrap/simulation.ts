import { ConfigViolations, productionWallsArmed } from './assembly';

/**
 * LE MUR DES DOUBLURES (lot déploiement, étape 1).
 *
 * Deux des trois coutures de CLAUDE.md §3.9 n'ont, à ce jour, qu'UN SEUL
 * implémenteur — et c'est un simulateur : LyingProver (src/proving/simulator)
 * et CountingDispatcher (src/dispatch/simulator). Il n'existe donc aucune
 * implémentation réelle vers laquelle basculer : la question n'est pas
 * « laquelle choisir ? » mais « le déploiement SAIT-IL qu'il tourne à vide ? ».
 *
 * CE QUE LA PROSE NE PROTÉGEAIT PAS — la raison d'être de ce fichier.
 * src/worker.ts nommait DÉJÀ le risque dans son commentaire (« le dispatcher
 * de simulation tant qu'aucun fournisseur réel n'est branché ») sans qu'aucun
 * mur ne le tienne. C'est le patron exact de la leçon ⑬ : un commentaire qui
 * nomme un risque donne au lecteur suivant le sentiment qu'il est traité.
 * Mesuré au 21/08/2026 : le simulateur de preuve rend une référence inventée
 * et record_proof_dispatch enregistre un succès AVEC sa ligne de coût
 * (phone.service.ts:186) ; le dispatcher simulé empile en mémoire et le
 * publisher marque l'événement publié juste après (publisher.ts:121 puis
 * :128). Dans les deux cas rien ne part, et rien ne rougit.
 *
 * LE MODE PERMISSIF SE DÉCLARE (leçon ⑩) — le défaut est FERMÉ. Sous murs
 * armés, une couture simulée doit être NOMMÉE dans l'environnement. Variable
 * absente, vide, ou couture non nommée : REFUS de boot, message qui dit
 * laquelle et pourquoi. Le pire cas devient un boot refusé bruyamment sur un
 * serveur mal configuré, jamais un service qui répond « envoyé » dans le vide.
 *
 * POURQUOI UNE LISTE ET NON UN BOOLÉEN (arbitrage Auditeur, 21/08/2026) : les
 * deux coutures ont des calendriers de remplacement INDÉPENDANTS — un
 * fournisseur réel peut servir la preuve de ligne avant qu'aucun envoi réel
 * n'existe, ou l'inverse. Un booléen ré-ouvrirait les deux d'un seul geste :
 * un oubli rendrait alors le système plus permissif, donc la garde serait à
 * l'envers. La liste rend chaque doublure déclarée une par une.
 *
 * FAIL-CLOSED SUR LA VALEUR (leçon ⑥) : une entrée inconnue est un REFUS
 * NOMMÉ, jamais un silence. « PROVER », « proving », « DISPATCHER » ne
 * déclarent rien — et le mur le DIT au lieu de les ignorer, sans quoi une
 * faute de frappe rouvrirait le trou qu'il ferme.
 *
 * PRÉDICAT UNIQUE (F1bis) : « production » se dérive ICI de
 * productionWallsArmed, jamais d'une deuxième égalité de chaîne.
 */
export type SimulatedSeam = 'PROVING' | 'DISPATCH';

/** Le nom lisible d'une couture — il part dans le refus ET dans le journal. */
const SEAM_LABELS: Record<SimulatedSeam, string> = {
  PROVING: 'preuve de possession de ligne (LineOwnershipProver)',
  DISPATCH: 'envoi sortant (OutboundDispatcher)',
};

const KNOWN_SEAMS = Object.keys(SEAM_LABELS) as SimulatedSeam[];

export const SIMULATED_SEAMS_VARIABLE = 'USER_CORE_SIMULATED_SEAMS';

/**
 * Les coutures déclarées, et les entrées qui ne veulent rien dire.
 *
 * Un segment VIDE (virgule finale, double virgule) ne déclare rien : il
 * n'ouvre donc rien, et l'ignorer ne relâche aucun mur. Une entrée NON VIDE
 * et inconnue, elle, trahit une intention ratée — elle est refusée.
 */
function parseDeclaration(raw: string | undefined): {
  declared: Set<string>;
  unknown: string[];
} {
  const declared = new Set<string>();
  const unknown: string[] = [];

  for (const entry of (raw ?? '').split(',')) {
    const token = entry.trim();
    if (token === '') {
      continue;
    }
    if ((KNOWN_SEAMS as string[]).includes(token)) {
      declared.add(token);
    } else {
      unknown.push(token);
    }
  }

  return { declared, unknown };
}

/**
 * À appeler AVANT d'instancier une doublure, à son point d'assemblage.
 *
 * Sous murs relâchés (development, test) : ne lève pas, ne journalise pas —
 * le poste de développement et les 551 tests ne changent pas d'un pouce.
 *
 * Sous murs armés : la couture doit être déclarée, sinon REFUS. Et quand elle
 * l'est, C'EST CETTE FONCTION QUI JOURNALISE — jamais l'appelant. Un appelant
 * qui doit penser à tracer finit par ne pas le faire (leçon ①) : le mur et son
 * aveu partent ensemble ou ne partent pas.
 */
export function declareSimulatedSeam(
  seam: SimulatedSeam,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!productionWallsArmed(env)) {
    return;
  }

  const raw = env[SIMULATED_SEAMS_VARIABLE];
  const { declared, unknown } = parseDeclaration(raw);
  const violations: string[] = [];

  if (unknown.length > 0) {
    violations.push(
      `${SIMULATED_SEAMS_VARIABLE} : entrée inconnue « ${unknown.join(' », « ')} » — ` +
        `valeurs acceptées : ${KNOWN_SEAMS.join(', ')}. Une faute de frappe ne déclare RIEN, ` +
        `et un mur qui l'ignorerait rouvrirait le trou qu'il ferme`,
    );
  }

  if (!declared.has(seam)) {
    violations.push(
      `${SIMULATED_SEAMS_VARIABLE} ne déclare pas « ${seam} » : la couture « ${SEAM_LABELS[seam]} » ` +
        `n'a aujourd'hui qu'un implémenteur, un SIMULATEUR — il accuse réception et n'envoie rien, ` +
        `pendant que le registre enregistre un succès. Sous murs de production, ce mode se DÉCLARE ` +
        `(${SIMULATED_SEAMS_VARIABLE}=${KNOWN_SEAMS.join(',')}) ou le service refuse de démarrer`,
    );
  }

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }

  // L'aveu, à chaque démarrage : un déploiement qui simule doit le DIRE dans
  // ses journaux, sinon la déclaration se perd dans un fichier d'environnement
  // que plus personne ne relit. Zéro PII : un nom de couture, rien d'autre.
  console.warn(
    `[SIMULATION DÉCLARÉE] ${seam} — ${SEAM_LABELS[seam]} : aucun fournisseur réel n'est ` +
      `branché, rien ne part réellement. Retirer cette couture de ` +
      `${SIMULATED_SEAMS_VARIABLE} EST l'acte de passage en production.`,
  );
}
